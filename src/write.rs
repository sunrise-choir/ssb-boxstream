use crate::msg::*;
use crate::PinFut;

use core::mem::replace;
use core::pin::Pin;
use core::task::{Context, Poll, Poll::Pending, Poll::Ready};
use futures::io::{AsyncWrite, AsyncWriteExt, Error};
use ssb_crypto::handshake::NonceGen;
use ssb_crypto::secretbox::{Hmac, Key};

const MAX_BOX_SIZE: usize = 4096;

pub(crate) fn seal(mut body: Vec<u8>, key: &Key, noncegen: &mut NonceGen) -> (HeadSealed, Vec<u8>) {
    let head_nonce = noncegen.next();
    let body_nonce = noncegen.next();

    let body_hmac = key.seal(&mut body, &body_nonce);
    let head = HeadPayload::new(body.len() as u16, body_hmac).seal(&key, head_nonce);
    (head, body)
}

struct BoxSender<W> {
    writer: W,
    key: Key,
    nonces: NonceGen,
}

impl<W> BoxSender<W> {
    fn new(w: W, key: Key, nonces: NonceGen) -> BoxSender<W> {
        BoxSender {
            writer: w,
            key,
            nonces,
        }
    }
}

impl<W: AsyncWrite> BoxSender<W>
where
    W: AsyncWrite + Unpin,
{
    async fn send(mut self, body: Vec<u8>) -> (Self, Vec<u8>, Result<(), Error>) {
        assert!(body.len() <= MAX_BOX_SIZE);

        let (head, mut body) = seal(body, &self.key, &mut self.nonces);
        let mut r = self.writer.write_all(head.as_bytes()).await;
        if r.is_ok() {
            r = self.writer.write_all(&body).await;
        }

        body.clear();
        (self, body, r)
    }

    async fn send_goodbye(mut self) -> (Self, Result<(), Error>) {
        let head = HeadPayload::new(0, Hmac([0; 16])).seal(&self.key, self.nonces.next());
        let r = self.writer.write_all(head.as_bytes()).await;
        (self, r)
    }
}

enum State<T> {
    Buffering(BoxSender<T>, Vec<u8>),
    Sending(PinFut<(BoxSender<T>, Vec<u8>, Result<(), Error>)>),
    SendingGoodbye(PinFut<(BoxSender<T>, Result<(), Error>)>),
    Closing(BoxSender<T>, Option<Error>),
    Closed(BoxSender<T>),
    Invalid,
}
impl<T> State<T> {
    fn take(&mut self) -> Self {
        replace(self, State::Invalid)
    }
}

pub struct BoxWriter<W> {
    state: State<W>,
}

impl<W> BoxWriter<W>
where
    W: AsyncWrite + Unpin + 'static,
{
    pub fn new(w: W, key: Key, nonces: NonceGen) -> BoxWriter<W> {
        BoxWriter {
            state: State::Buffering(
                BoxSender::new(w, key, nonces),
                Vec::with_capacity(MAX_BOX_SIZE),
            ),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self.state {
            State::Closed(_) => true,
            _ => false,
        }
    }

    pub fn into_inner(mut self) -> W {
        match self.state.take() {
            State::Buffering(s, _) | State::Closing(s, _) | State::Closed(s) => s.writer,
            _ => panic!(),
        }
    }
}

fn write<T>(state: State<T>, cx: &mut Context, buf: &[u8]) -> (State<T>, Poll<Result<usize, Error>>)
where
    T: AsyncWrite + Unpin + 'static,
{
    if buf.is_empty() {
        return (state, Ready(Ok(0)));
    }

    match state {
        State::Buffering(s, mut v) => {
            let room = v.capacity() - v.len();
            if room == 0 {
                match flush(State::Buffering(s, v), cx) {
                    (st, Pending) => (st, Pending),
                    (st, Ready(Ok(()))) => write(st, cx, buf),
                    (State::Buffering(s, _), Ready(Err(e))) => {
                        let (st, p) = close(State::Closing(s, Some(e)), cx);
                        (st, p.map(|r| r.map(|_| 0)))
                    }
                    _ => panic!(),
                }
            } else {
                let n = core::cmp::min(buf.len(), room);

                v.extend_from_slice(&buf[0..n]);
                (State::Buffering(s, v), Ready(Ok(n)))
            }
        }

        State::Sending(mut f) => match f.as_mut().poll(cx) {
            Pending => (State::Sending(f), Pending),
            Ready((s, mut v, Ok(()))) => {
                v.clear();
                write(State::Buffering(s, v), cx, buf)
            }
            Ready((s, _, Err(e))) => {
                let (st, p) = close(State::Closing(s, Some(e)), cx);
                (st, p.map(|r| r.map(|_| 0)))
            }
        },
        _ => panic!(),
    }
}

fn flush<T>(state: State<T>, cx: &mut Context) -> (State<T>, Poll<Result<(), Error>>)
where
    T: AsyncWrite + Unpin + 'static,
{
    match state {
        State::Buffering(mut s, v) => {
            if v.is_empty() {
                let p = Pin::new(&mut s.writer).poll_flush(cx);
                (State::Buffering(s, v), p)
            } else {
                flush(State::Sending(Box::pin(s.send(v))), cx)
            }
        }
        State::Sending(mut f) => match f.as_mut().poll(cx) {
            Pending => (State::Sending(f), Pending),
            Ready((s, _, Err(e))) => close(State::Closing(s, Some(e)), cx),
            Ready((mut s, mut v, Ok(()))) => {
                v.clear();
                let p = Pin::new(&mut s.writer).poll_flush(cx);
                (State::Buffering(s, v), p)
            }
        },
        _ => panic!(),
    }
}

fn close<T>(state: State<T>, cx: &mut Context) -> (State<T>, Poll<Result<(), Error>>)
where
    T: AsyncWrite + Unpin + 'static,
{
    match state {
        State::Buffering(s, v) => {
            if v.is_empty() {
                close(State::SendingGoodbye(Box::pin(s.send_goodbye())), cx)
            } else {
                close(State::Sending(Box::pin(s.send(v))), cx)
            }
        }
        state @ State::Sending(_) => {
            match flush(state, cx) {
                (st, Pending) => (st, Pending),

                // Flush succeeded
                (State::Buffering(s, _), Ready(Ok(()))) => {
                    close(State::SendingGoodbye(Box::pin(s.send_goodbye())), cx)
                }

                // Flush failed
                r @ (State::Closing(_, _), _) => r,
                r @ (State::Closed(_), _) => r,

                _ => panic!(),
            }
        }
        State::SendingGoodbye(mut f) => match f.as_mut().poll(cx) {
            Pending => (State::SendingGoodbye(f), Pending),
            Ready((s, Err(e))) => close(State::Closing(s, Some(e)), cx),
            Ready((s, Ok(()))) => close(State::Closing(s, None), cx),
        },
        State::Closing(mut s, e) => match (Pin::new(&mut s.writer).poll_close(cx), e) {
            (Pending, e) => (State::Closing(s, e), Pending),
            (Ready(r), None) => (State::Closed(s), Ready(r)),
            (Ready(_), Some(e)) => (State::Closed(s), Ready(Err(e))),
        },
        state @ State::Closed(_) => (state, Ready(Ok(()))),
        State::Invalid => panic!(),
    }
}

impl<W> AsyncWrite for BoxWriter<W>
where
    W: AsyncWrite + Unpin + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let (state, p) = write(self.state.take(), cx, buf);
        self.state = state;
        p
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let (state, p) = flush(self.state.take(), cx);
        self.state = state;
        p
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let (state, p) = close(self.state.take(), cx);
        self.state = state;
        p
    }
}
