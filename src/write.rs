use byteorder::{BigEndian, ByteOrder};
use core::mem::replace;
use core::task::{Context, Poll, Poll::Ready, Poll::Pending};
use core::pin::Pin;
use futures::io::{
    AsyncWrite,
    AsyncWriteExt,
    Error,
};
use ssb_crypto::{NonceGen, secretbox::{self, Nonce}};


use crate::PinFut;

pub(crate) fn seal_header(payload: &mut [u8; 18], nonce: Nonce, key: &secretbox::Key) -> [u8; 34] {
    let htag = secretbox::seal_detached(&mut payload[..], &nonce, &key);

    let mut hbox = [0; 34];
    hbox[..16].copy_from_slice(&htag[..]);
    hbox[16..].copy_from_slice(&payload[..]);
    hbox
}

pub(crate) fn seal(mut body: Vec<u8>,
                   key: &secretbox::Key,
                   noncegen: &mut NonceGen) -> ([u8; 34], Vec<u8>) {

    let head_nonce = noncegen.next();
    let body_nonce = noncegen.next();

    let mut head_payload = {
        // Overwrites body with ciphertext
        let btag = secretbox::seal_detached(&mut body, &body_nonce, &key);

        let mut hp = [0; 18];
        let (sz, tag) = hp.split_at_mut(2);
        BigEndian::write_u16(sz, body.len() as u16);
        tag.copy_from_slice(&btag[..]);
        hp
    };

    let head = seal_header(&mut head_payload, head_nonce, key);
    (head, body)
}

struct BoxSender<W> {
    writer: W,
    key: secretbox::Key,
    noncegen: NonceGen,
}

impl<W> BoxSender<W> {
    fn new(w: W, key: secretbox::Key, noncegen: NonceGen) -> BoxSender<W> {
        BoxSender {
            writer: w,
            key: key,
            noncegen: noncegen,
        }
    }
}

impl<W: AsyncWrite> BoxSender<W>
where W: AsyncWrite + Unpin
{
    async fn send(mut self, body: Vec<u8>) -> (Self, Vec<u8>, Result<(), Error>) {
        assert!(body.len() <= 4096);

        let (head, mut cipher_body) = seal(body, &self.key, &mut self.noncegen);

        let mut r = await!(self.writer.write_all(&head));
        if r.is_ok() {
            r = await!(self.writer.write_all(&cipher_body));
        }

        cipher_body.clear();
        (self, cipher_body, r)
    }

    async fn send_close(mut self) -> (Self, Result<(), Error>) {
        let mut payload = [0; 18];
        let head = seal_header(&mut payload, self.noncegen.next(), &self.key);
        let r = await!(self.writer.write_all(&head));
        (self, r)
    }
}

enum State<T> {
    Buffering(BoxSender<T>, Vec<u8>),
    Sending(PinFut<(BoxSender<T>, Vec<u8>, Result<(), Error>)>),
    SendingClose(PinFut<(BoxSender<T>, Result<(), Error>)>),
    Closing(BoxSender<T>),
    Closed(BoxSender<T>),
    Invalid,
}
impl<T> State<T> {
    fn take(&mut self) -> Self {
        replace(self, State::Invalid)
    }
}

pub struct BoxWriter<W> {
    state: State<W>
}

impl<W> BoxWriter<W>
where W: AsyncWrite + Unpin + 'static
{
    pub fn new(w: W, key: secretbox::Key, noncegen: NonceGen) -> BoxWriter<W> {
        BoxWriter {
            state: State::Buffering(BoxSender::new(w, key, noncegen),
                                    Vec::with_capacity(4096)),
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
            State::Buffering(s, _) |
            State::Closing(s)      |
            State::Closed(s) => s.writer,
            _ => panic!(),
        }
    }
}


fn write<T>(state: State<T>, cx: &mut Context, buf: &[u8]) -> (State<T>, Poll<Result<usize, Error>>)
where T: AsyncWrite + Unpin + 'static
{
    if buf.len() == 0 {
        return (state, Ready(Ok(0)));
    }

    match state {
        State::Buffering(s, mut v) => {
            if v.capacity() == 0 {
                match flush(State::Buffering(s, v), cx) {
                    (state, Pending) => (state, Pending),
                    (state, Ready(Ok(()))) => write(state, cx, buf),
                    (State::Buffering(s, _), Ready(Err(e))) => (State::Closed(s), Ready(Err(e))),
                    _ => panic!(),
                }
            } else {
                let n = core::cmp::min(buf.len(), v.capacity());
                v.extend_from_slice(&buf[0..n]);
                (State::Buffering(s, v), Ready(Ok(n)))
            }
        },

        State::Sending(mut f) => {
            match f.as_mut().poll(cx) {
                Pending => (State::Sending(f), Pending),
                Ready((s, _, Err(e))) => (State::Closed(s), Ready(Err(e))),
                Ready((s, mut v, Ok(()))) => {
                    v.clear();
                    write(State::Buffering(s, v), cx, buf)
                },
            }
        },
        _ => panic!()
    }
}


fn flush<T>(state: State<T>, cx: &mut Context) -> (State<T>, Poll<Result<(), Error>>)
where T: AsyncWrite + Unpin + 'static
{
    match state {
        State::Buffering(mut s, v) => {
            if v.len() == 0 {
                let p = Pin::new(&mut s.writer).poll_flush(cx);
                (State::Buffering(s, v), p)
            } else {
                flush(State::Sending(Box::pin(s.send(v))), cx)
            }
        },
        State::Sending(mut f) => {
            match f.as_mut().poll(cx) {
                Pending               => (State::Sending(f), Pending),
                Ready((s, _, Err(e))) => (State::Closed(s), Ready(Err(e))),
                Ready((mut s, mut v, Ok(()))) => {
                    v.clear();
                    let p = Pin::new(&mut s.writer).poll_flush(cx);
                    (State::Buffering(s, v), p)
                },
            }
        },
        _ => panic!()
    }
}

fn close<T>(state: State<T>, cx: &mut Context) -> (State<T>, Poll<Result<(), Error>>)
where T: AsyncWrite + Unpin + 'static
{
    match state {
        State::Buffering(s, v) => {
            if v.len() == 0 {
                close(State::SendingClose(Box::pin(s.send_close())), cx)
            } else {
                close(State::Sending(Box::pin(s.send(v))), cx)
            }
        },
        state @ State::Sending(_) => {
            match flush(state, cx) {
                (st, Pending) => (st, Pending),
                (State::Closed(s), Ready(Err(e)))
                    => (State::Closed(s), Ready(Err(e))),
                (State::Buffering(s, _), Ready(Ok(()))) =>
                    close(State::SendingClose(Box::pin(s.send_close())), cx),
                _ => panic!(),
            }
        },
        State::SendingClose(mut f) => {
            match f.as_mut().poll(cx) {
                Pending => (State::SendingClose(f), Pending),
                Ready((s, Err(e))) => (State::Closed(s), Ready(Err(e))),
                Ready((s, Ok(()))) => close(State::Closing(s), cx),
            }
        },
        State::Closing(mut s) => {
            match Pin::new(&mut s.writer).poll_close(cx) {
                Pending  => (State::Closing(s), Pending),
                Ready(r) => (State::Closed(s), Ready(r)),
            }
        },
        state @ State::Closed(_) => (state, Ready(Ok(()))),
        State::Invalid => panic!(),
    }
}

impl<W> AsyncWrite for BoxWriter<W>
where W: AsyncWrite + Unpin + 'static
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, Error>> {
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
