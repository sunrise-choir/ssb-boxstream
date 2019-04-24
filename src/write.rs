use byteorder::{BigEndian, ByteOrder};
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

enum State<W> {
    Buffering(Vec<u8>),
    Sending(PinFut<(BoxSender<W>, Vec<u8>, Result<(), Error>)>),
    SendingClose(PinFut<(BoxSender<W>, Result<(), Error>)>),
    Closing,
    Closed,
}

pub struct BoxWriter<W> {
    sender: Option<BoxSender<W>>,
    state: State<W>
}

impl<W> BoxWriter<W>
where W: AsyncWrite + Unpin + 'static
{
    pub fn new(w: W, key: secretbox::Key, noncegen: NonceGen) -> BoxWriter<W> {
        BoxWriter {
            sender: Some(BoxSender::new(w, key, noncegen)),
            state: State::Buffering(Vec::with_capacity(4096)),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self.state {
            State::Closed => true,
            _ => false,
        }
    }

    pub fn into_inner(mut self) -> W {
        let s = self.sender.take().unwrap();
        s.writer
    }

    fn do_poll_write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match &mut self.state {
            State::Buffering(v) => {
                let n = core::cmp::min(buf.len(), v.capacity() - v.len());
                assert!(n != 0);
                v.extend_from_slice(&buf[0..n]);

                if v.capacity() == 0 {
                    match self.do_poll_flush(cx) {
                        Ready(Err(e)) => Ready(Err(e)),
                        _ => Ready(Ok(n))
                    }
                } else {
                    Ready(Ok(n))
                }
            },

            State::Sending(f) => {
                match f.as_mut().poll(cx) {
                    Ready((sender, mut v, res)) => {
                        self.sender = Some(sender);
                        match res {
                            Ok(()) => {
                                v.clear();
                                self.state = State::Buffering(v);
                                self.do_poll_write(cx, buf)
                            },
                            Err(e) => {
                                self.state = State::Closed;
                                Ready(Err(e))
                            }
                        }
                    },
                    Pending => Pending
                }
            },

            _ => panic!()
        }
    }

    fn do_poll_flush(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        match &mut self.state {
            State::Buffering(v) => {
                if v.len() > 0 {
                    let s = self.sender.take().unwrap();
                    let buf = std::mem::replace(v, vec![]);
                    let boxed = Box::pin(s.send(buf));
                    self.state = State::Sending(boxed);
                    self.do_poll_flush(cx)
                } else {
                    if let Some(ref mut s) = &mut self.sender {
                        Pin::new(&mut s.writer).poll_flush(cx)
                    } else {
                        panic!()
                    }
                }
            },

            State::Sending(f) => {
                match f.as_mut().poll(cx) {
                    Ready((sender, mut v, res)) => {
                        self.sender = Some(sender);
                        match res {
                            Ok(()) => {
                                v.clear();
                                self.state = State::Buffering(v);
                                self.do_poll_flush(cx)
                            },
                            Err(e) => {
                                self.state = State::Closed;
                                Ready(Err(e))
                            }
                        }
                    },
                    Pending => Pending
                }
            },

            _ => panic!()
        }
    }

    fn do_poll_close(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        match &mut self.state {
            State::Closing => {
                if let Some(s) = &mut self.sender {
                    match Pin::new(&mut s.writer).poll_close(cx) {
                        Ready(r) => {
                            self.state = State::Closed;
                            Ready(r)
                        },
                        Pending => Pending
                    }
                } else {
                    panic!()
                }
            }

            State::SendingClose(f) => {
                match f.as_mut().poll(cx) {
                    Ready((s, Ok(()))) => {
                        self.sender = Some(s);
                        self.state = State::Closing;
                        self.do_poll_close(cx)
                    },
                    Ready((s, Err(e))) => {
                        self.sender = Some(s);
                        Ready(Err(e))
                    },
                    Pending => Pending,
                }
            },

            _ => match self.do_poll_flush(cx) {
                Ready(Ok(())) => {
                    let s = self.sender.take().unwrap();
                    self.state = State::SendingClose(Box::pin(s.send_close()));
                    self.do_poll_close(cx)
                },
                Ready(Err(e)) => Ready(Err(e)),
                Pending => Pending,
            }
        }
    }

}

impl<W> AsyncWrite for BoxWriter<W>
where W: AsyncWrite + Unpin + 'static
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, Error>> {
        self.do_poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.do_poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.do_poll_close(cx)
    }

}
