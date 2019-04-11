use byteorder::{BigEndian, ByteOrder};
use futures::future::Future;
use std::task::{Poll, Poll::Ready, Poll::Pending, Waker};
use std::pin::Pin;
use futures::io::{
    AsyncWrite,
    AsyncWriteExt,
    Error,
};
// use futures::stream::Stream;
use ssb_crypto::{NonceGen, secretbox::{self, Nonce}};

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
    fn inner(&mut self) -> &mut W {
        &mut self.writer
    }
}

impl<W: AsyncWrite> BoxSender<W> {

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


type PinFut<O> = Pin<Box<dyn Future<Output=O>>>;

enum State<W> {
    Buffering(Vec<u8>),
    Sending(PinFut<(BoxSender<W>, Vec<u8>, Result<(), Error>)>),
    SendingClose(PinFut<(BoxSender<W>, Result<(), Error>)>),
    Closing,
    Done,
}

pub struct BoxWriter<W> {
    sender: Option<BoxSender<W>>,
    state: State<W>
}

impl<W> BoxWriter<W> {
    pub fn new(w: W, key: secretbox::Key, noncegen: NonceGen) -> BoxWriter<W> {
        BoxWriter {
            sender: Some(BoxSender::new(w, key, noncegen)),
            state: State::Buffering(Vec::with_capacity(4096)),
        }
    }
}

impl<W: AsyncWrite + 'static> AsyncWrite for BoxWriter<W> {
    fn poll_write(&mut self, wk: &Waker, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match &mut self.state {
            State::Buffering(v) => {
                let n = core::cmp::min(buf.len(), v.capacity() - v.len());
                assert!(n != 0);
                v.extend_from_slice(&buf[0..n]);

                if v.capacity() == 0 {
                    match self.poll_flush(wk) {
                        Ready(Err(e)) => Ready(Err(e)),
                        _ => Ready(Ok(n))
                    }
                } else {
                    Ready(Ok(n))
                }
            },

            State::Sending(fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((sender, mut v, res)) => {
                        self.sender = Some(sender);
                        match res {
                            Ok(()) => {
                                v.clear();
                                self.state = State::Buffering(v);
                                self.poll_write(wk, buf)
                            },
                            Err(e) => {
                                self.state = State::Done;
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

    fn poll_flush(&mut self, wk: &Waker) -> Poll<Result<(), Error>> {
        match &mut self.state {
            State::Buffering(v) => {
                if v.len() > 0 {
                    let s = self.sender.take().unwrap();
                    let buf = std::mem::replace(v, vec![]);
                    let boxed = Box::pin(s.send(buf));
                    self.state = State::Sending(boxed);
                    self.poll_flush(wk)
                } else {
                    if let Some(ref mut s) = &mut self.sender {
                        s.inner().poll_flush(wk)
                    } else {
                        panic!()
                    }
                }
            },

            State::Sending(fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((sender, mut v, res)) => {
                        self.sender = Some(sender);
                        match res {
                            Ok(()) => {
                                v.clear();
                                self.state = State::Buffering(v);
                                self.poll_flush(wk)
                            },
                            Err(e) => {
                                self.state = State::Done;
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

    fn poll_close(&mut self, wk: &Waker) -> Poll<Result<(), Error>> {
        match &mut self.state {
            State::Closing => {
                if let Some(s) = &mut self.sender {
                    match s.writer.poll_close(wk) {
                        Ready(r) => {
                            self.state = State::Done;
                            Ready(r)
                        },
                        Pending => Pending
                    }
                } else {
                    panic!()
                }
            }

            State::SendingClose(fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((s, Ok(()))) => {
                        self.sender = Some(s);
                        self.state = State::Closing;
                        self.poll_close(wk)
                    },
                    Ready((s, Err(e))) => {
                        self.sender = Some(s);
                        Ready(Err(e))
                    },
                    Pending => Pending,
                }
            },

            _ => match self.poll_flush(wk) {
                Ready(Ok(())) => {
                    let s = self.sender.take().unwrap();
                    self.state = State::SendingClose(Box::pin(s.send_close()));
                    self.poll_close(wk)
                },
                Ready(Err(e)) => Ready(Err(e)),
                Pending => Pending,
            }
        }
    }

}
