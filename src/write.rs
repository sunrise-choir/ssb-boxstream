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
use shs_core::NonceGen;

use sodiumoxide::crypto::secretbox;


pub struct BoxSender<W> {
    writer: W,
    key: secretbox::Key,
    noncegen: NonceGen,
}

impl<W: AsyncWrite> BoxSender<W> {

    async fn send_move(mut self, buf: Vec<u8>) -> (Self, Vec<u8>, Result<(), Error>) {
        assert!(buf.len() <= 4096);

        let sbox = secretbox::seal(&buf, &self.noncegen.next(), &self.key);
        assert!(sbox.len() > 16);

        let mut head_payload = [0; 18];
        BigEndian::write_u16(&mut head_payload[..2], (sbox.len() - 16) as u16);
        head_payload[2..].copy_from_slice(&sbox[..16]);

        let hbox = secretbox::seal(&head_payload, &self.noncegen.next(), &self.key);

        let mut r = await!(self.writer.write_all(&hbox));
        if r.is_ok() {
            r = await!(self.writer.write_all(&sbox)); // TODO: should probably be sbox[16..]
        }
        (self, buf, r.map_err(|e| e.into()))
    }
}


type PinFut<O> = Pin<Box<dyn Future<Output=O>>>;
type Foot<W> = PinFut<(BoxSender<W>, Vec<u8>, Result<(), Error>)>;

enum WriterState<W> {
    Buffering(Vec<u8>),
    Sending(Foot<W>),
    Done,
}

pub struct BoxWriter<W> {
    sender: Option<BoxSender<W>>,
    state: WriterState<W>
}

impl<W: AsyncWrite + 'static> AsyncWrite for BoxWriter<W> {
    fn poll_write(&mut self, wk: &Waker, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match &mut self.state {
            WriterState::Buffering(v) => {
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

            WriterState::Sending(fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((sender, mut v, res)) => {
                        self.sender = Some(sender);
                        match res {
                            Ok(()) => {
                                v.clear();
                                self.state = WriterState::Buffering(v);
                                self.poll_write(wk, buf)
                            },
                            Err(e) => {
                                self.state = WriterState::Done;
                                Ready(Err(e))
                            }
                        }
                    },
                    Pending => Pending
                }
            },

            WriterState::Done => panic!()
        }
    }

    fn poll_flush(&mut self, wk: &Waker) -> Poll<Result<(), Error>> {
        match &mut self.state {
            WriterState::Buffering(v) => {
                if v.len() > 0 {
                    let s = self.sender.take().unwrap();
                    let buf = std::mem::replace(v, vec![]);
                    let boxed = Box::pin(s.send_move(buf));
                    self.state = WriterState::Sending(boxed);
                    self.poll_flush(wk)
                } else {
                    Ready(Ok(()))
                }
            },

            WriterState::Sending(fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((sender, mut v, res)) => {
                        self.sender = Some(sender);
                        match res {
                            Ok(()) => {
                                v.clear();
                                self.state = WriterState::Buffering(v);
                                Ready(Ok(()))
                            },
                            Err(e) => {
                                self.state = WriterState::Done;
                                Ready(Err(e))
                            }
                        }
                    },
                    Pending => Pending
                }
            },

            WriterState::Done => panic!()
        }
    }

    fn poll_close(&mut self, _wk: &Waker) -> Poll<Result<(), Error>> {
        unimplemented!()
    }

}
