use byteorder::{BigEndian, ByteOrder};
use futures::future::Future;
use std::io::{self, Cursor};
use std::task::{Poll, Poll::Ready, Poll::Pending, Waker};
use std::pin::Pin;
use futures::io::{
    AsyncRead,
    AsyncReadExt,
    Error,
};
// use futures::stream::Stream;
use shs_core::NonceGen;
use sodiumoxide::crypto::secretbox::{self, Tag};


#[derive(Debug)]
enum BoxStreamError {
    Io(io::Error),
    HeaderOpenFailed,
    BodyOpenFailed,
}
impl From<io::Error> for BoxStreamError {
    fn from(err: io::Error) -> BoxStreamError {
        BoxStreamError::Io(err)
    }
}

use BoxStreamError::*;


pub struct BoxReceiver<R> {
    reader: R,
    key: secretbox::Key,
    noncegen: NonceGen,
}

impl<R> BoxReceiver<R> {
    pub fn new(r: R, key: secretbox::Key, noncegen: NonceGen) -> BoxReceiver<R> {
        BoxReceiver {
            reader: r,
            key: key,
            noncegen: noncegen,
        }
    }
}

impl<R: AsyncRead> BoxReceiver<R> {

    async fn recv(mut self) -> (Self, Result<Option<Vec<u8>>, BoxStreamError>) {
        let r = await!(self.recv_helper());
        (self, r)
    }

    async fn recv_helper(&mut self) -> Result<Option<Vec<u8>>, BoxStreamError> {

        let (body_size, body_tag) = {
            let mut head_tag = Tag([0; 16]);
            await!(self.reader.read_exact(&mut head_tag.0))?;

            let mut head_payload = [0; 18];
            await!(self.reader.read_exact(&mut head_payload[..]))?;

            secretbox::open_detached(&mut head_payload, &head_tag, &self.noncegen.next(), &self.key)
                .map_err(|_| HeaderOpenFailed)?;

            let (sz, rest) = head_payload.split_at(2);
            (BigEndian::read_u16(sz) as usize, Tag::from_slice(rest).unwrap())
        };

        if body_size == 0 && body_tag.0 == [0; 16] {
            // Goodbye
            Ok(None)
        } else {
            let mut body = vec![0; body_size];
            await!(self.reader.read_exact(&mut body))?;

            secretbox::open_detached(&mut body, &body_tag, &self.noncegen.next(), &self.key)
                .map_err(|_| BodyOpenFailed)?;

            Ok(Some(body))
        }
    }
}

type PinFut<O> = Pin<Box<dyn Future<Output=O> + 'static>>;

enum State<R> {
    None,
    Data(Cursor<Vec<u8>>),
    Future(PinFut<(BoxReceiver<R>, Result<Option<Vec<u8>>, BoxStreamError>)>),
}

pub struct BoxReader<R> {
    receiver: Option<BoxReceiver<R>>,
    state: State<R>,
}

impl<R> BoxReader<R> {
    pub fn new(r: R, key: secretbox::Key, noncegen: NonceGen) -> BoxReader<R> {
        BoxReader {
            receiver: Some(BoxReceiver::new(r, key, noncegen)),
            state: State::None,
        }
    }
}

impl<R: AsyncRead + 'static> AsyncRead for BoxReader<R> {
    fn poll_read(&mut self, wk: &Waker, mut buf: &mut [u8])
                 -> Poll<Result<usize, Error>> {

        match &mut self.state {
            State::Data(ref mut curs) => {
                match io::Read::read(curs, &mut buf) {
                    Ok(0) => {
                        self.state = State::None;
                        self.poll_read(wk, buf)
                    },
                    Ok(n) => Ready(Ok(n)),
                    Err(e) => Ready(Err(e)),
                }
            },

            State::Future(ref mut fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((b, r)) => {
                        self.receiver = Some(b);
                        match r {
                            Ok(Some(v)) => {
                                self.state = State::Data(Cursor::new(v));
                                self.poll_read(wk, buf)
                            },
                            Ok(None) => {
                                self.state = State::None; // TODO: Done?
                                Ready(Ok(0))
                            },
                            Err(e) => {
                                self.state = State::None;
                                unimplemented!()
                                // Ready(Err(e.into()))
                            }
                        }
                    },
                    Pending => Pending
                }
            },

            State::None => {
                let r = self.receiver.take().unwrap();
                let boxed = Box::pin(r.recv());
                self.state = State::Future(boxed);
                self.poll_read(wk, buf)
            }
        }
    }
}
