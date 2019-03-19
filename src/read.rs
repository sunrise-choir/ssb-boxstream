use core::mem::size_of;
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
use sodiumoxide::crypto::secretbox::{self, Nonce, Key};


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

struct Header {
    bytes: [u8; 34]
}
impl Header {
    fn new_empty() -> Header {
        Header { bytes: [0; 34] }
    }

    fn open(&self, key: &Key, nonce: Nonce) -> Result<(usize, BodyPrefix), BoxStreamError> {
        let v = secretbox::open(&self.bytes, &nonce, key)
            .map_err(|_| HeaderOpenFailed)?;

        assert_eq!(v.len(), 18);
        let (sz, rest) = v.split_at(2);
        Ok((BigEndian::read_u16(sz) as usize,
            BodyPrefix::from_slice(rest).unwrap()))
    }
}

struct BodyPrefix([u8; 16]);
impl BodyPrefix {
    fn from_slice(b: &[u8]) -> Option<BodyPrefix> {
        if b.len() == 16 {
            let mut buf = [0; 16];
            buf.copy_from_slice(b);
            Some(BodyPrefix(buf))
        } else {
            None
        }
    }
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

struct Body(Vec<u8>);
impl Body {
    fn new(size: usize, prefix: &BodyPrefix) -> Body {
        let mut v = vec![0; size_of::<BodyPrefix>() + size];
        v[..size_of::<BodyPrefix>()].copy_from_slice(prefix.as_slice());
        Body(v)
    }

    fn mut_tail(&mut self) -> &mut [u8] {
        &mut self.0[size_of::<BodyPrefix>()..]
    }

    fn open(self, key: &Key, nonce: Nonce) -> Result<Vec<u8>, BoxStreamError> {
        secretbox::open(&self.0, &nonce, key)
            .map_err(|_| BodyOpenFailed)
    }
}

pub struct BoxReceiver<R> {
    reader: R,
    key: secretbox::Key,
    noncegen: NonceGen,
}

impl<R: AsyncRead> BoxReceiver<R> {
    async fn recv_move(mut self) -> (Self, Result<Option<Vec<u8>>, BoxStreamError>) {
        let r = await!(self.recv());
        (self, r)
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, BoxStreamError> {
        let mut head = Header::new_empty();
        await!(self.reader.read_exact(&mut head.bytes))?;

        let (size, prefix) = head.open(&self.key, self.noncegen.next())?;

        if size == 0 && prefix.as_slice().iter().all(|b| *b == 0) {
            // Goodbye
            return Ok(None);
        }

        let mut body = Body::new(size, &prefix);
        await!(self.reader.read_exact(body.mut_tail()))?;

        Ok(Some(body.open(&self.key, self.noncegen.next())?))
    }
}

type Fut<R> = Pin<Box<dyn Future<Output=(BoxReceiver<R>, Result<Option<Vec<u8>>, BoxStreamError>)>>>;

enum ReaderState<R> {
    None,
    Data(Cursor<Vec<u8>>),
    Future(Fut<R>),
}

pub struct BoxReader<R> {
    receiver: Option<BoxReceiver<R>>,
    state: ReaderState<R>,
}

impl<R: AsyncRead + 'static> AsyncRead for BoxReader<R> {
    fn poll_read(&mut self, wk: &Waker, mut buf: &mut [u8])
                 -> Poll<Result<usize, Error>> {

        match &mut self.state {
            ReaderState::Data(ref mut curs) => {
                match io::Read::read(curs, &mut buf) {
                    Ok(0) => {
                        self.state = ReaderState::None;
                        self.poll_read(wk, buf)
                    },
                    Ok(n) => Ready(Ok(n)),
                    Err(e) => Ready(Err(e)),
                }
            },

            ReaderState::Future(ref mut fut) => {
                let p = Pin::as_mut(fut);

                match p.poll(wk) {
                    Ready((b, r)) => {
                        self.receiver = Some(b);
                        match r {
                            Ok(Some(v)) => {
                                self.state = ReaderState::Data(Cursor::new(v));
                                self.poll_read(wk, buf)
                            },
                            Ok(None) => {
                                self.state = ReaderState::None; // TODO: Done?
                                Ready(Ok(0))
                            },
                            Err(e) => {
                                self.state = ReaderState::None;
                                unimplemented!()
                                // Ready(Err(e.into()))
                            }
                        }
                    },
                    Pending => Pending
                }
            },

            ReaderState::None => {
                let r = self.receiver.take().unwrap();
                let boxed = Box::pin(r.recv_move());
                self.state = ReaderState::Future(boxed);
                self.poll_read(wk, buf)
            }
        }
    }
}
