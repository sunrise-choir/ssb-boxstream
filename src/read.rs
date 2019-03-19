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

impl<R: AsyncRead> BoxReceiver<R> {
    async fn recv_move(mut self) -> (Self, Result<Option<Vec<u8>>, BoxStreamError>) {
        let r = await!(self.recv());
        (self, r)
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, BoxStreamError> {

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
