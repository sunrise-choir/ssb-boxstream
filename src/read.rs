use crate::bytes::cast_mut;
use crate::msg::*;

use crate::NonceGen;
use core::cmp::min;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_core::ready;
use futures_io::{self as io, AsyncRead};
use ssb_crypto::secretbox::{Key, Nonce};
use thiserror::Error;

#[derive(Debug, Error)]
enum BoxStreamError {
    #[error("IO error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Failed to decrypt header")]
    HeaderOpenFailed,
    #[error("Failed to decrypt body")]
    BodyOpenFailed,
}

impl From<BoxStreamError> for io::Error {
    fn from(err: BoxStreamError) -> io::Error {
        match err {
            BoxStreamError::Io { source } => source,
            err => io::Error::new(io::ErrorKind::InvalidData, err),
        }
    }
}

pub struct BoxReader<R, B> {
    inner: R,
    buffer: B,
    state: State,
    key: Key,
    nonces: NonceGen,
}

impl<R, B> BoxReader<R, B> {
    pub fn with_buffer(inner: R, key: Key, nonce: Nonce, buffer: B) -> BoxReader<R, B> {
        BoxReader {
            inner,
            buffer,
            state: State::ReadingHead {
                head: [0; Head::SIZE],
                pos: 0,
            },
            key,
            nonces: NonceGen::with_starting_nonce(nonce),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self.state {
            State::Done => true,
            _ => false,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R> BoxReader<R, Vec<u8>> {
    pub fn new(inner: R, key: Key, nonce: Nonce) -> BoxReader<R, Vec<u8>> {
        BoxReader::with_buffer(inner, key, nonce, std::vec![0; 4096])
    }
}

enum State {
    Ready { body_size: usize, pos: usize },
    ReadingHead { head: [u8; Head::SIZE], pos: usize },
    ReadingBody { head: HeadPayload, pos: usize },
    Done,
}

impl<R: AsyncRead, B> AsyncRead for BoxReader<R, B>
where
    R: Unpin + AsyncRead + 'static,
    B: AsMut<[u8]> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        out: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut this = self.get_mut();

        match this.state {
            State::Ready { body_size, pos } => {
                let n = min(out.len(), body_size - pos);
                out[..n].copy_from_slice(&this.buffer.as_mut()[pos..pos + n]);
                if pos + n == body_size {
                    // need to read a new box
                    this.state = State::ReadingHead {
                        head: [0; Head::SIZE],
                        pos: 0,
                    };
                } else {
                    this.state = State::Ready {
                        body_size,
                        pos: pos + n,
                    }
                }
                Poll::Ready(Ok(n))
            }

            State::ReadingHead { mut head, pos } => {
                let n = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut head[pos..]))?;
                if n == head.len() - pos {
                    // done reading head
                    let hd = cast_mut::<Head>(&mut head[..])
                        .open(&this.key, this.nonces.next())
                        .ok_or(io::Error::from(BoxStreamError::HeaderOpenFailed))?;

                    if hd.is_goodbye() {
                        this.state = State::Done;
                        Poll::Ready(Ok(0))
                    } else {
                        this.state = State::ReadingBody { head: *hd, pos: 0 };
                        Pin::new(&mut this).poll_read(cx, out)
                    }
                } else {
                    this.state = State::ReadingHead { head, pos: pos + n };
                    Poll::Pending
                }
            }

            State::ReadingBody { head, pos } => {
                let body_size = head.body_size.get() as usize;
                let n = ready!(Pin::new(&mut this.inner)
                    .poll_read(cx, &mut this.buffer.as_mut()[pos..body_size]))?;

                if n == body_size - pos {
                    // Done reading body, open it.
                    if this.key.open(
                        &mut this.buffer.as_mut()[..body_size],
                        &head.body_hmac,
                        &this.nonces.next(),
                    ) {
                        this.state = State::Ready { body_size, pos: 0 };
                        Pin::new(&mut this).poll_read(cx, out)
                    } else {
                        Poll::Ready(Err(BoxStreamError::BodyOpenFailed.into()))
                    }
                } else {
                    this.state = State::ReadingBody { head, pos: pos + n };
                    Poll::Pending
                }
            }

            State::Done => Poll::Ready(Ok(0)),
        }
    }
}
