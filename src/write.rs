use crate::msg::*;

use core::cmp::min;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::io::{AsyncWrite, Error};
use futures::ready;
use ssb_crypto::handshake::NonceGen;
use ssb_crypto::secretbox::Key;

pub const MAX_BOX_SIZE: usize = 4096;

pub(crate) fn seal(mut body: &mut [u8], key: &Key, noncegen: &mut NonceGen) -> Head {
    let head_nonce = noncegen.next();
    let body_nonce = noncegen.next();

    let body_hmac = key.seal(&mut body, &body_nonce);
    HeadPayload::new(body.len() as u16, body_hmac).seal(&key, head_nonce)
}

pub struct BoxWriter<W, B> {
    inner: W,
    buffer: B,
    state: State,
    key: Key,
    nonces: NonceGen,
}

impl<W, B> BoxWriter<W, B> {
    pub fn with_buffer(inner: W, key: Key, nonces: NonceGen, buffer: B) -> BoxWriter<W, B> {
        BoxWriter {
            inner,
            buffer,
            state: State::Buffering { pos: 0 },
            key,
            nonces,
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W> BoxWriter<W, Vec<u8>> {
    pub fn new(w: W, key: Key, nonces: NonceGen) -> BoxWriter<W, Vec<u8>> {
        BoxWriter::with_buffer(w, key, nonces, vec![0; 4096])
    }
}

enum State {
    Buffering {
        pos: usize,
    },
    SendingHead {
        head: Head,
        pos: usize,
        body_size: usize,
    },
    SendingBody {
        body_size: usize,
        pos: usize,
    },
    SendingGoodbye {
        head: Head,
        pos: usize,
    },
    Closed,
}

impl<W, B> AsyncWrite for BoxWriter<W, B>
where
    W: AsyncWrite + Unpin + 'static,
    B: AsMut<[u8]> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        mut to_write: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut this = self.get_mut();
        let mut wrote_bytes = 0;

        loop {
            match this.state {
                State::Buffering { pos } => {
                    let buffer = this.buffer.as_mut();
                    let n = min(buffer.len() - pos, to_write.len());

                    let (b, rest) = to_write.split_at(n);
                    buffer[pos..pos + n].copy_from_slice(b);

                    wrote_bytes += n;
                    to_write = rest;

                    if pos + n == buffer.len() {
                        let head = seal(buffer, &this.key, &mut this.nonces);
                        this.state = State::SendingHead {
                            head,
                            pos: 0,
                            body_size: buffer.len(),
                        };
                    } else {
                        this.state = State::Buffering { pos: pos + n };
                        return Poll::Ready(Ok(wrote_bytes));
                    }
                }

                State::SendingHead {
                    head,
                    pos,
                    body_size,
                } => {
                    let hb = head.as_bytes();
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &hb[pos..]))?;
                    if pos + n == hb.len() {
                        this.state = State::SendingBody { body_size, pos: 0 };
                    } else {
                        this.state = State::SendingHead {
                            head,
                            pos: pos + n,
                            body_size,
                        };
                        return Poll::Pending;
                    }
                }

                State::SendingBody { body_size, pos } => {
                    let n = ready!(Pin::new(&mut this.inner)
                        .poll_write(cx, &this.buffer.as_mut()[pos..body_size]))?;
                    if pos + n == body_size {
                        this.state = State::Buffering { pos: 0 };
                    } else {
                        this.state = State::SendingBody {
                            body_size,
                            pos: pos + n,
                        };
                        return Poll::Pending;
                    }
                }

                State::SendingGoodbye { .. } => panic!(), // ??
                State::Closed => return Poll::Ready(Ok(0)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let mut this = self.get_mut();
        match this.state {
            State::Buffering { pos } => {
                if pos == 0 {
                    Pin::new(&mut this.inner).poll_flush(cx)
                } else {
                    let mut body = &mut this.buffer.as_mut()[..pos];
                    let head = seal(&mut body, &this.key, &mut this.nonces);
                    this.state = State::SendingHead {
                        head,
                        pos: 0,
                        body_size: pos,
                    };
                    Pin::new(this).poll_flush(cx)
                }
            }

            State::SendingHead {
                head,
                pos,
                body_size,
            } => {
                let bytes = head.as_bytes();

                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &bytes[pos..]))?;
                if pos + n == bytes.len() {
                    this.state = State::SendingBody { body_size, pos: 0 };
                    Pin::new(this).poll_flush(cx)
                } else {
                    this.state = State::SendingHead {
                        head,
                        pos: pos + n,
                        body_size,
                    };
                    Poll::Pending
                }
            }

            State::SendingBody { body_size, pos } => {
                let n =
                    ready!(Pin::new(&mut this.inner)
                        .poll_write(cx, &this.buffer.as_mut()[pos..body_size]))?;
                if pos + n == body_size {
                    this.state = State::Buffering { pos: 0 };
                    Pin::new(&mut this.inner).poll_flush(cx)
                } else {
                    this.state = State::SendingBody {
                        body_size,
                        pos: pos + n,
                    };
                    Poll::Pending
                }
            }
            State::SendingGoodbye { .. } => panic!(),
            State::Closed => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        let mut this = self.get_mut();
        match this.state {
            State::SendingGoodbye { head, pos } => {
                let bytes = head.as_bytes();

                let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &bytes[pos..]))?;
                if pos + n == bytes.len() {
                    this.state = State::Closed;
                    Pin::new(&mut this.inner).poll_close(cx)
                } else {
                    this.state = State::SendingGoodbye { head, pos: pos + n };
                    Poll::Pending
                }
            }

            _ => {
                ready!(Pin::new(&mut this).poll_flush(cx))?;
                let head = HeadPayload::goodbye().seal(&this.key, this.nonces.next());
                this.state = State::SendingGoodbye { head, pos: 0 };
                Pin::new(&mut this).poll_close(cx)
            }
        }
    }
}
