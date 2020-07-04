use crate::bytes::*;
use crate::msg::*;
use crate::PinFut;

use core::mem::{replace, size_of};
use core::pin::Pin;
use core::task::{Context, Poll, Poll::Pending, Poll::Ready};
use futures::io::{AsyncRead, AsyncReadExt, Error};
use std::io::{self, Cursor};

use ssb_crypto::handshake::NonceGen;
use ssb_crypto::secretbox::Key;

quick_error! {
    #[derive(Debug)]
    enum BoxStreamError {
        Io(err: io::Error) {
            description(err.description())
        }
        HeaderOpenFailed {
            description("Failed to decrypt header")
        }
        BodyOpenFailed {
            description("Failed to decrypt body")
        }
    }
}

impl From<io::Error> for BoxStreamError {
    fn from(err: io::Error) -> BoxStreamError {
        BoxStreamError::Io(err)
    }
}
impl From<BoxStreamError> for io::Error {
    fn from(err: BoxStreamError) -> io::Error {
        match err {
            BoxStreamError::Io(err) => err,
            err => io::Error::new(io::ErrorKind::InvalidData, err),
        }
    }
}

use BoxStreamError::*;

pub struct BoxReceiver<R> {
    reader: R,
    key: Key,
    nonces: NonceGen,
}

impl<R> BoxReceiver<R>
where
    R: Unpin,
{
    pub fn new(r: R, key: Key, nonces: NonceGen) -> BoxReceiver<R> {
        BoxReceiver {
            reader: r,
            key,
            nonces,
        }
    }
}

impl<R> BoxReceiver<R>
where
    R: Unpin + AsyncRead,
{
    async fn recv(mut self) -> (Self, Result<Option<Vec<u8>>, BoxStreamError>) {
        let r = self.recv_helper().await;
        (self, r)
    }

    async fn recv_helper(&mut self) -> Result<Option<Vec<u8>>, BoxStreamError> {
        let mut buf = [0; size_of::<HeadSealed>()];
        self.reader.read_exact(&mut buf).await?;
        let hd = cast_mut::<HeadSealed>(&mut buf)
            .open(&self.key, self.nonces.next())
            .ok_or(HeaderOpenFailed)?;

        if hd.body_size.get() == 0 && hd.body_hmac.0 == [0; 16] {
            // Goodbye
            Ok(None)
        } else {
            let mut body = vec![0; hd.body_size.get() as usize];
            self.reader.read_exact(&mut body).await?;

            if self.key.open(&mut body, &hd.body_hmac, &self.nonces.next()) {
                Ok(Some(body))
            } else {
                Err(BodyOpenFailed)
            }
        }
    }
}

enum State<T> {
    Ready(BoxReceiver<T>),
    Data(BoxReceiver<T>, Cursor<Vec<u8>>),
    Future(PinFut<(BoxReceiver<T>, Result<Option<Vec<u8>>, BoxStreamError>)>),
    Closed(BoxReceiver<T>),
    Invalid,
}
impl<T> State<T> {
    fn take(&mut self) -> Self {
        replace(self, State::Invalid)
    }
}

fn read<R>(
    state: State<R>,
    cx: &mut Context,
    buf: &mut [u8],
) -> (State<R>, Poll<Result<usize, Error>>)
where
    R: AsyncRead + Unpin + 'static,
{
    match state {
        State::Ready(r) => read(State::Future(Box::pin(r.recv())), cx, buf),

        State::Data(r, mut curs) => match io::Read::read(&mut curs, buf) {
            Ok(0) => read(State::Future(Box::pin(r.recv())), cx, buf),
            Ok(n) => (State::Data(r, curs), Ready(Ok(n))),
            Err(e) => (State::Closed(r), Ready(Err(e))),
        },

        State::Future(mut f) => match f.as_mut().poll(cx) {
            Pending => (State::Future(f), Pending),
            Ready((r, Ok(Some(v)))) => read(State::Data(r, Cursor::new(v)), cx, buf),
            Ready((r, Ok(None))) => (State::Closed(r), Ready(Ok(0))),
            Ready((r, Err(e))) => (State::Closed(r), Ready(Err(e.into()))),
        },
        State::Closed(_) => panic!("Read from closed BoxReader"),
        State::Invalid => panic!(),
    }
}

pub struct BoxReader<R> {
    state: State<R>,
}

impl<R> BoxReader<R>
where
    R: Unpin,
{
    pub fn new(r: R, key: Key, nonces: NonceGen) -> BoxReader<R> {
        BoxReader {
            state: State::Ready(BoxReceiver::new(r, key, nonces)),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self.state {
            State::Closed(_) => true,
            _ => false,
        }
    }

    pub fn into_inner(mut self) -> R {
        match self.state.take() {
            State::Ready(r) | State::Data(r, _) | State::Closed(r) => r.reader,

            _ => panic!(),
        }
    }
}

impl<R> AsyncRead for BoxReader<R>
where
    R: Unpin + AsyncRead + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let (state, p) = read(self.state.take(), cx, buf);
        self.state = state;
        p
    }
}
