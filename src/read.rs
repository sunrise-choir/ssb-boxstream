use byteorder::{BigEndian, ByteOrder};
use core::mem::replace;
use core::pin::Pin;
use core::task::{Context, Poll, Poll::Ready, Poll::Pending};
use std::io::{self, Cursor};
use futures::io::{
    AsyncRead,
    AsyncReadExt,
    Error,
};

use ssb_crypto::{NonceGen, secretbox::{self, Tag}};

use crate::PinFut;

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
            err => io::Error::new(io::ErrorKind::InvalidData, err)
        }
    }
}

use BoxStreamError::*;

pub struct BoxReceiver<R> {
    reader: R,
    key: secretbox::Key,
    noncegen: NonceGen,
}

impl<R> BoxReceiver<R>
where R: Unpin
{
    pub fn new(r: R, key: secretbox::Key, noncegen: NonceGen) -> BoxReceiver<R> {
        BoxReceiver {
            reader: r,
            key: key,
            noncegen: noncegen,
        }
    }
}

impl<R> BoxReceiver<R>
where R: Unpin + AsyncRead
{
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

fn read<R>(state: State<R>, cx: &mut Context, buf: &mut [u8]) -> (State<R>, Poll<Result<usize, Error>>)
where R: AsyncRead + Unpin + 'static
{
    match state {
        State::Ready(r) => read(State::Future(Box::pin(r.recv())), cx, buf),

        State::Data(r, mut curs) => {
            match io::Read::read(&mut curs, buf) {
                Ok(0)  => read(State::Future(Box::pin(r.recv())), cx, buf),
                Ok(n)  => (State::Data(r, curs), Ready(Ok(n))),
                Err(e) => (State::Closed(r), Ready(Err(e))),
            }
        },

        State::Future(mut f) => {
            match f.as_mut().poll(cx) {
                Pending                 => (State::Future(f), Pending),
                Ready((r, Ok(Some(v)))) => read(State::Data(r, Cursor::new(v)), cx, buf),
                Ready((r, Ok(None)))    => (State::Closed(r), Ready(Ok(0))),
                Ready((r, Err(e)))      => (State::Closed(r), Ready(Err(e.into()))),
            }
        },
        State::Closed(_) => panic!("Read from closed BoxReader"),
        State::Invalid   => panic!(),
    }
}

pub struct BoxReader<R> {
    state: State<R>,
}

impl<R> BoxReader<R>
where R: Unpin
{
    pub fn new(r: R, key: secretbox::Key, noncegen: NonceGen) -> BoxReader<R> {
        BoxReader {
            state: State::Ready(BoxReceiver::new(r, key, noncegen)),
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
            State::Ready(r)   |
            State::Data(r, _) |
            State::Closed(r) => r.reader,

            _ => panic!()
        }
    }
}

impl<R> AsyncRead for BoxReader<R>
where R: Unpin + AsyncRead + 'static
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8])
                 -> Poll<Result<usize, Error>> {
        let (state, p) = read(self.state.take(), cx, buf);
        self.state = state;
        p
    }
}
