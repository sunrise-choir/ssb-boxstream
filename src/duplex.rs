use crate::read::BoxReader;
use crate::write::BoxWriter;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_io::{self as io, AsyncRead, AsyncWrite};
use ssb_crypto::secretbox::{Key, Nonce};

pub struct BoxStream<R, W> {
    reader: BoxReader<R, Vec<u8>>,
    writer: BoxWriter<W, Vec<u8>>,
}

impl<R, W> BoxStream<R, W>
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    pub fn new(
        r: R,
        w: W,
        r_key: Key,
        r_nonce: Nonce,
        w_key: Key,
        w_nonce: Nonce,
    ) -> BoxStream<R, W> {
        BoxStream {
            reader: BoxReader::new(r, r_key, r_nonce),
            writer: BoxWriter::new(w, w_key, w_nonce),
        }
    }

    pub fn split(self) -> (BoxReader<R, Vec<u8>>, BoxWriter<W, Vec<u8>>) {
        let BoxStream { reader, writer } = self;
        (reader, writer)
    }
}

impl<R, W> AsyncRead for BoxStream<R, W>
where
    R: Unpin + AsyncRead + 'static,
    W: Unpin + AsyncWrite + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for BoxStream<R, W>
where
    R: Unpin + AsyncRead + 'static,
    W: Unpin + AsyncWrite + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.writer).poll_close(cx)
    }
}
