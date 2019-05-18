use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;

use futures::io::{AsyncRead, AsyncWrite};

use shs_core::HandshakeOutcome;

use crate::read::BoxReader;
use crate::write::BoxWriter;

pub struct BoxStream<R, W> {
    reader: BoxReader<R>,
    writer: BoxWriter<W>,
}

impl<R, W> BoxStream<R, W>
where
    R: AsyncRead + Unpin + 'static,
    W: AsyncWrite + Unpin + 'static,
{
    pub fn client_side(r: R, w: W, h: HandshakeOutcome) -> BoxStream<R, W> {
        let HandshakeOutcome {
            read_key,
            read_noncegen,
            write_key,
            write_noncegen,
        } = h;
        BoxStream {
            reader: BoxReader::new(r, read_key, read_noncegen),
            writer: BoxWriter::new(w, write_key, write_noncegen),
        }
    }

    pub fn server_side(r: R, w: W, h: HandshakeOutcome) -> BoxStream<R, W> {
        let HandshakeOutcome {
            read_key,
            read_noncegen,
            write_key,
            write_noncegen,
        } = h;
        BoxStream {
            reader: BoxReader::new(r, read_key, read_noncegen),
            writer: BoxWriter::new(w, write_key, write_noncegen),
        }
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
