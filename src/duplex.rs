
use core::task::{Poll, Waker};
use futures::io::{AsyncRead, AsyncWrite};
use std::io;

use shs_core::HandshakeOutcome;

use crate::read::BoxReader;
use crate::write::BoxWriter;


pub struct BoxStream<R, W> {
    reader: BoxReader<R>,
    writer: BoxWriter<W>,
}

impl<R, W> BoxStream<R, W> {
    pub fn client_side(r: R, w: W, h: HandshakeOutcome) -> BoxStream<R, W> {
        let HandshakeOutcome { c2s_key, s2c_key, c2s_noncegen, s2c_noncegen } = h;
        BoxStream {
            reader: BoxReader::new(r, s2c_key.into_inner(), s2c_noncegen.into_inner()),
            writer: BoxWriter::new(w, c2s_key.into_inner(), c2s_noncegen.into_inner()),
        }
    }

    pub fn server_side(r: R, w: W, h: HandshakeOutcome) -> BoxStream<R, W> {
        let HandshakeOutcome { c2s_key, s2c_key, c2s_noncegen, s2c_noncegen } = h;
        BoxStream {
            reader: BoxReader::new(r, c2s_key.into_inner(), c2s_noncegen.into_inner()),
            writer: BoxWriter::new(w, s2c_key.into_inner(), s2c_noncegen.into_inner()),
        }
    }
}

impl<R: AsyncRead + 'static, W> AsyncRead for BoxStream<R, W> {
    fn poll_read(&mut self, wk: &Waker, buf: &mut [u8])
                 -> Poll<Result<usize, io::Error>> {
        self.reader.poll_read(wk, buf)
    }
}

impl<R, W: AsyncWrite + 'static> AsyncWrite for BoxStream<R, W> {
    fn poll_write(&mut self, wk: &Waker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        self.writer.poll_write(wk, buf)
    }

    fn poll_flush(&mut self, wk: &Waker) -> Poll<Result<(), io::Error>> {
        self.writer.poll_flush(wk)
    }

    fn poll_close(&mut self, wk: &Waker) -> Poll<Result<(), io::Error>> {
        self.writer.poll_close(wk)
    }
}
