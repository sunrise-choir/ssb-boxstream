
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
        let HandshakeOutcome { read_key, read_noncegen, write_key, write_noncegen } = h;
        BoxStream {
            reader: BoxReader::new(r, read_key, read_noncegen),
            writer: BoxWriter::new(w, write_key, write_noncegen),
        }
    }

    pub fn server_side(r: R, w: W, h: HandshakeOutcome) -> BoxStream<R, W> {
        let HandshakeOutcome { read_key, read_noncegen, write_key, write_noncegen } = h;
        BoxStream {
            reader: BoxReader::new(r, read_key, read_noncegen),
            writer: BoxWriter::new(w, write_key, write_noncegen),
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
