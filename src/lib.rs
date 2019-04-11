#![feature(async_await, await_macro, futures_api)]

extern crate byteorder;
extern crate futures;
extern crate ssb_crypto;
#[macro_use] extern crate quick_error;

mod duplex;
mod read;
mod write;

pub use duplex::*;
pub use read::*;
pub use write::*;


#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use futures::task::noop_waker;

    use ssb_crypto::{NonceGen, secretbox::{Key, Nonce}};

    use crate::write::{seal, seal_header};


    // Test data from https://github.com/AljoschaMeyer/box-stream-c
    const KEY_BYTES: [u8; 32] = [162,29,153,150,123,225,10,173,
                                 175,201,160,34,190,179,158,14,
                                 176,105,232,238,97,66,133,194,
                                 250,148,199,7,34,157,174,24];

    const NONCE_BYTES: [u8; 24] = [44,140,79,227,23,153,202,203,
                                   81,40,114,59,56,167,63,166,
                                   201,9,50,152,0,255,226,147];

    const HEAD1: [u8; 34] = [181,28,106,117,226,186,113,206,
                             135,153,250,54,221,225,178,211,
                             144,190,14,102,102,246,118,54,
                             195,34,174,182,190,45,129,48,96,193];

    const BODY1: [u8; 8] = [231,234,80,195,113,173,5,158];

    const HEAD2: [u8; 34] = [227,230,249,230,176,170,49,34,
                             220,29,156,118,225,243,7,3,
                             163,197,125,225,240,111,195,126,
                             240,148,201,237,158,158,134,224,246,137];
    const BODY2: [u8; 8] = [22,134,141,191,19,113,211,114];

    const HEAD3: [u8; 34] = [10,48,84,111,103,103,35,162,
                             175,78,189,58,240,250,196,226,
                             194,197,87,73,119,174,129,124,
                             225,30,3,26,37,221,87,213,153,123];

    #[test]
    fn encrypt() {
        let key = Key::from_slice(&KEY_BYTES).unwrap();
        let mut noncegen = NonceGen::with_starting_nonce(Nonce::from_slice(&NONCE_BYTES).unwrap());

        let (head, body) = seal(vec![0, 1, 2, 3, 4, 5, 6, 7], &key, &mut noncegen);
        assert_eq!(&head[..], &HEAD1[..]);
        assert_eq!(&body, &BODY1);

        let (head, body) = seal(vec![7, 6, 5, 4, 3, 2, 1, 0], &key, &mut noncegen);
        assert_eq!(&head[..], &HEAD2[..]);
        assert_eq!(&body, &BODY2);

        // goodbye
        let head = seal_header(&mut [0; 18], noncegen.next(), &key);
        assert_eq!(&head[..], &HEAD3[..]);
    }

    #[test]
    fn write_and_flush() {
        // TODO: use a buffered writer to test that boxwriter is actually
        //  flushing its 'inner' writer

        let key = Key::from_slice(&KEY_BYTES).unwrap();
        let noncegen = NonceGen::with_starting_nonce(Nonce::from_slice(&NONCE_BYTES).unwrap());

        let (rbw, mut rbr) = async_ringbuffer::ring_buffer(1024);
        let mut boxw = BoxWriter::new(rbw, key, noncegen);

        block_on(async {
            await!(boxw.write_all(&[0, 1, 2, 3, 4, 5, 6, 7])).unwrap();

            let mut head = [0; 34];

            // NOTE: async_ringbuffer reader.poll_read returns Pending if the buffer
            // is empty (not Ok(0))
            let wk = noop_waker();
            assert!(rbr.poll_read(&wk, &mut head).is_pending());

            await!(boxw.flush()).unwrap();

            await!(rbr.read_exact(&mut head)).unwrap();
            assert_eq!(&head[..], &HEAD1[..]);

            let mut body = [0; 8];
            await!(rbr.read_exact(&mut body)).unwrap();
            assert_eq!(&body, &BODY1);
        });
    }

    #[test]
    fn twoway() {
        let key = Key::from_slice(&KEY_BYTES).unwrap();
        let noncegen_r = NonceGen::with_starting_nonce(Nonce::from_slice(&NONCE_BYTES).unwrap());
        let noncegen_w = NonceGen::with_starting_nonce(Nonce::from_slice(&NONCE_BYTES).unwrap());

        let (rbw, rbr) = async_ringbuffer::ring_buffer(1024);
        let mut boxw = BoxWriter::new(rbw, key.clone(), noncegen_w);
        let mut boxr = BoxReader::new(rbr, key, noncegen_r);

        block_on(async {
            let body = [0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0];

            await!(boxw.write_all(&body[0..8])).unwrap();
            await!(boxw.flush()).unwrap();
            await!(boxw.write_all(&body[8..])).unwrap();
            await!(boxw.flush()).unwrap();

            let mut buf = [0; 16];
            await!(boxr.read_exact(&mut buf)).unwrap();
            assert_eq!(&buf, &body);

            await!(boxw.close()).unwrap();

            let n = await!(boxr.read(&mut buf)).unwrap();
            assert_eq!(n, 0);
            assert!(boxr.is_closed());
        });
    }
}
