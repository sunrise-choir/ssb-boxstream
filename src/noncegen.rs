use ssb_crypto::secretbox::Nonce;

/// A series of nonces. Each nonce must only be used once.
/// Get the next nonce in the series by calling [`NonceGen::next`](./struct.NonceGen.html#method.next).
/// This isn't an iterator, but it probably should be.
pub struct NonceGen {
    next_nonce: Nonce,
}

impl NonceGen {
    /// Create a series of nonces, with the specified starting nonce.
    ///
    pub fn with_starting_nonce(nonce: Nonce) -> NonceGen {
        NonceGen { next_nonce: nonce }
    }

    /// Generate the next nonce in the series.
    /// This treats the underlying bytes as a big-endian number, and increments.
    pub fn next(&mut self) -> Nonce {
        let n = self.next_nonce;

        // Increment the nonce as a big-endian u24
        for byte in self.next_nonce.0.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        n
    }
}

#[test]
fn increment() {
    use crate::NonceGen;
    use ssb_crypto::secretbox::Nonce;

    let nonce_bytes = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
    ];
    let mut gen = NonceGen::with_starting_nonce(Nonce(nonce_bytes));
    let n1 = gen.next();
    assert_eq!(&n1.0, &nonce_bytes);
    let n2 = gen.next();
    assert_eq!(
        &n2.0,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
    );
}
