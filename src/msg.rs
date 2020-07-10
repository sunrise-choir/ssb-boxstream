use crate::bytes::*;

use byteorder::BigEndian;
use core::mem::size_of;
use ssb_crypto::secretbox::{Hmac, Key, Nonce};
use zerocopy::byteorder::U16;
pub use zerocopy::{AsBytes, FromBytes};

#[derive(AsBytes, FromBytes, Copy, Clone)]
#[repr(C)]
pub struct Head {
    hmac: Hmac,
    hbox: [u8; 18],
}

impl Head {
    pub const SIZE: usize = size_of::<Self>();

    pub fn open(&mut self, key: &Key, nonce: Nonce) -> Option<&HeadPayload> {
        if key.open(&mut self.hbox, &self.hmac, &nonce) {
            Some(cast::<HeadPayload>(&self.hbox))
        } else {
            None
        }
    }
}

#[derive(AsBytes, FromBytes, Copy, Clone)]
#[repr(C)]
pub struct HeadPayload {
    pub body_size: U16<BigEndian>,
    pub body_hmac: Hmac,
}

impl HeadPayload {
    pub fn new(body_size: u16, body_hmac: Hmac) -> HeadPayload {
        HeadPayload {
            body_size: U16::new(body_size),
            body_hmac,
        }
    }
    pub fn seal(self, key: &Key, nonce: Nonce) -> Head {
        let mut hbox = [0; 18];
        hbox.copy_from_slice(self.as_bytes());
        let hmac = key.seal(&mut hbox, &nonce);
        Head { hmac, hbox }
    }

    pub fn goodbye() -> Self {
        Self {
            body_size: U16::new(0),
            body_hmac: Hmac([0; 16]),
        }
    }

    pub fn is_goodbye(&self) -> bool {
        self.body_size.get() == 0 && self.body_hmac.0 == [0; 16]
    }
}
