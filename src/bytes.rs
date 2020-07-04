use zerocopy::LayoutVerified;
pub use zerocopy::{AsBytes, FromBytes};

pub fn cast<T: FromBytes>(b: &[u8]) -> &T {
    LayoutVerified::<&[u8], T>::new(b).unwrap().into_ref()
}

pub fn cast_mut<T: AsBytes + FromBytes>(b: &mut [u8]) -> &mut T {
    LayoutVerified::<&mut [u8], T>::new(b).unwrap().into_mut()
}
