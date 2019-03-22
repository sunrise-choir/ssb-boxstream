#![feature(async_await, await_macro, futures_api)]

extern crate byteorder;
extern crate futures;
extern crate shs_core;
extern crate sodiumoxide;

mod duplex;
mod read;
mod write;

pub use duplex::*;
pub use read::*;
pub use write::*;
