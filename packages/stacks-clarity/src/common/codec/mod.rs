use std::{error, fmt, io};
use std::io::{Write};

#[macro_use]
pub mod macros;

#[derive(Debug)]
pub enum Error {
    /// Failed to encode
    SerializeError(String),
    /// Failed to read
    ReadError(io::Error),
    /// Failed to decode
    DeserializeError(String),
    /// Failed to write
    WriteError(io::Error),
    /// Underflow -- not enough bytes to form the message
    UnderflowError(String),
    /// Overflow -- message too big
    OverflowError(String),
    /// Array is too big
    ArrayTooLong,
    /// Failed to sign
    SigningError(String),
    /// Generic error
    GenericError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SerializeError(ref s) => fmt::Display::fmt(s, f),
            Error::DeserializeError(ref s) => fmt::Display::fmt(s, f),
            Error::ReadError(ref io) => fmt::Display::fmt(io, f),
            Error::WriteError(ref io) => fmt::Display::fmt(io, f),
            Error::UnderflowError(ref s) => fmt::Display::fmt(s, f),
            Error::OverflowError(ref s) => fmt::Display::fmt(s, f),
            Error::ArrayTooLong => write!(f, "Array too long"),
            Error::SigningError(ref s) => fmt::Display::fmt(s, f),
            Error::GenericError(ref s) => fmt::Display::fmt(s, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::SerializeError(ref _s) => None,
            Error::ReadError(ref io) => Some(io),
            Error::DeserializeError(ref _s) => None,
            Error::WriteError(ref io) => Some(io),
            Error::UnderflowError(ref _s) => None,
            Error::OverflowError(ref _s) => None,
            Error::ArrayTooLong => None,
            Error::SigningError(ref _s) => None,
            Error::GenericError(ref _s) => None,
        }
    }
}

pub trait StacksMessageCodec {
    /// serialize implementors _should never_ error unless there is an underlying
    ///   failure in writing to the `fd`
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error>
    where
        Self: Sized;
    /// Convenience for serialization to a vec.
    ///  this function unwraps any underlying serialization error
    fn serialize_to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: serialization to buffer failed.");
        bytes
    }
}

impl_stacks_message_codec_for_int!(u8; [0; 1]);
impl_stacks_message_codec_for_int!(u16; [0; 2]);
impl_stacks_message_codec_for_int!(u32; [0; 4]);
impl_stacks_message_codec_for_int!(u64; [0; 8]);
impl_stacks_message_codec_for_int!(i64; [0; 8]);

impl StacksMessageCodec for [u8; 20] {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        fd.write_all(self).map_err(Error::WriteError)
    }
}

impl StacksMessageCodec for [u8; 32] {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        fd.write_all(self).map_err(Error::WriteError)
    }
}

pub fn write_next<T: StacksMessageCodec, W: Write>(fd: &mut W, item: &T) -> Result<(), Error> {
    item.consensus_serialize(fd)
}

impl<T> StacksMessageCodec for Vec<T>
where
    T: StacksMessageCodec + Sized,
{
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        let len = self.len() as u32;
        write_next(fd, &len)?;
        for item in self {
            write_next(fd, item)?;
        }
        Ok(())
    }
}
