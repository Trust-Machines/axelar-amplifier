use std::fmt::Write;

use crate::common::util::pair::Pairable;
use crate::common::util::HexError;

// borrowed from Andrew Poelstra's rust-bitcoin library
/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    let mut v = vec![];
    let mut iter = s.chars().pair();
    // Do the parsing
    iter.by_ref()
        .try_fold((), |_, (f, s)| match (f.to_digit(16), s.to_digit(16)) {
            (None, _) => Err(HexError::BadCharacter(f)),
            (_, None) => Err(HexError::BadCharacter(s)),
            (Some(f), Some(s)) => {
                v.push((f * 0x10 + s) as u8);
                Ok(())
            }
        })?;
    // Check that there was no remainder
    match iter.remainder() {
        Some(_) => Err(HexError::BadLength(s.len())),
        None => Ok(v),
    }
}

pub fn to_hex(s: &[u8]) -> String {
    let mut r = String::with_capacity(s.len() * 2);
    for b in s.iter() {
        write!(r, "{:02x}", b).unwrap();
    }
    r
}
