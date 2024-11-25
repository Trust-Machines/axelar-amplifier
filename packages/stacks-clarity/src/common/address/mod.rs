// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{error, fmt};

pub mod c32;

pub const C32_ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 22; // P
pub const C32_ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 20; // M
pub const C32_ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 26; // T
pub const C32_ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 21; // N

#[derive(Debug)]
pub enum Error {
    InvalidCrockford32,
    InvalidVersion(u8),
    EmptyData,
    /// Invalid character encountered
    BadByte(u8),
    /// Checksum was not correct (expected, actual)
    BadChecksum(u32, u32),
    /// The length (in bytes) of the object was not correct
    /// Note that if the length is excessively long the provided length may be
    /// an estimate (and the checksum step may be skipped).
    InvalidLength(usize),
    /// Checked data was less than 4 bytes
    TooShort(usize),
    /// Any other error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidCrockford32 => write!(f, "Invalid crockford 32 string"),
            Error::InvalidVersion(ref v) => write!(f, "Invalid version {}", v),
            Error::EmptyData => f.write_str("Empty data"),
            Error::BadByte(b) => write!(f, "invalid base58 character 0x{:x}", b),
            Error::BadChecksum(exp, actual) => write!(
                f,
                "base58ck checksum 0x{:x} does not match expected 0x{:x}",
                actual, exp
            ),
            Error::InvalidLength(ell) => write!(f, "length {} invalid for this base58 type", ell),
            Error::TooShort(_) => write!(f, "base58ck data not even long enough for a checksum"),
            Error::Other(ref s) => f.write_str(s),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &'static str {
        match *self {
            Error::InvalidCrockford32 => "Invalid crockford 32 string",
            Error::InvalidVersion(_) => "Invalid version",
            Error::EmptyData => "Empty data",
            Error::BadByte(_) => "invalid b58 character",
            Error::BadChecksum(_, _) => "invalid b58ck checksum",
            Error::InvalidLength(_) => "invalid length for b58 type",
            Error::TooShort(_) => "b58ck data less than 4 bytes",
            Error::Other(_) => "unknown b58 error",
        }
    }
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}
