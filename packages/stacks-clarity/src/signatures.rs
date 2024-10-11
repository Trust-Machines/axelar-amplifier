use serde::{Deserialize, Serialize};
use crate::errors::CheckErrors;
use crate::MAX_VALUE_SIZE;

type Result<R> = std::result::Result<R, CheckErrors>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BufferLength(u32);

impl TryFrom<u32> for BufferLength {
    type Error = CheckErrors;
    fn try_from(data: u32) -> Result<BufferLength> {
        if data > MAX_VALUE_SIZE {
            Err(CheckErrors::ValueTooLarge)
        } else {
            Ok(BufferLength(data))
        }
    }
}

impl TryFrom<usize> for BufferLength {
    type Error = CheckErrors;
    fn try_from(data: usize) -> Result<BufferLength> {
        if data > (MAX_VALUE_SIZE as usize) {
            Err(CheckErrors::ValueTooLarge)
        } else {
            Ok(BufferLength(data as u32))
        }
    }
}

impl From<BufferLength> for u32 {
    fn from(v: BufferLength) -> u32 {
        v.0
    }
}
