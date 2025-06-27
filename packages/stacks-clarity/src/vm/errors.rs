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

use crate::vm::analysis::errors::CheckErrors;
use crate::vm::contexts::StackTrace;
use crate::vm::types::Value;

#[derive(Debug)]
pub struct IncomparableError<T> {
    pub err: T,
}

#[derive(Debug)]
pub enum Error {
    /// UncheckedErrors are errors that *should* be caught by the
    ///   TypeChecker and other check passes. Test executions may
    ///   trigger these errors.
    Unchecked(CheckErrors),
    Interpreter(InterpreterError),
    Runtime(RuntimeErrorType, Option<StackTrace>),
    ShortReturn(ShortReturnType),
}

#[derive(Debug, PartialEq)]
pub enum InterpreterError {
    BadSender(Value),
    BadSymbolicRepresentation(String),
    InterpreterError(String),
    UninitializedPersistedVariable,
    FailedToConstructAssetTable,
    FailedToConstructEventBatch,
    BadFileName,
    FailedToCreateDataDirectory,
    MarfFailure(String),
    FailureConstructingTupleWithType,
    FailureConstructingListWithType,
    InsufficientBalance,
    CostContractLoadFailure,
    DBError(String),
    Expect(String),
}

/// RuntimeErrors are errors that smart contracts are expected
///   to be able to trigger during execution (e.g., arithmetic errors)
#[derive(Debug, PartialEq)]
pub enum RuntimeErrorType {
    Arithmetic(String),
    ArithmeticOverflow,
    ArithmeticUnderflow,
    SupplyOverflow(u128, u128),
    SupplyUnderflow(u128, u128),
    DivisionByZero,
    // error in parsing types
    ParseError(String),
    // error in parsing the AST
    // ASTError(ParseError),
    MaxStackDepthReached,
    MaxContextDepthReached,
    ListDimensionTooHigh,
    BadTypeConstruction,
    ValueTooLarge,
    BadBlockHeight(String),
    TransferNonPositiveAmount,
    NoSuchToken,
    NotImplemented,
    NoCallerInContext,
    NoSenderInContext,
    NonPositiveTokenSupply,
    // JSONParseError(IncomparableError<SerdeJSONErr>),
    AttemptToFetchInTransientContext,
    BadNameValue(&'static str, String),
    // UnknownBlockHeaderHash(BlockHeaderHash),
    BadBlockHash(Vec<u8>),
    UnwrapFailure,
    DefunctPoxContract,
    PoxAlreadyLocked,
    MetadataAlreadySet,
}

#[derive(Debug, PartialEq)]
pub enum ShortReturnType {
    ExpectedValue(Value),
    AssertionFailed(Value),
}

pub type InterpreterResult<R> = Result<R, Error>;

impl<T> PartialEq<IncomparableError<T>> for IncomparableError<T> {
    fn eq(&self, _other: &IncomparableError<T>) -> bool {
        return false;
    }
}

impl PartialEq<Error> for Error {
    fn eq(&self, other: &Error) -> bool {
        match (self, other) {
            (Error::Runtime(x, _), Error::Runtime(y, _)) => x == y,
            (Error::Unchecked(x), Error::Unchecked(y)) => x == y,
            (Error::ShortReturn(x), Error::ShortReturn(y)) => x == y,
            (Error::Interpreter(x), Error::Interpreter(y)) => x == y,
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Runtime(ref err, ref stack) => {
                match err {
                    _ => write!(f, "{}", err),
                }?;

                if let Some(ref stack_trace) = stack {
                    write!(f, "\n Stack Trace: \n")?;
                    for item in stack_trace.iter() {
                        write!(f, "{}\n", item)?;
                    }
                }
                Ok(())
            }
            _ => write!(f, "{:?}", self),
        }
    }
}

impl fmt::Display for RuntimeErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl error::Error for RuntimeErrorType {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<RuntimeErrorType> for Error {
    fn from(err: RuntimeErrorType) -> Self {
        Error::Runtime(err, None)
    }
}

impl From<CheckErrors> for Error {
    fn from(err: CheckErrors) -> Self {
        Error::Unchecked(err)
    }
}

impl From<ShortReturnType> for Error {
    fn from(err: ShortReturnType) -> Self {
        Error::ShortReturn(err)
    }
}

impl From<InterpreterError> for Error {
    fn from(err: InterpreterError) -> Self {
        Error::Interpreter(err)
    }
}

#[cfg(test)]
impl From<Error> for () {
    fn from(_: Error) -> Self {}
}

impl Into<Value> for ShortReturnType {
    fn into(self) -> Value {
        match self {
            ShortReturnType::ExpectedValue(v) => v,
            ShortReturnType::AssertionFailed(v) => v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn equality() {
        assert_eq!(
            Error::Interpreter(InterpreterError::InterpreterError("".to_string())),
            Error::Interpreter(InterpreterError::InterpreterError("".to_string()))
        );
    }
}
