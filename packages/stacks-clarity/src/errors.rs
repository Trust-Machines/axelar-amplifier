use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct FunctionIdentifier {
    identifier: String,
}

impl fmt::Display for FunctionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

pub type StackTrace = Vec<FunctionIdentifier>;

#[derive(Debug)]
pub enum Error {
    /// UncheckedErrors are errors that *should* be caught by the
    ///   TypeChecker and other check passes. Test executions may
    ///   trigger these errors.
    // Unchecked(CheckErrors),
    // Interpreter(InterpreterError),
    Runtime(RuntimeErrorType, Option<StackTrace>),
    // ShortReturn(ShortReturnType),
}

#[derive(Debug, PartialEq)]
pub enum RuntimeErrorType {
    ParseError(String),
    BadNameValue(&'static str, String),
}

impl From<RuntimeErrorType> for Error {
    fn from(err: RuntimeErrorType) -> Self {
        Error::Runtime(err, None)
    }
}

pub type InterpreterResult<R> = Result<R, Error>;

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
