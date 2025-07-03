use clarity::vm::errors::{CheckErrors, Error as ClarityError, InterpreterError};
use clarity::vm::types::serialization::SerializationError;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("payload is invalid")]
    InvalidPayload,

    #[error("amount is too large for Stacks")]
    InvalidAmount,

    #[error("serialization failed")]
    SerializationFailed,
}

impl From<ClarityError> for ContractError {
    fn from(_: ClarityError) -> Self {
        ContractError::InvalidPayload
    }
}

impl From<InterpreterError> for ContractError {
    fn from(_: InterpreterError) -> Self {
        ContractError::InvalidPayload
    }
}

impl From<SerializationError> for ContractError {
    fn from(_: SerializationError) -> Self {
        ContractError::InvalidPayload
    }
}

impl From<CheckErrors> for ContractError {
    fn from(_: CheckErrors) -> Self {
        ContractError::InvalidPayload
    }
}
