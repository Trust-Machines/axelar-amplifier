use axelar_wasm_std::IntoContractError;
use clarity::vm::errors::{CheckErrors, Error as ClarityError, InterpreterError};
use clarity::vm::types::serialization::SerializationError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("payload is invalid")]
    InvalidPayload,

    #[error("amount is too large for Stacks")]
    InvalidAmount,
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
