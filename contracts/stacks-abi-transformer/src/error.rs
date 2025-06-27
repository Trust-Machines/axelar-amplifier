use axelar_wasm_std::IntoContractError;
use stacks_clarity::vm::errors::Error as ClarityError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("payload is invalid")]
    InvalidPayload,

    #[error("message is invalid")]
    InvalidMessage,

    #[error("amount is too large for Stacks")]
    InvalidAmount,
}

impl From<ClarityError> for ContractError {
    fn from(_: ClarityError) -> Self {
        ContractError::InvalidMessage
    }
}
