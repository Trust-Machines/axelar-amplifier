use clarity_serialization::errors::CodecError;
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

impl From<CodecError> for ContractError {
    fn from(_: CodecError) -> Self {
        ContractError::InvalidPayload
    }
}
