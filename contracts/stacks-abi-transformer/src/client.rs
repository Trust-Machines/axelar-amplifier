use cosmwasm_std::HexBinary;
use error_stack::ResultExt;

use crate::msg::{DecodeResponse, ExecuteMsg, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to query stacks abi transformer encode to abi. clarity payload: {0}")]
    EncodeToAbi(HexBinary),
    #[error("failed to query stacks abi transformer decode from abi. abi payload: {0}")]
    DecodeFromAbi(HexBinary),
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::EncodeToAbi { stacks_payload } => Error::EncodeToAbi(stacks_payload),
            QueryMsg::DecodeFromAbi { abi_payload } => Error::DecodeFromAbi(abi_payload),
        }
    }
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    pub fn encode_to_abi(&self, stacks_payload: HexBinary) -> Result<HexBinary> {
        let msg = QueryMsg::EncodeToAbi { stacks_payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn decode_from_abi(&self, abi_payload: HexBinary) -> Result<DecodeResponse> {
        let msg = QueryMsg::DecodeFromAbi { abi_payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {
    //     TODO:
}
