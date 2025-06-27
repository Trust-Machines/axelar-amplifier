use cosmwasm_std::HexBinary;
use error_stack::ResultExt;

use crate::msg::{DecodeResponse, ExecuteMsg, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(
        "failed to query stacks abi transformer decode receive from hub. clarity payload: {0}"
    )]
    DecodeReceiveFromHub(HexBinary),
    #[error("failed to query stacks abi transformer decode send to hub. abi payload: {0}")]
    DecodeSendToHub(HexBinary),
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::DecodeReceiveFromHub { abi_payload } => {
                Error::DecodeReceiveFromHub(abi_payload)
            }
            QueryMsg::DecodeSendToHub { abi_payload } => Error::DecodeSendToHub(abi_payload),
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
    pub fn decode_receive_from_hub(&self, abi_payload: HexBinary) -> Result<DecodeResponse> {
        let msg = QueryMsg::DecodeReceiveFromHub { abi_payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn decode_send_to_hub(&self, abi_payload: HexBinary) -> Result<DecodeResponse> {
        let msg = QueryMsg::DecodeSendToHub { abi_payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}
