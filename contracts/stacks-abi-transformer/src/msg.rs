use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
pub struct DecodeResponse {
    pub clarity_payload: Vec<u8>,
    pub payload_hash: [u8; 32],
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(DecodeResponse)]
    DecodeReceiveFromHub { abi_payload: HexBinary },

    #[returns(DecodeResponse)]
    DecodeSendToHub { abi_payload: HexBinary },

    #[returns(interchain_token_service::HubMessage)]
    FromBytes { payload: HexBinary },

    #[returns(HexBinary)]
    ToBytes {
        message: interchain_token_service::HubMessage,
    },
}
