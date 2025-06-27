use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(interchain_token_service::HubMessage)]
    FromBytes { payload: HexBinary },

    #[returns(HexBinary)]
    ToBytes {
        message: interchain_token_service::HubMessage,
    },
}
