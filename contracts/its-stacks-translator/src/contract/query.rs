use cosmwasm_std::{Binary, HexBinary};
use interchain_token_service_std::HubMessage;

use crate::contract::decode::bytes_to_hub_message;
use crate::contract::encode::hub_message_to_bytes;
use crate::error::ContractError;

pub fn bytes_to_hub_message_query(payload: HexBinary) -> Result<Binary, ContractError> {
    let hub_message = bytes_to_hub_message(payload.to_vec())?;

    cosmwasm_std::to_json_binary(&hub_message).map_err(|_| ContractError::SerializationFailed)
}

pub fn hub_message_to_bytes_query(its_hub_message: HubMessage) -> Result<Binary, ContractError> {
    let clarity_payload = hub_message_to_bytes(its_hub_message)?;

    cosmwasm_std::to_json_binary(&clarity_payload).map_err(|_| ContractError::SerializationFailed)
}
