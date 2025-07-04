use cosmwasm_std::{Binary, HexBinary};
use interchain_token_service_std::HubMessage;

use crate::contract::its_clarity_bytes_to_hub_message::its_clarity_bytes_to_hub_message;
use crate::contract::its_hub_message_to_clarity_bytes::its_hub_message_to_clarity_bytes;
use crate::error::ContractError;

pub fn clarity_bytes_to_hub_message(clarity_payload: HexBinary) -> Result<Binary, ContractError> {
    let hub_message = its_clarity_bytes_to_hub_message(clarity_payload.to_vec())?;

    cosmwasm_std::to_json_binary(&hub_message).map_err(|_| ContractError::SerializationFailed)
}

pub fn hub_message_to_clarity_bytes(its_hub_message: HubMessage) -> Result<Binary, ContractError> {
    let clarity_payload = its_hub_message_to_clarity_bytes(its_hub_message)?;

    cosmwasm_std::to_json_binary(&clarity_payload).map_err(|_| ContractError::SerializationFailed)
}
