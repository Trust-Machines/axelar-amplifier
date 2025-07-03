use cosmwasm_std::HexBinary;
use interchain_token_service::HubMessage;

use crate::contract::its_clarity_bytes_to_hub_message::its_clarity_bytes_to_hub_message;
use crate::contract::its_hub_message_to_clarity_bytes::its_hub_message_to_clarity_bytes;
use crate::error::ContractError;

pub fn clarity_bytes_to_hub_message(
    clarity_payload: HexBinary,
) -> error_stack::Result<HubMessage, ContractError> {
    let hub_message = its_clarity_bytes_to_hub_message(clarity_payload.to_vec())?;

    Ok(hub_message)
}

pub fn hub_message_to_clarity_bytes(
    its_hub_message: HubMessage,
) -> error_stack::Result<HexBinary, ContractError> {
    let clarity_payload = its_hub_message_to_clarity_bytes(its_hub_message)?;

    Ok(clarity_payload.into())
}
