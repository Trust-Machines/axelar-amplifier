use crate::contract::its_clarity_bytes_to_hub_message::get_its_hub_message;
use crate::contract::its_receive_from_hub::get_its_payload_and_hash_receive_from_hub;
use crate::contract::its_send_to_hub::get_its_payload_and_hash_send_to_hub;
use crate::error::ContractError;
use crate::msg::DecodeResponse;
use cosmwasm_std::HexBinary;
use interchain_token_service::HubMessage;

pub fn decode_send_to_hub(
    abi_payload: HexBinary,
) -> error_stack::Result<DecodeResponse, ContractError> {
    let (clarity_payload, payload_hash) = get_its_payload_and_hash_send_to_hub(abi_payload)?;

    Ok(DecodeResponse {
        clarity_payload,
        payload_hash,
    })
}

pub fn decode_receive_from_hub(
    abi_payload: HexBinary,
) -> error_stack::Result<DecodeResponse, ContractError> {
    let its_hub_message = HubMessage::abi_decode(abi_payload.as_slice())
        .map_err(|_| ContractError::InvalidPayload)?;

    let (clarity_payload, payload_hash) =
        get_its_payload_and_hash_receive_from_hub(its_hub_message)?;

    Ok(DecodeResponse {
        clarity_payload,
        payload_hash,
    })
}

pub fn clarity_bytes_to_hub_message(
    clarity_payload: HexBinary,
) -> error_stack::Result<HubMessage, ContractError> {
    let hub_message = get_its_hub_message(clarity_payload.to_vec())?;

    Ok(hub_message)
}

pub fn hub_message_to_clarity_bytes(
    its_hub_message: HubMessage,
) -> error_stack::Result<HexBinary, ContractError> {
    let (clarity_payload, _) = get_its_payload_and_hash_receive_from_hub(its_hub_message)?;

    Ok(clarity_payload.into())
}
