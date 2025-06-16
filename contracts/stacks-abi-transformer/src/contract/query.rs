use crate::contract::its_receive_from_hub::get_its_payload_and_hash_receive_from_hub;
use crate::contract::its_send_to_hub::get_its_payload_and_hash_send_to_hub;
use crate::error::ContractError;
use crate::msg::DecodeResponse;
use cosmwasm_std::HexBinary;

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
    let (clarity_payload, payload_hash) = get_its_payload_and_hash_receive_from_hub(abi_payload)?;

    Ok(DecodeResponse {
        clarity_payload,
        payload_hash,
    })
}
