use crate::contract::its::get_its_payload_and_hash;
use crate::error::ContractError;
use crate::msg::DecodeResponse;
use cosmwasm_std::HexBinary;

pub fn decode_from_abi(
    abi_payload: HexBinary,
) -> error_stack::Result<DecodeResponse, ContractError> {
    let (clarity_payload, payload_hash) = get_its_payload_and_hash(abi_payload)?;

    Ok(DecodeResponse {
        clarity_payload,
        payload_hash,
    })
}
