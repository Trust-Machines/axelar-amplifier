use crate::error::ContractError;
use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::HexBinary;
use interchain_token_service as its;
use interchain_token_service::TokenId;
use sha3::{Digest, Keccak256};
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::signatures::{
    BufferLength, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
};
use stacks_clarity::vm::types::{TupleData, Value};

pub fn get_its_payload_hash(message_payload: HexBinary) -> Result<[u8; 32], ContractError> {
    let its_hub_message = its::HubMessage::abi_decode(message_payload.as_slice()).unwrap();

    let payload = match its_hub_message {
        its::HubMessage::SendToHub { .. } => Err(ContractError::InvalidPayload),
        its::HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => match message {
            its::Message::InterchainTransfer {
                token_id,
                source_address,
                destination_address,
                amount,
                data,
            } => get_its_interchain_transfer_payload(
                token_id,
                source_address,
                destination_address,
                amount,
                data,
            ),
            its::Message::DeployInterchainToken { .. }
            | its::Message::DeployTokenManager { .. } => {
                todo!()
            }
        },
    }?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload).into();

    Ok(payload_hash)
}

fn get_its_interchain_transfer_payload(
    token_id: TokenId,
    source_address: HexBinary,
    destination_address: HexBinary,
    amount: Uint256,
    data: Option<HexBinary>,
) -> Result<Vec<u8>, ContractError> {
    let tuple_type_signature = TupleData::from_data(vec![
        (ClarityName::from("type"), Value::UInt(0)), // TODO: Add consts for these
        (
            ClarityName::from("token-id"),
            Value::buff_from(token-id),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                32u32,
            )?)),
        ),
        (
            ClarityName::from("source-address"),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(48u32)?,
            ))),
        ),
        (
            ClarityName::from("destination-address"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                200u32,
            )?)),
        ),
        (ClarityName::from("amount"), TypeSignature::UIntType),
        (
            ClarityName::from("data"),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                256u32,
            )?)),
        ),
    ])?;
    Value::from()

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let abi_payload = encode(&[
        Token::Uint(MESSAGE_TYPE_INTERCHAIN_TRANSFER.into()),
        Token::FixedBytes(
            original_value
                .data_map
                .remove("token-id")
                .ok_or(Error::InvalidCall)?
                .expect_buff(32)?,
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("source-address")
                .ok_or(Error::InvalidCall)?
                .expect_principal()?
                .serialize_to_vec(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("destination-address")
                .ok_or(Error::InvalidCall)?
                .expect_buff(100)?,
        ),
        Token::Uint(
            original_value
                .data_map
                .remove("amount")
                .ok_or(Error::InvalidCall)?
                .expect_u128()?
                .into(),
        ),
        Token::Bytes(
            original_value
                .data_map
                .remove("data")
                .ok_or(Error::InvalidCall)?
                .expect_buff(1024)?,
        ),
    ]);

    Ok(abi_payload)
}
