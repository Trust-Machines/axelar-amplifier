use std::str::FromStr;

use clarity_serialization::representations::ClarityName;
use clarity_serialization::types::{
    BufferLength, SequenceSubtype, StringSubtype, TupleData, TupleTypeSignature, TypeSignature,
    Value,
};
use clarity_serialization::codec::StacksMessageCodec;
use cosmwasm_std::Uint128;
use cw_storage_plus::KeyDeserialize;
use interchain_token_service_std::{
    DeployInterchainToken, HubMessage, InterchainTransfer, Message, TokenId,
};
use router_api::ChainNameRaw;
use stacks_types::constants::*;

use crate::error::ContractError;

pub fn bytes_to_hub_message(payload: Vec<u8>) -> Result<HubMessage, ContractError> {
    let tuple_data = its_hub_call_params(payload)?;

    // All messages should go through ITS hub
    if !tuple_data
        .get(CLARITY_NAME_TYPE)?
        .eq(&Value::UInt(MESSAGE_TYPE_SEND_TO_HUB))
    {
        return Err(ContractError::InvalidPayload);
    }

    let destination_chain = tuple_data
        .get(CLARITY_NAME_DESTINATION_CHAIN)?
        .clone()
        .expect_ascii()?;
    let payload = tuple_data.get_owned(CLARITY_NAME_PAYLOAD)?.expect_buff(
        CLARITY_SIZE_PAYLOAD
            .try_into()
            .map_err(|_| ContractError::InvalidPayload)?,
    )?;

    let subtuple_type_signature = TupleTypeSignature::try_from(vec![(
        ClarityName::from(CLARITY_NAME_TYPE),
        TypeSignature::UIntType,
    )])?;

    let original_its_call = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(subtuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let its_type = original_its_call
        .get_owned(CLARITY_NAME_TYPE)?
        .expect_u128()?;

    let message = match its_type {
        MESSAGE_TYPE_INTERCHAIN_TRANSFER => bytes_to_interchain_transfer_message(payload),
        MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN => bytes_to_deploy_interchain_token_message(payload),
        _ => {
            return Err(ContractError::InvalidPayload);
        }
    }?;

    Ok(HubMessage::SendToHub {
        message,
        destination_chain: ChainNameRaw::from_str(destination_chain.as_str())
            .map_err(|_| ContractError::InvalidPayload)?,
    })
}

fn its_hub_call_params(payload: Vec<u8>) -> Result<TupleData, ContractError> {
    let its_send_to_hub_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from(CLARITY_NAME_TYPE),
            TypeSignature::UIntType,
        ),
        (
            ClarityName::from(CLARITY_NAME_DESTINATION_CHAIN),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(CLARITY_SIZE_DESTINATION_CHAIN)?,
            ))),
        ),
        (
            ClarityName::from(CLARITY_NAME_PAYLOAD),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_PAYLOAD,
            )?)),
        ),
    ])?;

    let its_hub_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(its_send_to_hub_signature),
        true,
    )?
    .expect_tuple()?;

    Ok(its_hub_value)
}

fn bytes_to_interchain_transfer_message(payload: Vec<u8>) -> Result<Message, ContractError> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from(CLARITY_NAME_TOKEN_ID),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_TOKEN_ID,
            )?)),
        ),
        (
            ClarityName::from(CLARITY_NAME_SOURCE_ADDRESS),
            TypeSignature::PrincipalType,
        ),
        (
            ClarityName::from(CLARITY_NAME_DESTINATION_ADDRESS),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_DESTINATION_ADDRESS,
            )?)),
        ),
        (
            ClarityName::from(CLARITY_NAME_AMOUNT),
            TypeSignature::UIntType,
        ),
        (
            ClarityName::from(CLARITY_NAME_DATA),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_DATA,
            )?)),
        ),
    ])?;

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let data = original_value
        .data_map
        .remove(CLARITY_NAME_DATA)
        .ok_or(ContractError::InvalidPayload)?
        .expect_buff(
            CLARITY_SIZE_DATA
                .try_into()
                .map_err(|_| ContractError::InvalidPayload)?,
        )?;

    Ok(Message::InterchainTransfer(InterchainTransfer {
        token_id: TokenId::from_vec(
            original_value
                .data_map
                .remove(CLARITY_NAME_TOKEN_ID)
                .ok_or(ContractError::InvalidPayload)?
                .expect_buff(
                    CLARITY_SIZE_TOKEN_ID
                        .try_into()
                        .map_err(|_| ContractError::InvalidPayload)?,
                )?,
        )
        .map_err(|_| ContractError::InvalidPayload)?,
        source_address: original_value
            .data_map
            .remove(CLARITY_NAME_SOURCE_ADDRESS)
            .ok_or(ContractError::InvalidPayload)?
            .expect_principal()?
            .serialize_to_vec()
            .try_into()
            .map_err(|_| ContractError::InvalidPayload)?,
        destination_address: original_value
            .data_map
            .remove(CLARITY_NAME_DESTINATION_ADDRESS)
            .ok_or(ContractError::InvalidPayload)?
            .expect_buff(
                CLARITY_SIZE_DESTINATION_ADDRESS
                    .try_into()
                    .map_err(|_| ContractError::InvalidPayload)?,
            )?
            .try_into()
            .map_err(|_| ContractError::InvalidPayload)?,
        amount: <u128 as Into<Uint128>>::into(
            original_value
                .data_map
                .remove(CLARITY_NAME_AMOUNT)
                .ok_or(ContractError::InvalidPayload)?
                .expect_u128()?,
        )
        .try_into()
        .map_err(|_| ContractError::InvalidPayload)?,
        data: if data.is_empty() {
            None
        } else {
            Some(data.try_into().map_err(|_| ContractError::InvalidPayload)?)
        },
    }))
}

fn bytes_to_deploy_interchain_token_message(payload: Vec<u8>) -> Result<Message, ContractError> {
    let tuple_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from(CLARITY_NAME_TOKEN_ID),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_TOKEN_ID,
            )?)),
        ),
        (
            ClarityName::from(CLARITY_NAME_NAME),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(CLARITY_SIZE_NAME)?,
            ))),
        ),
        (
            ClarityName::from(CLARITY_NAME_SYMBOL),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(CLARITY_SIZE_SYMBOL)?,
            ))),
        ),
        (
            ClarityName::from(CLARITY_NAME_DECIMALS),
            TypeSignature::UIntType,
        ),
        (
            ClarityName::from(CLARITY_NAME_MINTER),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_MINTER,
            )?)),
        ),
    ])?;

    let mut original_value = Value::try_deserialize_bytes(
        &payload,
        &TypeSignature::TupleType(tuple_type_signature),
        true,
    )?
    .expect_tuple()?;

    let minter = original_value
        .data_map
        .remove(CLARITY_NAME_MINTER)
        .ok_or(ContractError::InvalidPayload)?
        .expect_buff(
            CLARITY_SIZE_MINTER
                .try_into()
                .map_err(|_| ContractError::InvalidPayload)?,
        )?;

    Ok(Message::DeployInterchainToken(DeployInterchainToken {
        token_id: TokenId::from_vec(
            original_value
                .data_map
                .remove(CLARITY_NAME_TOKEN_ID)
                .ok_or(ContractError::InvalidPayload)?
                .expect_buff(
                    CLARITY_SIZE_TOKEN_ID
                        .try_into()
                        .map_err(|_| ContractError::InvalidPayload)?,
                )?,
        )
        .map_err(|_| ContractError::InvalidPayload)?,
        name: original_value
            .data_map
            .remove(CLARITY_NAME_NAME)
            .ok_or(ContractError::InvalidPayload)?
            .expect_ascii()?
            .try_into()
            .map_err(|_| ContractError::InvalidPayload)?,
        symbol: original_value
            .data_map
            .remove(CLARITY_NAME_SYMBOL)
            .ok_or(ContractError::InvalidPayload)?
            .expect_ascii()?
            .try_into()
            .map_err(|_| ContractError::InvalidPayload)?,
        decimals: original_value
            .data_map
            .remove(CLARITY_NAME_DECIMALS)
            .ok_or(ContractError::InvalidPayload)?
            .expect_u128()?
            .try_into()
            .map_err(|_| ContractError::InvalidPayload)?,
        minter: if minter.is_empty() {
            None
        } else {
            Some(
                minter
                    .try_into()
                    .map_err(|_| ContractError::InvalidPayload)?,
            )
        },
    }))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::HexBinary;
    use interchain_token_service_std::{
        DeployInterchainToken, HubMessage, InterchainTransfer, Message,
    };
    use router_api::ChainNameRaw;

    use crate::contract::decode::bytes_to_hub_message;
    use crate::contract::query::bytes_to_hub_message_query;
    use crate::error::ContractError;

    #[test]
    fn bytes_to_hub_message_error() {
        let res = bytes_to_hub_message_query(HexBinary::from_hex("abcd").unwrap());

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            ContractError::InvalidPayload.to_string()
        );
    }

    #[test]
    fn bytes_to_hub_message_interchain_transfer() {
        /*
            payload is:
            {
                type: u3,
                destination-chain: "ethereum",
                payload: {
                    type: u0,
                    token-id: 0x753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f,
                    source-address: ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM,
                    destination-address: 0x00,
                    amount: u100000,
                    data: 0x00
                }
            }
        */
        let payload = HexBinary::from_hex("0c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f616402000000ab0c0000000606616d6f756e7401000000000000000000000000000186a004646174610200000001001364657374696e6174696f6e2d616464726573730200000001000e736f757263652d61646472657373051a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce08746f6b656e2d69640200000020753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f0474797065010000000000000000000000000000000004747970650100000000000000000000000000000003").unwrap();

        let result = bytes_to_hub_message(payload.to_vec()).unwrap();

        let token_id: [u8; 32] =
            from_hex("753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f")
                .to_vec()
                .try_into()
                .unwrap();

        let expected_its_hub_message = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("ethereum").unwrap(),
            message: Message::InterchainTransfer(InterchainTransfer {
                token_id: token_id.into(),
                source_address: from_hex("051a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce"),
                destination_address: from_hex("00"),
                amount: 100000u64.try_into().unwrap(),
                data: Some(from_hex("00")),
            }),
        };

        assert_eq!(result, expected_its_hub_message);
    }

    #[test]
    fn bytes_to_hub_message_deploy_interchain_token() {
        /*
            payload is:
            {
                type: u3,
                destination-chain: "ethereum",
                payload: {
                    type: u1,
                    token-id: 0x563dc3698c0f2c5adf375ff350bb54ecf86d2be109e3aacaf38111cdf171df78,
                    name: "sample",
                    symbol: "sample",
                    decimals: u6,
                    minter: 0x00
                }
            }
        */
        let payload = HexBinary::from_hex("0c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f616402000000920c0000000608646563696d616c730100000000000000000000000000000006066d696e746572020000000100046e616d650d0000000673616d706c650673796d626f6c0d0000000673616d706c6508746f6b656e2d69640200000020563dc3698c0f2c5adf375ff350bb54ecf86d2be109e3aacaf38111cdf171df780474797065010000000000000000000000000000000104747970650100000000000000000000000000000003").unwrap();

        let result = bytes_to_hub_message(payload.to_vec()).unwrap();

        let token_id: [u8; 32] =
            from_hex("563dc3698c0f2c5adf375ff350bb54ecf86d2be109e3aacaf38111cdf171df78")
                .to_vec()
                .try_into()
                .unwrap();

        let expected_its_hub_message = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("ethereum").unwrap(),
            message: Message::DeployInterchainToken(DeployInterchainToken {
                token_id: token_id.into(),
                name: "sample".to_string().try_into().unwrap(),
                symbol: "sample".to_string().try_into().unwrap(),
                decimals: 6,
                minter: Some(from_hex("00")),
            }),
        };

        assert_eq!(result, expected_its_hub_message);
    }

    fn from_hex(hex: &str) -> nonempty::HexBinary {
        HexBinary::from_hex(hex).unwrap().try_into().unwrap()
    }
}
