use axelar_wasm_std::nonempty;
use axelar_wasm_std::nonempty::Uint256;
use clarity_serialization::representations::ClarityName;
use clarity_serialization::types::{TupleData, Value};
use cosmwasm_std::{HexBinary, Uint128};
use interchain_token_service_std::{
    DeployInterchainToken, HubMessage, InterchainTransfer, Message, TokenId,
};
use router_api::ChainNameRaw;
use stacks_types::constants::*;

use crate::error::ContractError;

pub fn hub_message_to_bytes(its_hub_message: HubMessage) -> Result<HexBinary, ContractError> {
    let payload = match its_hub_message {
        HubMessage::SendToHub { .. } => Err(ContractError::InvalidPayload),
        HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => match message {
            Message::InterchainTransfer(InterchainTransfer {
                token_id,
                source_address,
                destination_address,
                amount,
                data,
            }) => interchain_transfer_message_to_bytes(
                source_chain,
                token_id,
                source_address.into(),
                destination_address.into(),
                amount,
                data,
            ),
            Message::DeployInterchainToken(DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals,
                minter,
            }) => deploy_interchain_token_message_to_bytes(
                source_chain,
                token_id,
                name.into(),
                symbol.into(),
                decimals,
                minter,
            ),
            Message::LinkToken(_) => Err(ContractError::InvalidPayload),
        },
        HubMessage::RegisterTokenMetadata(_) => Err(ContractError::InvalidPayload),
    }?;

    Ok(payload.into())
}

fn interchain_transfer_message_to_bytes(
    source_chain: ChainNameRaw,
    token_id: TokenId,
    source_address: HexBinary,
    destination_address: HexBinary,
    amount: Uint256,
    data: Option<nonempty::HexBinary>,
) -> Result<Vec<u8>, ContractError> {
    let token_id: [u8; 32] = token_id.into();

    if amount > Uint256::try_from(Uint128::MAX).map_err(|_| ContractError::InvalidAmount)? {
        return Err(ContractError::InvalidAmount);
    }

    let amount: Uint128 = cosmwasm_std::Uint256::from(amount)
        .try_into()
        .map_err(|_| ContractError::InvalidAmount)?;

    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::from(CLARITY_NAME_TYPE),
            Value::UInt(MESSAGE_TYPE_INTERCHAIN_TRANSFER),
        ),
        (
            ClarityName::from(CLARITY_NAME_SOURCE_CHAIN),
            Value::string_ascii_from_bytes(source_chain.to_string().into_bytes())
                .map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_TOKEN_ID),
            Value::buff_from(token_id.to_vec()).map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_SOURCE_ADDRESS),
            Value::buff_from(source_address.to_vec()).map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_DESTINATION_ADDRESS),
            Value::buff_from(destination_address.to_vec())
                .map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_AMOUNT),
            Value::UInt(amount.u128()),
        ),
        (
            ClarityName::from(CLARITY_NAME_DATA),
            Value::buff_from(if let Some(data) = data {
                data.to_vec()
            } else {
                vec![]
            })
            .map_err(|_| ContractError::InvalidPayload)?,
        ),
    ])?;

    Ok(Value::from(tuple_data).serialize_to_vec()?)
}

fn deploy_interchain_token_message_to_bytes(
    source_chain: ChainNameRaw,
    token_id: TokenId,
    name: String,
    symbol: String,
    decimals: u8,
    minter: Option<nonempty::HexBinary>,
) -> Result<Vec<u8>, ContractError> {
    let token_id: [u8; 32] = token_id.into();

    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::from(CLARITY_NAME_TYPE),
            Value::UInt(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN),
        ),
        (
            ClarityName::from(CLARITY_NAME_SOURCE_CHAIN),
            Value::string_ascii_from_bytes(source_chain.to_string().into_bytes())
                .map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_TOKEN_ID),
            Value::buff_from(token_id.to_vec()).map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_NAME),
            Value::string_ascii_from_bytes(name.into_bytes())
                .map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_SYMBOL),
            Value::string_ascii_from_bytes(symbol.into_bytes())
                .map_err(|_| ContractError::InvalidPayload)?,
        ),
        (
            ClarityName::from(CLARITY_NAME_DECIMALS),
            Value::UInt(decimals.into()),
        ),
        (
            ClarityName::from(CLARITY_NAME_MINTER_BYTES),
            Value::buff_from(if let Some(minter) = minter {
                minter.to_vec()
            } else {
                vec![]
            })
            .map_err(|_| ContractError::InvalidPayload)?,
        ),
    ])?;

    Ok(Value::from(tuple_data).serialize_to_vec()?)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::nonempty;
    use clarity_serialization::representations::ClarityName;
    use clarity_serialization::types::{TupleData, Value};
    use cosmwasm_std::HexBinary;
    use interchain_token_service_std::{
        DeployInterchainToken, HubMessage, InterchainTransfer, Message, TokenId,
    };
    use router_api::ChainNameRaw;

    use crate::contract::encode::{
        hub_message_to_bytes, MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN,
        MESSAGE_TYPE_INTERCHAIN_TRANSFER,
    };
    use crate::error::ContractError;

    #[test]
    fn hub_message_to_bytes_error() {
        let token_id: [u8; 32] =
            from_hex("753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f")
                .to_vec()
                .try_into()
                .unwrap();

        let its_hub_message = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: Message::DeployInterchainToken(DeployInterchainToken {
                token_id: TokenId::new(token_id),
                name: "name".to_string().try_into().unwrap(),
                symbol: "symbol".to_string().try_into().unwrap(),
                decimals: 18,
                minter: None,
            }),
        };

        let res = hub_message_to_bytes(its_hub_message);

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            ContractError::InvalidPayload.to_string()
        );
    }

    #[test]
    fn hub_message_to_bytes_interchain_transfer() {
        let token_id: [u8; 32] =
            from_hex("753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f")
                .to_vec()
                .try_into()
                .unwrap();

        let its_hub_message = HubMessage::ReceiveFromHub {
            source_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: Message::InterchainTransfer(InterchainTransfer {
                token_id: token_id.into(),
                source_address: from_hex("00"),
                destination_address: from_hex("10"),
                amount: 1u64.try_into().unwrap(),
                data: Some(from_hex("1234")),
            }),
        };

        let payload = hub_message_to_bytes(its_hub_message).unwrap();

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("type"),
                Value::UInt(MESSAGE_TYPE_INTERCHAIN_TRANSFER),
            ),
            (
                ClarityName::from("source-chain"),
                Value::string_ascii_from_bytes("chain".to_string().into_bytes()).unwrap(),
            ),
            (
                ClarityName::from("token-id"),
                Value::buff_from(token_id.into()).unwrap(),
            ),
            (
                ClarityName::from("source-address"),
                Value::buff_from(from_hex("00").to_vec()).unwrap(),
            ),
            (
                ClarityName::from("destination-address"),
                Value::buff_from(from_hex("10").to_vec()).unwrap(),
            ),
            (ClarityName::from("amount"), Value::UInt(1u128)),
            (
                ClarityName::from("data"),
                Value::buff_from(from_hex("1234").to_vec()).unwrap(),
            ),
        ])
        .unwrap();
        let expected_payload = Value::from(tuple_data).serialize_to_vec().unwrap();
        let expected_payload_hex = HexBinary::from(expected_payload);

        goldie::assert!(expected_payload_hex.to_hex());

        assert_eq!(payload, expected_payload_hex);
    }

    #[test]
    fn hub_message_to_bytes_deploy_interchain_token() {
        let token_id: [u8; 32] =
            from_hex("753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f")
                .to_vec()
                .try_into()
                .unwrap();

        let its_hub_message = HubMessage::ReceiveFromHub {
            source_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: Message::DeployInterchainToken(DeployInterchainToken {
                token_id: token_id.into(),
                name: "name".to_string().try_into().unwrap(),
                symbol: "symbol".to_string().try_into().unwrap(),
                decimals: 18,
                minter: Some(from_hex("1234")),
            }),
        };

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("type"),
                Value::UInt(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN),
            ),
            (
                ClarityName::from("source-chain"),
                Value::string_ascii_from_bytes("chain".to_string().into_bytes()).unwrap(),
            ),
            (
                ClarityName::from("token-id"),
                Value::buff_from(token_id.into()).unwrap(),
            ),
            (
                ClarityName::from("name"),
                Value::string_ascii_from_bytes("name".to_string().into_bytes()).unwrap(),
            ),
            (
                ClarityName::from("symbol"),
                Value::string_ascii_from_bytes("symbol".to_string().into_bytes()).unwrap(),
            ),
            (ClarityName::from("decimals"), Value::UInt(18u128)),
            (
                ClarityName::from("minter-bytes"),
                Value::buff_from(from_hex("1234").to_vec()).unwrap(),
            ),
        ])
        .unwrap();
        let expected_payload = Value::from(tuple_data).serialize_to_vec().unwrap();
        let expected_payload_hex = HexBinary::from(expected_payload);

        let payload = hub_message_to_bytes(its_hub_message).unwrap();

        goldie::assert!(expected_payload_hex.to_hex());

        assert_eq!(payload, expected_payload_hex);
    }

    fn from_hex(hex: &str) -> nonempty::HexBinary {
        HexBinary::from_hex(hex).unwrap().try_into().unwrap()
    }
}
