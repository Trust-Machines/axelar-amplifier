use axelar_wasm_std::nonempty;
use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::{HexBinary, Uint128};
use interchain_token_service as its;
use interchain_token_service::{HubMessage, Message, TokenId};
use sha3::{Digest, Keccak256};
use stacks_clarity::common::codec::StacksMessageCodec;
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::{PrincipalData, TupleData, Value};

use crate::error::ContractError;

pub const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
pub const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;

pub fn get_its_payload_and_hash_send_to_hub(
    message_payload: HexBinary,
) -> Result<(Vec<u8>, [u8; 32]), ContractError> {
    let its_hub_message = HubMessage::abi_decode(message_payload.as_slice())
        .map_err(|_| ContractError::InvalidPayload)?;

    let payload = match its_hub_message {
        HubMessage::ReceiveFromHub { .. } => Err(ContractError::InvalidPayload),
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let inner_payload = match message {
                Message::InterchainTransfer(its::InterchainTransfer {
                    token_id,
                    source_address,
                    destination_address,
                    amount,
                    data,
                }) => get_its_interchain_transfer_payload_send_to_hub(
                    token_id,
                    source_address.into(),
                    destination_address.into(),
                    amount,
                    data,
                ),
                Message::DeployInterchainToken(its::DeployInterchainToken {
                    token_id,
                    name,
                    symbol,
                    decimals,
                    minter,
                }) => get_its_deploy_interchain_token_payload_send_to_hub(
                    token_id,
                    name.into(),
                    symbol.into(),
                    decimals,
                    minter,
                ),
                Message::LinkToken(_) => Err(ContractError::InvalidPayload),
            }?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from("type"),
                    Value::UInt(MESSAGE_TYPE_SEND_TO_HUB),
                ),
                (
                    ClarityName::from("destination-chain"),
                    Value::string_ascii_from_bytes(destination_chain.to_string().into_bytes())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from("payload"),
                    Value::buff_from(inner_payload)?,
                ),
            ])?;

            Ok(Value::from(tuple_data).serialize_to_vec())
        }
        HubMessage::RegisterTokenMetadata(_) => Err(ContractError::InvalidPayload),
    }?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();

    Ok((payload, payload_hash))
}

fn get_its_interchain_transfer_payload_send_to_hub(
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
            ClarityName::from("type"),
            Value::UInt(MESSAGE_TYPE_INTERCHAIN_TRANSFER),
        ),
        (
            ClarityName::from("token-id"),
            Value::buff_from(token_id.to_vec()).map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("source-address"),
            PrincipalData::inner_consensus_deserialize(&mut source_address.clone().as_slice())
                .map_err(|_| ContractError::InvalidMessage)?
                .into(),
        ),
        (
            ClarityName::from("destination-address"),
            Value::buff_from(destination_address.to_vec())
                .map_err(|_| ContractError::InvalidMessage)?,
        ),
        (ClarityName::from("amount"), Value::UInt(amount.u128())),
        (
            ClarityName::from("data"),
            Value::buff_from(if let Some(data) = data {
                data.to_vec()
            } else {
                vec![]
            })
            .map_err(|_| ContractError::InvalidMessage)?,
        ),
    ])?;

    Ok(Value::from(tuple_data).serialize_to_vec())
}

fn get_its_deploy_interchain_token_payload_send_to_hub(
    token_id: TokenId,
    name: String,
    symbol: String,
    decimals: u8,
    minter: Option<nonempty::HexBinary>,
) -> Result<Vec<u8>, ContractError> {
    let token_id: [u8; 32] = token_id.into();

    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::from("type"),
            Value::UInt(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN),
        ),
        (
            ClarityName::from("token-id"),
            Value::buff_from(token_id.to_vec()).map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("name"),
            Value::string_ascii_from_bytes(name.into_bytes())
                .map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("symbol"),
            Value::string_ascii_from_bytes(symbol.into_bytes())
                .map_err(|_| ContractError::InvalidMessage)?,
        ),
        (ClarityName::from("decimals"), Value::UInt(decimals.into())),
        (
            ClarityName::from("minter"),
            Value::buff_from(if let Some(minter) = minter {
                minter.to_vec()
            } else {
                vec![]
            })
            .map_err(|_| ContractError::InvalidMessage)?,
        ),
    ])?;

    Ok(Value::from(tuple_data).serialize_to_vec())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::contract::its_send_to_hub::{
        get_its_payload_and_hash_send_to_hub, MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN,
        MESSAGE_TYPE_INTERCHAIN_TRANSFER, MESSAGE_TYPE_SEND_TO_HUB,
    };
    use crate::error::ContractError;
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::HexBinary;
    use interchain_token_service as its;
    use interchain_token_service::TokenId;
    use router_api::ChainNameRaw;
    use sha3::{Digest, Keccak256};
    use stacks_clarity::common::codec::StacksMessageCodec;
    use stacks_clarity::vm::representations::ClarityName;
    use stacks_clarity::vm::types::{PrincipalData, TupleData, Value};

    #[test]
    fn test_get_its_payload_hash_receive_from_hub_error() {
        let token_id: [u8; 32] = Keccak256::digest(vec![]).into();

        let message_payload = its::HubMessage::ReceiveFromHub {
            source_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: its::Message::DeployInterchainToken(its::DeployInterchainToken {
                token_id: TokenId::new(token_id),
                name: "name".to_string().try_into().unwrap(),
                symbol: "symbol".to_string().try_into().unwrap(),
                decimals: 18,
                minter: None,
            }),
        }
        .abi_encode();

        let res = get_its_payload_and_hash_send_to_hub(message_payload);

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidPayload).to_string()
        );
    }

    #[test]
    fn test_get_its_payload_hash_interchain_transfer_send_to_hub() {
        let token_id: [u8; 32] = Keccak256::digest(vec![1, 2, 3]).into();

        let message_payload = its::HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: its::Message::InterchainTransfer(its::InterchainTransfer {
                token_id: token_id.into(),
                source_address: from_hex("051adb73632c0601f1e9ab5e9407d1da7011fea1149a"),
                destination_address: from_hex("10"),
                amount: 1u64.try_into().unwrap(),
                data: Some(from_hex("1234")),
            }),
        }
        .abi_encode();

        let inner_tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("type"),
                Value::UInt(MESSAGE_TYPE_INTERCHAIN_TRANSFER),
            ),
            (
                ClarityName::from("token-id"),
                Value::buff_from(token_id.to_vec()).unwrap(),
            ),
            (
                ClarityName::from("source-address"),
                PrincipalData::inner_consensus_deserialize(
                    &mut from_hex("051adb73632c0601f1e9ab5e9407d1da7011fea1149a").as_slice(),
                )
                .unwrap()
                .into(),
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
        let inner_expected_payload = Value::from(inner_tuple_data).serialize_to_vec();

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("type"),
                Value::UInt(MESSAGE_TYPE_SEND_TO_HUB),
            ),
            (
                ClarityName::from("destination-chain"),
                Value::string_ascii_from_bytes("chain".to_string().into_bytes()).unwrap(),
            ),
            (
                ClarityName::from("payload"),
                Value::buff_from(inner_expected_payload).unwrap(),
            ),
        ])
        .unwrap();
        let expected_payload = Value::from(tuple_data).serialize_to_vec();

        let (payload, payload_hash) =
            get_its_payload_and_hash_send_to_hub(message_payload).unwrap();

        assert_eq!(payload, expected_payload);
        assert_eq!(payload_hash, Keccak256::digest(expected_payload).as_slice());
    }

    #[test]
    fn test_get_its_payload_hash_deploy_interchain_token_payload_send_to_hub() {
        let token_id: [u8; 32] = Keccak256::digest(vec![]).into();

        let message_payload = its::HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: its::Message::DeployInterchainToken(its::DeployInterchainToken {
                token_id: token_id.into(),
                name: "name".to_string().try_into().unwrap(),
                symbol: "symbol".to_string().try_into().unwrap(),
                decimals: 18,
                minter: Some(from_hex("1234")),
            }),
        }
        .abi_encode();

        let inner_tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("type"),
                Value::UInt(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN),
            ),
            (
                ClarityName::from("token-id"),
                Value::buff_from(token_id.to_vec()).unwrap(),
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
                ClarityName::from("minter"),
                Value::buff_from(from_hex("1234").to_vec()).unwrap(),
            ),
        ])
        .unwrap();
        let inner_expected_payload = Value::from(inner_tuple_data).serialize_to_vec();

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("type"),
                Value::UInt(MESSAGE_TYPE_SEND_TO_HUB),
            ),
            (
                ClarityName::from("destination-chain"),
                Value::string_ascii_from_bytes("chain".to_string().into_bytes()).unwrap(),
            ),
            (
                ClarityName::from("payload"),
                Value::buff_from(inner_expected_payload).unwrap(),
            ),
        ])
        .unwrap();
        let expected_payload = Value::from(tuple_data).serialize_to_vec();

        let (payload, payload_hash) =
            get_its_payload_and_hash_send_to_hub(message_payload).unwrap();

        assert_eq!(payload, expected_payload);
        assert_eq!(payload_hash, Keccak256::digest(expected_payload).as_slice());
    }

    fn from_hex(hex: &str) -> nonempty::HexBinary {
        HexBinary::from_hex(hex).unwrap().try_into().unwrap()
    }
}
