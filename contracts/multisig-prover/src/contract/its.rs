use axelar_wasm_std::nonempty;
use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::{HexBinary, Uint128};
use interchain_token_service as its;
use interchain_token_service::{TokenId, TokenManagerType};
use router_api::ChainNameRaw;
use sha3::{Digest, Keccak256};
use stacks_clarity::common::codec::StacksMessageCodec;
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::{TupleData, Value};

use crate::error::ContractError;

const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER: u128 = 2;

fn token_manager_type_to_u128(token_manager_type: TokenManagerType) -> u128 {
    match token_manager_type {
        TokenManagerType::NativeInterchainToken => 0,
        TokenManagerType::MintBurnFrom => 1,
        TokenManagerType::LockUnlock => 2,
        TokenManagerType::LockUnlockFee => 3,
        TokenManagerType::MintBurn => 4,
        TokenManagerType::Gateway => 5,
    }
}

// TODO: Add events here that contain the payload as well
pub fn get_its_payload_and_hash(
    message_payload: HexBinary,
) -> Result<(Vec<u8>, [u8; 32]), ContractError> {
    let its_hub_message = its::HubMessage::abi_decode(message_payload.as_slice()).unwrap();

    let payload = match its_hub_message {
        its::HubMessage::SendToHub { .. } => Err(ContractError::InvalidPayload),
        its::HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => match message {
            its::Message::InterchainTransfer(its::InterchainTransfer {
                token_id,
                source_address,
                destination_address,
                amount,
                data,
            }) => get_its_interchain_transfer_payload(
                source_chain,
                token_id,
                source_address.into(),
                destination_address.into(),
                amount,
                data,
            ),
            its::Message::DeployInterchainToken(its::DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals,
                minter,
            }) => get_its_deploy_interchain_token_payload(
                source_chain,
                token_id,
                name.into(),
                symbol.into(),
                decimals,
                minter,
            ),
            its::Message::DeployTokenManager(its::DeployTokenManager {
                token_id,
                token_manager_type,
                params,
            }) => get_its_deploy_token_manager_payload(
                source_chain,
                token_id,
                token_manager_type,
                params.into(),
            ),
        },
    }?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();

    Ok((payload, payload_hash))
}

fn get_its_interchain_transfer_payload(
    source_chain: ChainNameRaw,
    token_id: TokenId,
    source_address: HexBinary,
    destination_address: HexBinary,
    amount: Uint256,
    data: Option<nonempty::HexBinary>,
) -> Result<Vec<u8>, ContractError> {
    let token_id: [u8; 32] = token_id.into();

    // TODO: Should we handle this in another way?
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
            ClarityName::from("source-chain"),
            Value::string_ascii_from_bytes(source_chain.to_string().into_bytes())
                .map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("token-id"),
            Value::buff_from(token_id.to_vec()).map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("source-address"),
            Value::buff_from(source_address.to_vec()).map_err(|_| ContractError::InvalidMessage)?,
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

fn get_its_deploy_interchain_token_payload(
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
            ClarityName::from("type"),
            Value::UInt(MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN),
        ),
        (
            ClarityName::from("source-chain"),
            Value::string_ascii_from_bytes(source_chain.to_string().into_bytes())
                .map_err(|_| ContractError::InvalidMessage)?,
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
            ClarityName::from("minter-bytes"),
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

fn get_its_deploy_token_manager_payload(
    source_chain: ChainNameRaw,
    token_id: TokenId,
    token_manager_type: TokenManagerType,
    params: HexBinary,
) -> Result<Vec<u8>, ContractError> {
    let token_id: [u8; 32] = token_id.into();

    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::from("source-chain"),
            Value::string_ascii_from_bytes(source_chain.to_string().into_bytes())
                .map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("type"),
            Value::UInt(MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER),
        ),
        (
            ClarityName::from("token-id"),
            Value::buff_from(token_id.to_vec()).map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("token-manager-type"),
            Value::UInt(token_manager_type_to_u128(token_manager_type)),
        ),
        (
            ClarityName::from("params"),
            Value::buff_from(params.to_vec()).map_err(|_| ContractError::InvalidMessage)?,
        ),
    ])?;

    Ok(Value::from(tuple_data).serialize_to_vec())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::HexBinary;
    use interchain_token_service as its;
    use interchain_token_service::{TokenId, TokenManagerType};
    use router_api::ChainNameRaw;
    use sha3::{Digest, Keccak256};

    use crate::contract::its::get_its_payload_and_hash;
    use crate::error::ContractError;

    #[test]
    fn test_get_its_payload_hash_send_to_hub_error() {
        let token_id: [u8; 32] = Keccak256::digest(vec![]).into();

        let message_payload = its::HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: its::Message::DeployTokenManager(its::DeployTokenManager {
                token_id: TokenId::new(token_id),
                token_manager_type: TokenManagerType::NativeInterchainToken,
                params: HexBinary::from_hex("00").unwrap().try_into().unwrap(),
            }),
        }
        .abi_encode();

        let res = get_its_payload_and_hash(message_payload);

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidPayload).to_string()
        );
    }

    #[test]
    fn test_get_its_payload_hash_interchain_transfer() {
        let message_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a6d756c7469766572737800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000002c2a94e0c1200b3432349f28ac617a7c9242bbc9d2c9cb46d7fe9ac55510471000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002077588c18055a483754b68c2378d5e7a6fa4e1d4e0302dadf5db12e7a50a1b5bf0000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let (_, payload_hash) = get_its_payload_and_hash(message_payload).unwrap();

        assert_eq!(
            payload_hash,
            HexBinary::from_hex("9399aacddb14646f239b4dd906bd50c0246669863257823ed80de5a36f95d070")
                .unwrap()
        );
    }

    #[test]
    fn test_get_its_payload_hash_deploy_interchain_token_payload() {
        let message_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000e6176616c616e6368652d66756a6900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000c031ce12590c2efefb2606c231b1b47bc10480448ae705c8f0d54edf616ec2f200000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000016051a72cdd749200c730ca316a0d6157ceff9a50be50c000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let (_, payload_hash) = get_its_payload_and_hash(message_payload).unwrap();

        assert_eq!(
            payload_hash,
            HexBinary::from_hex("92e933c55cf55e79eb5207570671e0afc9c49b1e4e269985e51013f67be7b50e")
                .unwrap()
        );
    }

    #[test]
    fn test_get_its_payload_hash_deploy_token_manager_payload() {
        let message_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000e6176616c616e6368652d66756a6900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000002dfbbd97a4e0c3ec2338d800be851dca6d08d4779398d4070d5cb18d2ebfe62d70000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000420c00000002086f70657261746f72090d746f6b656e2d61646472657373061a555db886b8dda288a0a7695027c4d2656dacbc760e73616d706c652d7369702d303130000000000000000000000000000000000000000000000000000000000000").unwrap();

        let (_, payload_hash) = get_its_payload_and_hash(message_payload).unwrap();

        assert_eq!(
            payload_hash,
            HexBinary::from_hex("84ee196a98d6bb6201f9518e8023c813bb214941e1bb83e8fb97783aef0adc88")
                .unwrap()
        );
    }
}
