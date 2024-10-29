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
                source_chain,
                token_id,
                source_address.into(),
                destination_address.into(),
                amount,
                data,
            ),
            its::Message::DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals,
                minter,
            } => get_its_deploy_interchain_token_payload(
                source_chain,
                token_id,
                name.into(),
                symbol.into(),
                decimals,
                minter,
            ),
            its::Message::DeployTokenManager {
                token_id,
                token_manager_type,
                params,
            } => get_its_deploy_token_manager_payload(
                source_chain,
                token_id,
                token_manager_type,
                params.into(),
            ),
        },
    }?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload).into();

    Ok(payload_hash)
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
            ClarityName::from("type"),
            Value::UInt(MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER),
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
            ClarityName::from("token-manager-type"),
            Value::UInt(token_manager_type_to_u128(token_manager_type)),
        ),
        (
            ClarityName::from("minter-bytes"),
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

    use crate::contract::its::get_its_payload_hash;
    use crate::error::ContractError;

    #[test]
    fn test_get_its_payload_hash_send_to_hub_error() {
        let token_id: [u8; 32] = Keccak256::digest(vec![]).into();

        let message_payload = its::HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: its::Message::DeployTokenManager {
                token_id: TokenId::new(token_id),
                token_manager_type: TokenManagerType::NativeInterchainToken,
                params: HexBinary::from_hex("00").unwrap().try_into().unwrap(),
            },
        }
        .abi_encode();

        let res = get_its_payload_hash(message_payload);

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

        let payload_hash = get_its_payload_hash(message_payload).unwrap();

        assert_eq!(
            payload_hash,
            HexBinary::from_hex("9399aacddb14646f239b4dd906bd50c0246669863257823ed80de5a36f95d070")
                .unwrap()
        );
    }

    #[test]
    fn test_get_its_payload_hash_deploy_interchain_token_payload() {
        let message_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000106f7074696d69736d2d7365706f6c6961000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000138aeb4100114b3b4a49492d038d21344fee0d3ec84b8b5f3e0ebbac760590fa300000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000f436861696e4c696e6b20546f6b656e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044c494e4b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let payload_hash = get_its_payload_hash(message_payload).unwrap();

        assert_eq!(
            payload_hash,
            HexBinary::from_hex("e867b2dbb519a33d18a375e990d5672b0cd8a401da83e312479b00aa32d1ba90")
                .unwrap()
        );
    }

    #[test]
    fn test_get_its_payload_hash_deploy_token_manager_payload() {
        let message_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000008457468657265756d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000201b3d64c8c6530a3aad5909ae7e0985d4438ce8eafd90e51ce48fbc809bced39000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000032010000000000000000050000000000000000040000000000000000000000000000010000000c5745474c442d3132333435360000000000000000000000000000").unwrap();

        let payload_hash = get_its_payload_hash(message_payload).unwrap();

        assert_eq!(
            payload_hash,
            HexBinary::from_hex("35ab7621ae4ef05d18d7196bbfb8cba99a186f9a7004bad5ed57e3d73dd84bea")
                .unwrap()
        );
    }
}
