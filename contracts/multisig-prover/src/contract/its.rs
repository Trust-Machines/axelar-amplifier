use crate::error::ContractError;
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
    if amount > Uint256::try_from(Uint128::MAX).map_err(|_| ContractError::InvalidMessage)? {
        return Err(ContractError::InvalidAmount);
    }

    let amount: Uint128 = cosmwasm_std::Uint256::from(amount)
        .try_into()
        .map_err(|_| ContractError::InvalidMessage)?;

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
            Value::string_ascii_from_bytes(source_address.to_vec())
                .map_err(|_| ContractError::InvalidMessage)?,
        ),
        (
            ClarityName::from("destination-address"),
            Value::string_ascii_from_bytes(destination_address.to_vec())
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
