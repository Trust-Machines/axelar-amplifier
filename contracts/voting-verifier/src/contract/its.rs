use axelar_wasm_std::nonempty;
use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::{HexBinary, Uint128};
use interchain_token_service as its;
use interchain_token_service::TokenId;
use sha3::{Digest, Keccak256};
use stacks_clarity::common::codec::StacksMessageCodec;
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::{PrincipalData, TupleData, Value};

use crate::error::ContractError;

const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;

pub fn get_its_payload_and_hash(
    message_payload: HexBinary,
) -> Result<(Vec<u8>, [u8; 32]), ContractError> {
    let its_hub_message = its::HubMessage::abi_decode(message_payload.as_slice()).unwrap();

    let payload = match its_hub_message {
        its::HubMessage::ReceiveFromHub { .. } => Err(ContractError::InvalidPayload),
        its::HubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let inner_payload = match message {
                its::Message::InterchainTransfer(its::InterchainTransfer {
                    token_id,
                    source_address,
                    destination_address,
                    amount,
                    data,
                }) => get_its_interchain_transfer_payload(
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
                    token_id,
                    name.into(),
                    symbol.into(),
                    decimals,
                    minter,
                ),
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
    }?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();

    Ok((payload, payload_hash))
}

fn get_its_interchain_transfer_payload(
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

fn get_its_deploy_interchain_token_payload(
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

    use cosmwasm_std::HexBinary;
    use interchain_token_service as its;
    use interchain_token_service::TokenId;
    use router_api::ChainNameRaw;
    use sha3::{Digest, Keccak256};

    use crate::contract::its::get_its_payload_and_hash;
    use crate::error::ContractError;

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
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000e6176616c616e6368652d66756a6900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000b60524f7374deae5624711575011ae6fdfbbf4073fec106f4ebe773da9c6104800000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000b71b0000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000016051ac4a739e6e70be056920e5195e7ed579182c862aa000000000000000000000000000000000000000000000000000000000000000000000000000000000014ab905ea4dc0b571c127e8b38f00cecd97f0855590000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let (_, payload_hash) = get_its_payload_and_hash(message_payload).unwrap();

        // Payload hash is taken from correct Stacks payload
        assert_eq!(
            payload_hash,
            HexBinary::from_hex("ed9305978fd027c60310c48f29710503a2c9878a57deda4c99b87e504475595e")
                .unwrap()
        );
    }

    #[test]
    fn test_get_its_payload_hash_deploy_interchain_token_payload() {
        let message_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000e6176616c616e6368652d66756a6900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000001fb54f5b1504830e66f2ca3db8c1fda59ff5c7324866525daeff56820c93730e600000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000673616d706c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004534d504c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let (_, payload_hash) = get_its_payload_and_hash(message_payload).unwrap();

        // Payload hash is taken from correct Stacks payload
        assert_eq!(
            payload_hash,
            HexBinary::from_hex("e4bba8e351bdceb10b03e965d4f710eb8a83e406ddbc78c9ebf76fd82939950d")
                .unwrap()
        );
    }
}
