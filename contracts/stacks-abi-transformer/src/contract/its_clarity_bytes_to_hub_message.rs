use crate::contract::its_receive_from_hub::{
    CLARITY_NAME_AMOUNT, CLARITY_NAME_DATA, CLARITY_NAME_DECIMALS,
    CLARITY_NAME_DESTINATION_ADDRESS, CLARITY_NAME_NAME, CLARITY_NAME_SOURCE_ADDRESS,
    CLARITY_NAME_SYMBOL, CLARITY_NAME_TOKEN_ID, CLARITY_NAME_TYPE,
};
use crate::contract::its_send_to_hub::{
    CLARITY_NAME_DESTINATION_CHAIN, CLARITY_NAME_MINTER, CLARITY_NAME_PAYLOAD,
};
use crate::error::ContractError;
use interchain_token_service::{DeployInterchainToken, HubMessage, InterchainTransfer, Message};
use sha3::{Digest, Keccak256};
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::{
    BufferLength, SequenceSubtype, StringSubtype, TupleData, TupleTypeSignature, TypeSignature,
    Value,
};

const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;

const CLARITY_SIZE_DESTINATION_CHAIN: u32 = 19;
const CLARITY_SIZE_PAYLOAD: u32 = 63_000;
const CLARITY_SIZE_TOKEN_ID: u32 = 32;
const CLARITY_SIZE_DESTINATION_ADDRESS: u32 = 128;
const CLARITY_SIZE_DATA: u32 = 62_000;
const CLARITY_SIZE_NAME: u32 = 32;
const CLARITY_SIZE_SYMBOL: u32 = 32;
const CLARITY_SIZE_MINTER: u32 = 128;

pub fn get_its_hub_message(payload: Vec<u8>) -> Result<HubMessage, Box<dyn std::error::Error>> {
    let tuple_data = get_its_hub_call_params(payload)?;

    // All messages should go through ITS hub
    if !tuple_data
        .get(CLARITY_NAME_TYPE)?
        .eq(&Value::UInt(MESSAGE_TYPE_SEND_TO_HUB))
    {
        return Err(ContractError::InvalidPayload.into());
    }

    let destination_chain = tuple_data
        .get(CLARITY_NAME_DESTINATION_CHAIN)?
        .clone()
        .expect_ascii()?;
    let payload = tuple_data
        .get_owned(CLARITY_NAME_PAYLOAD)?
        .expect_buff(CLARITY_SIZE_PAYLOAD.into())?;

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
        MESSAGE_TYPE_INTERCHAIN_TRANSFER => get_its_interchain_transfer_message(payload),
        MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN => get_its_deploy_interchain_token_payload(payload),
        _ => {
            return Err(ContractError::InvalidPayload.into());
        }
    }?;

    Ok(HubMessage::SendToHub {
        message,
        destination_chain,
    })
}

fn get_its_hub_call_params(payload: Vec<u8>) -> Result<TupleData, Box<dyn std::error::Error>> {
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

fn get_its_interchain_transfer_message(
    payload: Vec<u8>,
) -> Result<Message, Box<dyn std::error::Error>> {
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
        .expect_buff(CLARITY_SIZE_DATA)?;

    Ok(Message::InterchainTransfer(InterchainTransfer {
        token_id: original_value
            .data_map
            .remove(CLARITY_NAME_TOKEN_ID)
            .ok_or(ContractError::InvalidPayload)?
            .expect_buff(CLARITY_SIZE_TOKEN_ID)?,
        source_address: original_value
            .data_map
            .remove(CLARITY_NAME_SOURCE_ADDRESS)
            .ok_or(ContractError::InvalidPayload)?
            .expect_principal()?
            .serialize_to_vec()
            .into(),
        destination_address: original_value
            .data_map
            .remove(CLARITY_NAME_DESTINATION_ADDRESS)
            .ok_or(ContractError::InvalidPayload)?
            .expect_buff(CLARITY_SIZE_DESTINATION_ADDRESS)?
            .into(),
        amount: original_value
            .data_map
            .remove(CLARITY_NAME_AMOUNT)
            .ok_or(ContractError::InvalidPayload)?
            .expect_u128()?
            .into(),
        data: if data.is_empty() {
            None
        } else {
            Some(data.into())
        },
    }))
}

fn get_its_deploy_interchain_token_payload(
    payload: Vec<u8>,
) -> Result<Message, Box<dyn std::error::Error>> {
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
        .expect_buff(CLARITY_SIZE_MINTER)?;

    Ok(Message::DeployInterchainToken(DeployInterchainToken {
        token_id: original_value
            .data_map
            .remove(CLARITY_NAME_TOKEN_ID)
            .ok_or(ContractError::InvalidPayload)?
            .expect_buff(CLARITY_SIZE_TOKEN_ID)?,
        name: original_value
            .data_map
            .remove(CLARITY_NAME_NAME)
            .ok_or(ContractError::InvalidPayload)?
            .expect_ascii()?,
        symbol: original_value
            .data_map
            .remove(CLARITY_NAME_SYMBOL)
            .ok_or(ContractError::InvalidPayload)?
            .expect_ascii()?,
        decimals: original_value
            .data_map
            .remove(CLARITY_NAME_DECIMALS)
            .ok_or(ContractError::InvalidPayload)?
            .expect_u128()?
            .into(),
        minter: if minter.is_empty() {
            None
        } else {
            Some(minter.into())
        },
    }))
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use router_api::ChainName;
    use tokio::test as async_test;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::stacks::http_client::{
        Client, ContractInfo, ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::verify_message;
    use crate::types::Hash;

    // test verify message its hub
    #[async_test]
    async fn should_not_verify_its_hub_interchain_transfer_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_hub_interchain_transfer_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::NotFound
        );
    }

    #[async_test]
    async fn should_verify_msg_its_hub_interchain_transfer() {
        let (source_chain, gateway_address, its_address, tx, msg) =
            get_matching_its_hub_interchain_transfer_msg_and_tx();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::SucceededOnChain
        );
    }

    #[async_test]
    async fn should_not_verify_its_hub_deploy_interchain_token_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) =
            get_matching_its_hub_deploy_interchain_token_msg_and_tx();

        msg.payload_hash = "0xaa38573718f5cd6d7e5a90adcdebd28b097f99574ad6febffea9a40adb17f4aa"
            .parse()
            .unwrap();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::NotFound
        );
    }

    #[async_test]
    async fn should_verify_msg_its_hub_deploy_interchain_token() {
        let (source_chain, gateway_address, its_address, tx, msg) =
            get_matching_its_hub_deploy_interchain_token_msg_and_tx();

        assert_eq!(
            verify_message(
                &source_chain,
                &gateway_address,
                &its_address,
                &tx,
                &msg,
                &Client::faux(),
                &"native_interchain_token_code".to_string(),
                &"token_manager_code".to_string()
            )
            .await,
            Vote::SucceededOnChain
        );
    }

    fn get_matching_its_hub_interchain_transfer_msg_and_tx(
    ) -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.interchain-token-service";

        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let msg = Message {
            message_id: message_id.clone(),
            source_address: its_address.to_string(),
            destination_chain: "axelar".parse().unwrap(),
            destination_address: "cosmwasm".to_string(),
            payload_hash: "0x99cdb5935274c6a59d3ce9cd6c47b58acc0ef461d6b3cab7162c2842c182b94a"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: None,
        };

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
        let event = TransactionEvents {
            event_index: 1,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d000000066178656c61721c64657374696e6174696f6e2d636f6e74726163742d616464726573730d00000008636f736d7761736d077061796c6f616402000000f20c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f616402000000ab0c0000000606616d6f756e7401000000000000000000000000000186a004646174610200000001001364657374696e6174696f6e2d616464726573730200000001000e736f757263652d61646472657373051a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce08746f6b656e2d69640200000020753306c46380848b5189cd9db90107b15d25decccd93dcb175c0098958f18b6f04747970650100000000000000000000000000000000047479706501000000000000000000000000000000030c7061796c6f61642d6861736802000000203dc0763c57c9c7912d2c072718e6ef2ae2d595ce2da31d8b248205d67ad7c3ab0673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id: message_id.tx_hash.into(),
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }

    fn get_matching_its_hub_deploy_interchain_token_msg_and_tx(
    ) -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.interchain-token-service";

        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let msg = Message {
            message_id: message_id.clone(),
            source_address: its_address.to_string(),
            destination_chain: "axelar".parse().unwrap(),
            destination_address: "0x00".to_string(),
            payload_hash: "0x63b56229fc520914aa0f690e136517fceae159a49082f5f18f866a9ba5e3ce15"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: None,
        };

        /*
            payload is:
            {
                type: u3,
                destination-chain: "ethereum",
                payload: {
                    type: u1,
                    token-id: 0x42fad3435446674f88b47510fe7d2d144c8867c405d4933007705db85f37ded5,
                    name: "sample",
                    symbol: "sample",
                    decimals: u6,
                    minter: 0x00
                }
            }
        */
        let event = TransactionEvents {
            event_index: 1,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d000000066178656c61721c64657374696e6174696f6e2d636f6e74726163742d616464726573730d0000000430783030077061796c6f616402000000d90c000000031164657374696e6174696f6e2d636861696e0d00000008657468657265756d077061796c6f616402000000920c0000000608646563696d616c730100000000000000000000000000000006066d696e746572020000000100046e616d650d0000000673616d706c650673796d626f6c0d0000000673616d706c6508746f6b656e2d69640200000020563dc3698c0f2c5adf375ff350bb54ecf86d2be109e3aacaf38111cdf171df7804747970650100000000000000000000000000000001047479706501000000000000000000000000000000030c7061796c6f61642d6861736802000000207bcf62a3e8aed07d1eb704a1c4b142de9c1f429d2a6cf835c3347763ae8e05ab0673656e646572061a6d78de7b0625dfbfc16c3a8a5735f6dc3dc3f2ce18696e746572636861696e2d746f6b656e2d7365727669636504747970650d0000000d636f6e74726163742d63616c6c".to_string(),
                }
            }),
        };

        let transaction = Transaction {
            tx_id: message_id.tx_hash.into(),
            nonce: 1,
            sender_address: "whatever".to_string(),
            tx_status: "success".to_string(),
            events: vec![wrong_event, event],
        };

        (
            source_chain.parse().unwrap(),
            gateway_address.to_string(),
            its_address.to_string(),
            transaction,
            msg,
        )
    }
}
