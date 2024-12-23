use axelar_wasm_std::voting::Vote;
use clarity::vm::types::{
    BufferLength, PrincipalData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
    Value,
};
use clarity::vm::ClarityName;
use router_api::ChainName;

use crate::handlers::stacks_verify_msg::Message;
use crate::handlers::stacks_verify_verifier_set::VerifierSetConfirmation;
use crate::stacks::error::Error;
use crate::stacks::http_client::{Client, Transaction, TransactionEvents};
use crate::stacks::its_verifier::{get_its_hub_payload_hash, its_verify_contract_code};
use crate::stacks::WeightedSigners;
use crate::types::Hash;

pub const PRINT_TOPIC: &str = "print";

pub const CONTRACT_CALL_TYPE: &str = "contract-call";
const SIGNERS_ROTATED_TYPE: &str = "signers-rotated";

impl Message {
    pub fn eq_event(
        &self,
        event: &TransactionEvents,
        new_payload_hash: Option<Hash>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

        if contract_log.topic != PRINT_TOPIC {
            return Ok(false);
        }

        let tuple_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from("type"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(13u32)?,
                ))),
            ),
            (ClarityName::from("sender"), TypeSignature::PrincipalType),
            (
                ClarityName::from("destination-chain"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(20u32)?,
                ))),
            ),
            (
                ClarityName::from("destination-contract-address"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(128u32)?,
                ))),
            ),
            (
                ClarityName::from("payload-hash"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    32u32,
                )?)),
            ),
        ])?;

        let hex = contract_log
            .value
            .hex
            .strip_prefix("0x")
            .ok_or(Error::PropertyEmpty)?;

        let value =
            Value::try_deserialize_hex(hex, &TypeSignature::TupleType(tuple_type_signature), true)?;

        if let Value::Tuple(data) = value {
            if !data.get("type")?.eq(&Value::string_ascii_from_bytes(
                CONTRACT_CALL_TYPE.as_bytes().to_vec(),
            )?) {
                return Ok(false);
            }

            if !data.get("sender")?.eq(&Value::from(PrincipalData::parse(
                self.source_address.as_str(),
            )?)) {
                return Ok(false);
            }

            if !data
                .get("destination-chain")?
                .eq(&Value::string_ascii_from_bytes(
                    self.destination_chain.as_ref().as_bytes().to_vec(),
                )?)
            {
                return Ok(false);
            }

            if !data
                .get("destination-contract-address")?
                .eq(&Value::string_ascii_from_bytes(
                    self.destination_address.as_bytes().to_vec(),
                )?)
            {
                return Ok(false);
            }

            if let Some(new_payload_hash) = new_payload_hash {
                if new_payload_hash != self.payload_hash {
                    return Ok(false);
                }
            } else if !data
                .get("payload-hash")?
                .eq(&Value::buff_from(self.payload_hash.as_bytes().to_vec())?)
            {
                return Ok(false);
            }

            return Ok(true);
        }

        Ok(false)
    }
}

impl VerifierSetConfirmation {
    fn eq_event(&self, event: &TransactionEvents) -> Result<bool, Box<dyn std::error::Error>> {
        let contract_log = event.contract_log.as_ref().ok_or(Error::PropertyEmpty)?;

        if contract_log.topic != PRINT_TOPIC {
            return Ok(false);
        }

        let tuple_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from("type"),
                TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                    BufferLength::try_from(15u32)?,
                ))),
            ),
            (
                ClarityName::from("signers-hash"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    32u32,
                )?)),
            ),
        ])?;

        let hex = contract_log
            .value
            .hex
            .strip_prefix("0x")
            .ok_or(Error::PropertyEmpty)?;

        let value =
            Value::try_deserialize_hex(hex, &TypeSignature::TupleType(tuple_type_signature), true)?;

        if let Value::Tuple(data) = value {
            if !data.get("type")?.eq(&Value::string_ascii_from_bytes(
                SIGNERS_ROTATED_TYPE.as_bytes().to_vec(),
            )?) {
                return Ok(false);
            }

            let weighted_signers = WeightedSigners::try_from(&self.verifier_set)?;

            let hash = weighted_signers.hash();

            if !data
                .get("signers-hash")?
                .eq(&Value::buff_from(hash?.to_vec())?)
            {
                return Ok(false);
            }

            return Ok(true);
        }

        Ok(false)
    }
}

fn find_event<'a>(
    transaction: &'a Transaction,
    gateway_address: &String,
    log_index: u64,
) -> Option<&'a TransactionEvents> {
    let event = transaction
        .events
        .iter()
        .find(|el| el.event_index == log_index)?;

    if !event.contract_log.as_ref()?.contract_id.eq(gateway_address) {
        return None;
    }

    Some(event)
}

pub async fn verify_message(
    source_chain: &ChainName,
    gateway_address: &String,
    its_address: &String,
    transaction: &Transaction,
    message: &Message,
    http_client: &Client,
    reference_native_interchain_token_code: &String,
    reference_token_manager_code: &String,
) -> Vote {
    if message.message_id.tx_hash != transaction.tx_id.as_bytes() {
        return Vote::NotFound;
    }

    match find_event(transaction, gateway_address, message.message_id.event_index) {
        Some(event) => {
            // In case message is not from ITS
            if &message.source_address != its_address {
                if message.eq_event(event, None).unwrap_or(false) {
                    return Vote::SucceededOnChain;
                }

                return Vote::NotFound;
            }

            // In case messages is from Stacks -> Stacks and from ITS -> ITS, use custom logic
            // for confirming contract deployments
            if &message.destination_chain == source_chain
                && &message.destination_address == its_address
            {
                if message.eq_event(event, None).unwrap_or(false)
                    && its_verify_contract_code(
                        event,
                        http_client,
                        reference_native_interchain_token_code,
                        reference_token_manager_code,
                    )
                    .await
                    .unwrap_or(false)
                {
                    return Vote::SucceededOnChain;
                }

                return Vote::NotFound;
            }

            // In other case, abi encode payload coming from Stacks ITS
            if let Ok(payload_hash) = get_its_hub_payload_hash(event) {
                if message.eq_event(event, Some(payload_hash)).unwrap_or(false) {
                    return Vote::SucceededOnChain;
                }
            }

            Vote::NotFound
        }
        _ => Vote::NotFound,
    }
}

pub fn verify_verifier_set(
    gateway_address: &String,
    transaction: &Transaction,
    verifier_set: VerifierSetConfirmation,
) -> Vote {
    if verifier_set.message_id.tx_hash != transaction.tx_id.as_bytes() {
        return Vote::NotFound;
    }

    match find_event(
        transaction,
        gateway_address,
        verifier_set.message_id.event_index,
    ) {
        Some(event) if verifier_set.eq_event(event).unwrap_or(false) => Vote::SucceededOnChain,
        _ => Vote::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use clarity::vm::types::TupleData;
    use clarity::vm::{ClarityName, Value};
    use cosmwasm_std::{HexBinary, Uint128};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use router_api::ChainName;
    use tokio::test as async_test;

    use crate::handlers::stacks_verify_msg::Message;
    use crate::handlers::stacks_verify_verifier_set::VerifierSetConfirmation;
    use crate::stacks::http_client::{
        Client, ContractLog, ContractLogValue, Transaction, TransactionEvents,
    };
    use crate::stacks::verifier::{verify_message, verify_verifier_set, SIGNERS_ROTATED_TYPE};
    use crate::types::Hash;

    // test verify message
    #[async_test]
    async fn should_not_verify_tx_id_does_not_match() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.tx_hash = Hash::random().into();

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
    async fn should_not_verify_no_log_for_event_index() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.event_index = 2;

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
    async fn should_not_verify_event_index_does_not_match() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.message_id.event_index = 0;

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
    async fn should_not_verify_not_gateway() {
        let (source_chain, gateway_address, its_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.contract_id = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_string();

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
    async fn should_not_verify_invalid_topic() {
        let (source_chain, gateway_address, its_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.topic = "other".to_string();

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
    async fn should_not_verify_invalid_type() {
        let (source_chain, gateway_address, its_address, mut tx, msg) = get_matching_msg_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        // Remove 'call' as hex from `contract-call` data
        contract_call.value.hex = contract_call
            .value
            .hex
            .strip_suffix("63616c6c")
            .unwrap()
            .to_string();

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
    async fn should_not_verify_invalid_sender() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.source_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway".to_string();

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
    async fn should_not_verify_invalid_destination_chain() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_chain = "other".parse().unwrap();

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
    async fn should_not_verify_invalid_destination_address() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

        msg.destination_address = "other".parse().unwrap();

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
    async fn should_not_verify_invalid_payload_hash() {
        let (source_chain, gateway_address, its_address, tx, mut msg) = get_matching_msg_and_tx();

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
    async fn should_verify_msg() {
        let (source_chain, gateway_address, its_address, tx, msg) = get_matching_msg_and_tx();

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

    // test verify worker set
    #[test]
    fn should_not_verify_verifier_set_if_tx_id_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.message_id.tx_hash = Hash::random().into();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_no_log_for_event_index() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.message_id.event_index = 2;

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_event_index_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.message_id.event_index = 0;

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_if_not_from_gateway() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.contract_id = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_invalid_topic() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let contract_call = transaction_events.contract_log.as_mut().unwrap();

        contract_call.topic = "other".to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_verifier_set_invalid_type() {
        let (gateway_address, mut tx, verifier_set) = get_matching_verifier_set_and_tx();

        let transaction_events = tx.events.get_mut(1).unwrap();
        let signers_rotated = transaction_events.contract_log.as_mut().unwrap();

        // Remove 'rotated' as hex from `signers-rotated` data
        signers_rotated.value.hex = signers_rotated
            .value
            .hex
            .strip_suffix("726f7461746564")
            .unwrap()
            .to_string();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_not_verify_worker_set_if_verifier_set_does_not_match() {
        let (gateway_address, tx, mut verifier_set) = get_matching_verifier_set_and_tx();

        verifier_set.verifier_set.threshold = Uint128::from(10u128);
        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::NotFound
        );
    }

    #[test]
    fn should_verify_verifier_set() {
        let (gateway_address, tx, verifier_set) = get_matching_verifier_set_and_tx();

        assert_eq!(
            verify_verifier_set(&gateway_address, &tx, verifier_set),
            Vote::SucceededOnChain
        );
    }

    fn get_matching_msg_and_tx() -> (ChainName, String, String, Transaction, Message) {
        let source_chain = "stacks";
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let its_address = "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B.its";

        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let msg = Message {
            message_id: message_id.clone(),
            source_address: "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG".to_string(),
            destination_chain: "Destination".parse().unwrap(),
            destination_address: "0x123abc".to_string(),
            payload_hash: "0x9ed02951dbf029855b46b102cc960362732569e83d00a49a7575d7aed229890e"
                .parse()
                .unwrap(),
        };

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: None,
        };

        let event = TransactionEvents {
            event_index: 1,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: "0x0c000000061164657374696e6174696f6e2d636861696e0d0000000b64657374696e6174696f6e1c64657374696e6174696f6e2d636f6e74726163742d616464726573730d000000083078313233616263077061796c6f61640200000029535431534a3344544535444e375835345944483544363452334243423641324147325a5138595044350c7061796c6f61642d6861736802000000209ed02951dbf029855b46b102cc960362732569e83d00a49a7575d7aed229890e0673656e646572051a99e2ec69ac5b6e67b4e26edd0e2c1c1a6b9bbd2304747970650d0000000d636f6e74726163742d63616c6c".to_string(),
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

    fn get_matching_verifier_set_and_tx() -> (String, Transaction, VerifierSetConfirmation) {
        let gateway_address = "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway";
        let message_id = HexTxHashAndEventIndex::new(Hash::random(), 1u64);

        let mut verifier_set_confirmation = VerifierSetConfirmation {
            message_id: message_id.clone(),
            verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
        };
        verifier_set_confirmation.verifier_set.created_at = 5;

        let wrong_event = TransactionEvents {
            event_index: 0,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: None,
        };

        let signers_hash =
            HexBinary::from_hex("6925aafa48d1c99f0fd9bdd98b00fc319462a3ecbf2bbb8379c975a26a0c0c46")
                .unwrap();

        let value = Value::from(
            TupleData::from_data(vec![
                (
                    ClarityName::from("signers-hash"),
                    Value::buff_from(signers_hash.to_vec()).unwrap(),
                ),
                (
                    ClarityName::from("type"),
                    Value::string_ascii_from_bytes(SIGNERS_ROTATED_TYPE.as_bytes().to_vec())
                        .unwrap(),
                ),
            ])
            .unwrap(),
        );

        let event = TransactionEvents {
            event_index: 1,
            tx_id: message_id.tx_hash_as_hex().to_string(),
            contract_log: Some(ContractLog {
                contract_id: gateway_address.to_string(),
                topic: "print".to_string(),
                value: ContractLogValue {
                    hex: format!("0x{}", value.serialize_to_hex().unwrap()),
                },
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
            gateway_address.to_string(),
            transaction,
            verifier_set_confirmation,
        )
    }
}
