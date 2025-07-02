pub mod execute_data;

use axelar_wasm_std::hash::Hash;
use cosmwasm_std::Uint256;
use error_stack::ResultExt;
use multisig::key::PublicKey;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;
use sha3::{Digest, Keccak256};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::StacksEpochId;
use clarity::vm::analysis::errors::CheckErrors;
use clarity::vm::errors::Error as ClarityError;
use clarity::vm::representations::ClarityName;
use clarity::vm::types::signatures::{
    BufferLength, ListTypeData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
};
use clarity::vm::types::{PrincipalData, TupleData, Value};

use crate::error::ContractError;
use crate::Payload;

const TYPE_APPROVE_MESSAGES: &str = "approve-messages";
const TYPE_ROTATE_SIGNERS: &str = "rotate-signers";

const STACKS_SIGNER_MESSAGE: &str = "Stacks Signed Message";

pub const CLARITY_NAME_SIGNERS: &str = "signers";
pub const CLARITY_NAME_SIGNATURES: &str = "signatures";
pub const CLARITY_SIZE_SIGNATURES: u32 = 65;
pub const CLARITY_MAX_LEN_SIGNATURES: u32 = 100;
pub const CLARITY_NAME_FUNCTION: &str = "function";
pub const CLARITY_NAME_DATA: &str = "data";
pub const CLARITY_NAME_PROOF: &str = "proof";

const CLARITY_NAME_SOURCE_CHAIN: &str = "source-chain";
const CLARITY_SIZE_SOURCE_CHAIN: u32 = 20;
const CLARITY_NAME_MESSAGE_ID: &str = "message-id";
const CLARITY_SIZE_MESSAGE_ID: u32 = 128;
const CLARITY_NAME_SOURCE_ADDRESS: &str = "source-address";
const CLARITY_SIZE_SOURCE_ADDRESS: u32 = 128;
const CLARITY_NAME_CONTRACT_ADDRESS: &str = "contract-address";
const CLARITY_NAME_PAYLOAD_HASH: &str = "payload-hash";
const CLARITY_SIZE_PAYLOAD_HASH: u32 = 32;
const CLARITY_NAME_SIGNER: &str = "signer";
const CLARITY_SIZE_SIGNER: u32 = 33;
const CLARITY_NAME_WEIGHT: &str = "weight";
const CLARITY_NAME_THRESHOLD: &str = "threshold";
const CLARITY_NAME_NONCE: &str = "nonce";
const CLARITY_NAME_TYPE: &str = "type";
const CLARITY_MAX_LEN_MESSAGES: u32 = 10;

#[derive(Debug)]
pub struct Message {
    pub source_chain: Value,
    pub message_id: Value,
    pub source_address: Value,
    pub contract_address: Value,
    pub payload_hash: Value,
}

impl TryFrom<&RouterMessage> for Message {
    type Error = ContractError;

    fn try_from(msg: &RouterMessage) -> Result<Self, Self::Error> {
        let contract_address = PrincipalData::parse(msg.destination_address.as_str())
            .map_err(|_| ContractError::InvalidMessage)?;

        Ok(Message {
            source_chain: Value::string_ascii_from_bytes(
                msg.cc_id.source_chain.as_ref().as_bytes().to_vec(),
            )
            .map_err(|_| ContractError::InvalidMessage)?,
            message_id: Value::string_ascii_from_bytes(msg.cc_id.message_id.as_bytes().to_vec())
                .map_err(|_| ContractError::InvalidMessage)?,
            source_address: Value::string_ascii_from_bytes(msg.source_address.as_bytes().to_vec())
                .map_err(|_| ContractError::InvalidMessage)?,
            contract_address: Value::Principal(contract_address),
            payload_hash: Value::buff_from(msg.payload_hash.to_vec())
                .map_err(|_| ContractError::InvalidMessage)?,
        })
    }
}

impl Message {
    fn try_into_value(self) -> Result<Value, ContractError> {
        Ok(Value::from(TupleData::from_data(vec![
            (
                ClarityName::from(CLARITY_NAME_SOURCE_CHAIN),
                self.source_chain,
            ),
            (ClarityName::from(CLARITY_NAME_MESSAGE_ID), self.message_id),
            (
                ClarityName::from(CLARITY_NAME_SOURCE_ADDRESS),
                self.source_address,
            ),
            (
                ClarityName::from(CLARITY_NAME_CONTRACT_ADDRESS),
                self.contract_address,
            ),
            (
                ClarityName::from(CLARITY_NAME_PAYLOAD_HASH),
                self.payload_hash,
            ),
        ])?))
    }
}

#[derive(PartialEq, Clone)]
pub struct WeightedSigner {
    pub signer: Vec<u8>,
    pub weight: u128,
}

#[derive(PartialEq)]
pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: Value,
    pub nonce: Value,
}

impl TryFrom<&Signer> for WeightedSigner {
    type Error = ContractError;

    fn try_from(signer: &Signer) -> Result<Self, Self::Error> {
        Ok(WeightedSigner {
            signer: ecdsa_key(&signer.pub_key)?,
            weight: signer.weight.into(),
        })
    }
}

impl TryFrom<&VerifierSet> for WeightedSigners {
    type Error = ContractError;

    fn try_from(verifier_set: &VerifierSet) -> Result<Self, Self::Error> {
        let mut signers: Vec<WeightedSigner> = verifier_set
            .signers
            .values()
            .map(WeightedSigner::try_from)
            .collect::<Result<_, _>>()?;

        signers.sort_by(|signer1, signer2| signer1.signer.cmp(&signer2.signer));

        Ok(WeightedSigners {
            signers,
            threshold: Value::UInt(verifier_set.threshold.into()),
            nonce: Value::buff_from(
                Uint256::from(verifier_set.created_at)
                    .to_be_bytes()
                    .to_vec(),
            )?,
        })
    }
}

impl WeightedSigner {
    fn try_into_value(self) -> Result<Value, ContractError> {
        Ok(Value::from(TupleData::from_data(vec![
            (
                ClarityName::from(CLARITY_NAME_SIGNER),
                Value::buff_from(self.signer)?,
            ),
            (
                ClarityName::from(CLARITY_NAME_WEIGHT),
                Value::UInt(self.weight),
            ),
        ])?))
    }
}

impl WeightedSigners {
    pub fn hash(self) -> Result<Hash, ContractError> {
        let value = self.try_into_value()?;

        Ok(Keccak256::digest(value.serialize_to_vec()?).into())
    }

    pub fn try_into_value(self) -> Result<Value, ContractError> {
        let weighted_signers: Vec<Value> = self
            .signers
            .into_iter()
            .map(|weighted_signer| weighted_signer.try_into_value())
            .collect::<Result<_, _>>()?;

        let signer_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from(CLARITY_NAME_SIGNER),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    CLARITY_SIZE_SIGNER,
                )?)),
            ),
            (
                ClarityName::from(CLARITY_NAME_WEIGHT),
                TypeSignature::UIntType,
            ),
        ])?;

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from(CLARITY_NAME_SIGNERS),
                Value::list_with_type(
                    &StacksEpochId::latest(),
                    weighted_signers,
                    ListTypeData::new_list(
                        TypeSignature::from(signer_type_signature),
                        CLARITY_MAX_LEN_SIGNATURES,
                    )?,
                )
                .map_err(|_| ContractError::InvalidMessage)?,
            ),
            (ClarityName::from(CLARITY_NAME_THRESHOLD), self.threshold),
            (ClarityName::from(CLARITY_NAME_NONCE), self.nonce),
        ])?;

        Ok(Value::from(tuple_data))
    }
}

impl From<ClarityError> for ContractError {
    fn from(_: ClarityError) -> Self {
        ContractError::InvalidMessage
    }
}

impl From<CheckErrors> for ContractError {
    fn from(_: CheckErrors) -> Self {
        ContractError::InvalidMessage
    }
}

pub fn ecdsa_key(pub_key: &PublicKey) -> Result<Vec<u8>, ContractError> {
    match pub_key {
        PublicKey::Ecdsa(ecdsa_key) => Ok(ecdsa_key.to_vec()),
        _ => Err(ContractError::InvalidPublicKey {
            reason: "Public key is not ecdsa".into(),
        }),
    }
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> error_stack::Result<Hash, ContractError> {
    let signer_hash = WeightedSigners::try_from(verifier_set)?.hash()?;
    let data_hash = Keccak256::digest(encode(payload)?);

    let stacks_signed_message =
        Value::string_ascii_from_bytes(STACKS_SIGNER_MESSAGE.as_bytes().to_vec())
            .change_context(ContractError::InvalidMessage)?
            .serialize_to_vec();

    let unsigned = [
        stacks_signed_message.as_slice(),
        domain_separator,
        signer_hash.as_slice(),
        data_hash.as_slice(),
    ]
    .concat();

    Ok(Keccak256::digest(unsigned).into())
}

fn encode(payload: &Payload) -> Result<Vec<u8>, ContractError> {
    match payload {
        Payload::Messages(messages) => {
            let message_value = encode_messages(messages)?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from(CLARITY_NAME_TYPE),
                    Value::string_ascii_from_bytes(TYPE_APPROVE_MESSAGES.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (ClarityName::from(CLARITY_NAME_DATA), message_value),
            ])?;

            Ok(Value::from(tuple_data).serialize_to_vec())
        }
        Payload::VerifierSet(verifier_set) => {
            let signers = WeightedSigners::try_from(verifier_set)?.try_into_value()?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from(CLARITY_NAME_TYPE),
                    Value::string_ascii_from_bytes(TYPE_ROTATE_SIGNERS.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (ClarityName::from(CLARITY_NAME_DATA), signers),
            ])?;

            Ok(Value::from(tuple_data).serialize_to_vec())
        }
    }
}

fn encode_messages(messages: &Vec<RouterMessage>) -> Result<Value, ContractError> {
    let messages: Vec<Value> = messages
        .iter()
        .map(Message::try_from)
        .map(|message| message?.try_into_value())
        .collect::<Result<_, _>>()?;

    let message_type_signature = TupleTypeSignature::try_from(vec![
        (
            ClarityName::from(CLARITY_NAME_SOURCE_CHAIN),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(CLARITY_SIZE_SOURCE_CHAIN)?,
            ))),
        ),
        (
            ClarityName::from(CLARITY_NAME_MESSAGE_ID),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(CLARITY_SIZE_MESSAGE_ID)?,
            ))),
        ),
        (
            ClarityName::from(CLARITY_NAME_SOURCE_ADDRESS),
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                BufferLength::try_from(CLARITY_SIZE_SOURCE_ADDRESS)?,
            ))),
        ),
        (
            ClarityName::from(CLARITY_NAME_CONTRACT_ADDRESS),
            TypeSignature::PrincipalType,
        ),
        (
            ClarityName::from(CLARITY_NAME_PAYLOAD_HASH),
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                CLARITY_SIZE_PAYLOAD_HASH,
            )?)),
        ),
    ])?;

    Ok(Value::list_with_type(
        &StacksEpochId::latest(),
        messages,
        ListTypeData::new_list(
            TypeSignature::from(message_type_signature),
            CLARITY_MAX_LEN_MESSAGES,
        )?,
    )
    .map_err(|_| ContractError::InvalidMessages)?)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{Addr, HexBinary, Uint256};
    use multisig::key::PublicKey;
    use multisig::msg::Signer;
    use router_api::{CrossChainId, Message as RouterMessage};
    use clarity::common::codec::StacksMessageCodec;

    use crate::encoding::stacks::{payload_digest, Message, WeightedSigner, WeightedSigners};
    use crate::error::ContractError;
    use crate::payload::Payload;
    use crate::test::test_data::{curr_verifier_set, domain_separator, verifier_set_from_pub_keys};

    #[test]
    fn weighted_signers_hash() {
        let expected_hash =
            HexBinary::from_hex("663DAF037F6CD2C37A2BC72A11BD06A43E50CB3C7FFC2C42D393B5927E53A564")
                .unwrap();
        let verifier_set = curr_verifier_set();

        let weighted_signers = WeightedSigners::try_from(&verifier_set);

        assert!(weighted_signers.is_ok());

        let weighted_signers = weighted_signers.unwrap();

        assert_eq!(
            weighted_signers.threshold.clone().expect_u128().unwrap(),
            3u128
        );
        assert_eq!(
            weighted_signers.nonce.clone().expect_buff(32).unwrap(),
            Uint256::from(1u128).to_be_bytes()
        );

        let hash = weighted_signers.hash();

        assert!(hash.is_ok());

        assert_eq!(hash.unwrap(), expected_hash);
    }

    #[test]
    fn rotate_signers_message_hash() {
        let expected_hash =
            HexBinary::from_hex("42cda0148cf0a4124670ca146155834b3e0135eaa1dd737632310294bfd89ed4")
                .unwrap();

        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
            "039d9031e97dd78ff8c15aa86939de9b1e791066a0224e331bc962a2099a7b1f04",
        ];
        let new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);

        let msg_to_sign = payload_digest(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::VerifierSet(new_verifier_set),
        )
        .unwrap();
        assert_eq!(msg_to_sign, expected_hash);
    }

    #[test]
    fn router_message_to_gateway_message() {
        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "ST2D4483A7FHNKV1ANCBWQ4TEDH31ZY1R8AG6WFCA";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_messages = RouterMessage {
            cc_id: CrossChainId {
                source_chain: source_chain.parse().unwrap(),
                message_id: message_id.parse().unwrap(),
            },
            source_address: source_address.parse().unwrap(),
            destination_address: destination_address.parse().unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: HexBinary::from_hex(payload_hash)
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        };

        let gateway_message = Message::try_from(&router_messages).unwrap();
        assert_eq!(
            gateway_message.source_chain.expect_ascii().unwrap(),
            source_chain
        );
        assert_eq!(
            gateway_message.message_id.expect_ascii().unwrap(),
            message_id
        );
        assert_eq!(
            gateway_message.source_address.expect_ascii().unwrap(),
            source_address
        );
        assert_eq!(
            gateway_message
                .contract_address
                .expect_principal()
                .unwrap()
                .serialize_to_vec(),
            HexBinary::from_hex("051a9a42206a3be359ec2aab17cb934e6c461ff83842")
                .unwrap()
                .as_slice(),
        );
        assert_eq!(
            gateway_message
                .payload_hash
                .expect_buff(32)
                .unwrap()
                .as_slice(),
            HexBinary::from_hex(payload_hash).unwrap().as_slice()
        );

        let tuple = Message::try_from(&router_messages)
            .unwrap()
            .try_into_value()
            .unwrap()
            .expect_tuple()
            .unwrap();

        assert_eq!(
            tuple
                .get("source-chain")
                .unwrap()
                .clone()
                .expect_ascii()
                .unwrap(),
            source_chain,
        );
        assert_eq!(
            tuple
                .get("message-id")
                .unwrap()
                .clone()
                .expect_ascii()
                .unwrap(),
            message_id,
        );
        assert_eq!(
            tuple
                .get("source-address")
                .unwrap()
                .clone()
                .expect_ascii()
                .unwrap(),
            source_address,
        );
        assert_eq!(
            tuple
                .get("contract-address")
                .unwrap()
                .clone()
                .expect_principal()
                .unwrap()
                .serialize_to_vec(),
            HexBinary::from_hex("051a9a42206a3be359ec2aab17cb934e6c461ff83842")
                .unwrap()
                .as_slice(),
        );
        assert_eq!(
            tuple
                .get("payload-hash")
                .unwrap()
                .clone()
                .expect_buff(32)
                .unwrap()
                .as_slice(),
            HexBinary::from_hex(payload_hash).unwrap().as_slice(),
        );
    }

    #[test]
    fn router_message_to_gateway_message_error() {
        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_messages = RouterMessage {
            cc_id: CrossChainId {
                source_chain: source_chain.parse().unwrap(),
                message_id: message_id.parse().unwrap(),
            },
            source_address: source_address.parse().unwrap(),
            destination_address: destination_address.parse().unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: HexBinary::from_hex(payload_hash)
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        };

        let gateway_message = Message::try_from(&router_messages);

        assert!(gateway_message.is_err());
        assert_eq!(
            gateway_message.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidMessage).to_string()
        );
    }

    #[test]
    fn approve_messages_hash() {
        let expected_hash =
            HexBinary::from_hex("1579b575ab10e664a708372d22a5909d558bce5b7d5b5a0c9e64034599d298d3")
                .unwrap();

        let domain_separator = domain_separator();

        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "ST2D4483A7FHNKV1ANCBWQ4TEDH31ZY1R8AG6WFCA";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_messages = RouterMessage {
            cc_id: CrossChainId {
                source_chain: source_chain.parse().unwrap(),
                message_id: message_id.parse().unwrap(),
            },
            source_address: source_address.parse().unwrap(),
            destination_address: destination_address.parse().unwrap(),
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: HexBinary::from_hex(payload_hash)
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        };

        let gateway_message = Message::try_from(&router_messages).unwrap();
        assert_eq!(
            gateway_message.source_chain.expect_ascii().unwrap(),
            source_chain
        );

        let digest = payload_digest(
            &domain_separator,
            &curr_verifier_set(),
            &Payload::Messages(vec![router_messages]),
        )
        .unwrap();

        assert_eq!(digest, expected_hash);
    }

    #[test]
    fn signer_to_weighted_signer() {
        let verifier_set = curr_verifier_set();
        let first_signer = verifier_set.signers.values().next().unwrap();

        let weighted_signer = WeightedSigner::try_from(first_signer).unwrap();

        assert_eq!(
            weighted_signer.signer,
            HexBinary::from_hex(
                "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0"
            )
            .unwrap()
        );

        assert_eq!(weighted_signer.weight, 1u128);

        let first_signer = weighted_signer.try_into_value().unwrap();
        let tuple = first_signer.expect_tuple().unwrap();

        assert_eq!(
            tuple
                .get("signer")
                .unwrap()
                .clone()
                .expect_buff(33)
                .unwrap(),
            PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0"
                )
                .unwrap()
            )
            .as_ref()
        );
        assert_eq!(
            tuple.get("weight").unwrap().clone().expect_u128().unwrap(),
            1,
        );
    }

    #[test]
    #[should_panic(expected = "Public key is not ecdsa")]
    fn signer_to_weighted_signer_error() {
        let signer = Signer {
            address: Addr::unchecked("verifier"),
            weight: 1u128.into(),
            pub_key: PublicKey::Ed25519(
                HexBinary::from_hex(
                    "ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6",
                )
                .unwrap(),
            ),
        };

        let _ = WeightedSigner::try_from(&signer).unwrap();
    }

    #[test]
    fn signers_to_weighted_signers() {
        let verifier_set = curr_verifier_set();

        let tuple = WeightedSigners::try_from(&verifier_set)
            .unwrap()
            .try_into_value()
            .unwrap()
            .expect_tuple()
            .unwrap();

        let signers = tuple.get("signers").unwrap().clone().expect_list().unwrap();
        assert_eq!(signers.len(), 5);

        let signer_tuple = signers.get(0).unwrap().clone().expect_tuple().unwrap();

        assert_eq!(
            signer_tuple
                .get("signer")
                .unwrap()
                .clone()
                .expect_buff(33)
                .unwrap(),
            PublicKey::Ecdsa(
                HexBinary::from_hex(
                    "0220b871f3ced029e14472ec4ebc3c0448164942b123aa6af91a3386c1c403e0eb"
                )
                .unwrap()
            )
            .as_ref()
        );
        assert_eq!(
            signer_tuple
                .get("weight")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap(),
            1,
        );

        assert_eq!(
            tuple
                .get("threshold")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap(),
            3,
        );
        assert_eq!(
            tuple.get("nonce").unwrap().clone().expect_buff(32).unwrap(),
            Uint256::from(1u128).to_be_bytes()
        );
    }
}
