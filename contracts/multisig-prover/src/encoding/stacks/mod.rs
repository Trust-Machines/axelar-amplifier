use crate::error::ContractError;
use crate::Payload;
use axelar_wasm_std::hash::Hash;
use cosmwasm_std::Uint256;
use error_stack::ResultExt;
use multisig::key::PublicKey;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;
use sha3::{Digest, Keccak256};
use stacks_clarity::common::codec::StacksMessageCodec;
use stacks_clarity::common::types::StacksEpochId;
use stacks_clarity::vm::analysis::errors::CheckErrors;
use stacks_clarity::vm::errors::{Error as ClarityError, Error};
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::signatures::{
    BufferLength, ListTypeData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
};
use stacks_clarity::vm::types::{PrincipalData, TupleData, Value};

const TYPE_APPROVE_MESSAGES: &str = "approve-messages";
const TYPE_ROTATE_SIGNERS: &str = "rotate-signers";

const STACKS_SIGNER_MESSAGE: &str = "Stacks Signed Message";

#[derive(Debug)]
pub struct Message {
    pub source_chain: Value,
    pub message_id: Value,
    pub source_address: Value,
    pub contract_address: PrincipalData,
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
            contract_address,
            payload_hash: Value::buff_from(msg.payload_hash.to_vec())
                .map_err(|_| ContractError::InvalidMessage)?,
        })
    }
}

impl Message {
    fn try_into_value(self) -> Result<Value, ContractError> {
        Ok(Value::from(TupleData::from_data(vec![
            (ClarityName::from("source-chain"), self.source_chain),
            (ClarityName::from("message-id"), self.message_id),
            (ClarityName::from("source-address"), self.source_address),
            (
                ClarityName::from("contract-address"),
                Value::Principal(self.contract_address),
            ),
            (ClarityName::from("payload-hash"), self.payload_hash),
        ])?))
    }
}

#[derive(PartialEq)]
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
            (ClarityName::from("signer"), Value::buff_from(self.signer)?),
            (ClarityName::from("weight"), Value::UInt(self.weight)),
        ])?))
    }
}

impl WeightedSigners {
    pub fn hash(self) -> Result<Hash, ContractError> {
        let value = self.encode()?;

        Ok(Keccak256::digest(value.serialize_to_vec()).into())
    }

    pub fn encode(self) -> Result<Value, ContractError> {
        let weighted_signers: Vec<Value> = self
            .signers
            .into_iter()
            .map(|weighted_signer| weighted_signer.try_into_value())
            .collect::<Result<_, _>>()?;

        let signer_type_signature = TupleTypeSignature::try_from(vec![
            (
                ClarityName::from("signer"),
                TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                    33u32,
                )?)),
            ),
            (ClarityName::from("weight"), TypeSignature::UIntType),
        ])?;

        let tuple_data = TupleData::from_data(vec![
            (
                ClarityName::from("signers"),
                Value::list_with_type(
                    &StacksEpochId::latest(),
                    weighted_signers,
                    ListTypeData::new_list(TypeSignature::from(signer_type_signature), 48)?,
                )
                .map_err(|_| ContractError::InvalidMessage)?,
            ),
            (ClarityName::from("threshold"), self.threshold),
            (ClarityName::from("nonce"), self.nonce),
        ])?;

        Ok(Value::from(tuple_data))
    }
}

// TODO: Handle different cases here?
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
            reason: "Public key is not ed25519".into(),
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
            let messages: Vec<Value> = messages
                .iter()
                .map(Message::try_from)
                .map(|message| message?.try_into_value())
                .collect::<Result<_, _>>()?;

            let message_type_signature = TupleTypeSignature::try_from(vec![
                (
                    ClarityName::from("source-chain"),
                    TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                        BufferLength::try_from(32u32)?,
                    ))),
                ),
                (
                    ClarityName::from("message-id"),
                    TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                        BufferLength::try_from(71u32)?,
                    ))),
                ),
                (
                    ClarityName::from("source-address"),
                    TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                        BufferLength::try_from(48u32)?,
                    ))),
                ),
                (
                    ClarityName::from("contract-address"),
                    TypeSignature::PrincipalType,
                ),
                (
                    ClarityName::from("payload-hash"),
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        BufferLength::try_from(18u32)?,
                    )),
                ),
            ])?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from("type"),
                    Value::string_ascii_from_bytes(TYPE_APPROVE_MESSAGES.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from("data"),
                    Value::list_with_type(
                        &StacksEpochId::latest(),
                        messages,
                        ListTypeData::new_list(TypeSignature::from(message_type_signature), 10)?,
                    )
                    .map_err(|_| ContractError::InvalidMessage)?,
                ),
            ])?;

            Ok(Value::from(tuple_data).serialize_to_vec())
        }
        Payload::VerifierSet(verifier_set) => {
            let signers = WeightedSigners::try_from(verifier_set)?.encode()?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from("type"),
                    Value::string_ascii_from_bytes(TYPE_ROTATE_SIGNERS.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (ClarityName::from("data"), signers),
            ])?;

            Ok(Value::from(tuple_data).serialize_to_vec())
        }
    }
}
