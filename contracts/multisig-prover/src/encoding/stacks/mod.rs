use crate::error::ContractError;
use crate::Payload;
use axelar_wasm_std::hash::Hash;
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;
use sha3::{Digest, Keccak256};
use multisig::msg::Signer;
use stacks_clarity::common::codec::StacksMessageCodec;
use stacks_clarity::common::types::StacksEpochId;
use stacks_clarity::vm::analysis::errors::CheckErrors;
use stacks_clarity::vm::errors::Error as ClarityError;
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::signatures::{
    BufferLength, ListTypeData, SequenceSubtype, StringSubtype, TupleTypeSignature, TypeSignature,
};
use stacks_clarity::vm::types::{PrincipalData, TupleData, Value};

const TYPE_APPROVE_MESSAGES: &str = "approve-messages";

const STACKS_SIGNER_MESSAGE: &str = "Stacks Signed Message";

#[derive(Debug)]
pub struct Message {
    pub source_chain: Value,
    pub message_id: Value,
    pub source_address: Value,
    pub contract_address: PrincipalData,
    pub payload_hash: Value,
}

#[derive(PartialEq)]
pub struct WeightedSigner {
    pub signer: Value,
    pub weight: Value,
}

#[derive(PartialEq)]
pub struct WeightedSigners {
    pub signers: Vec<WeightedSigner>,
    pub threshold: Value,
    pub nonce: Value,
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
//
// impl From<&Signer> for WeightedSigner {
//     fn from(signer: &Signer) -> Self {
//         WeightedSigner {
//             signer: ed25519_key(&signer.pub_key).expect("not ed25519 key"),
//             weight: uint256_to_compact_vec(signer.weight.into()),
//         }
//     }
// }
//
// impl From<&VerifierSet> for WeightedSigners {
//     fn from(verifier_set: &VerifierSet) -> Self {
//         let mut signers = verifier_set
//             .signers
//             .values()
//             .map(WeightedSigner::from)
//             .collect::<Vec<_>>();
//
//         signers.sort_by_key(|weighted_signer| weighted_signer.signer);
//
//         WeightedSigners {
//             signers,
//             threshold: uint256_to_compact_vec(verifier_set.threshold.into()),
//             nonce: Uint256::from(verifier_set.created_at).to_be_bytes(),
//         }
//     }
// }

impl Message {
    fn try_into_value(self) -> Result<Value, ContractError> {
        Ok(Value::from(TupleData::from_data(vec![(
            ClarityName::from("source-chain"),
            self.source_chain,
        )])?))
    }
}

impl WeightedSigners {
    pub fn hash(&self) -> Hash {
        let mut encoded: Vec<&[u8]> = Vec::new();

        // for signer in self.signers.iter() {
        //     encoded.push(signer.signer.as_slice());
        //     encoded.push(signer.weight.as_slice());
        // }
        //
        // encoded.push(self.threshold.as_slice());
        // encoded.push(self.nonce.as_slice());

        Keccak256::digest(encoded.concat()).into()
    }

    // pub fn encode(self) -> Result<Vec<u8>, ContractError> {
    //     Ok(
    //         top_encode_to_vec_u8(&(self.signers, self.threshold.as_slice(), self.nonce))
    //             .expect("couldn't serialize weighted signers as mvx"),
    //     )
    // }
}

impl From<ClarityError> for ContractError {
    fn from(_: ClarityError) -> Self {
        ContractError::InvalidMessage
    }
}

impl From<CheckErrors> for ContractError {
    // TODO: Handle different cases here?
    fn from(_: CheckErrors) -> Self {
        ContractError::InvalidMessage
    }
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    // let signer_hash = WeightedSigners::from(verifier_set).hash();
    let data_hash = Keccak256::digest(encode(payload)?);

    let stacks_signed_message = Value::string_ascii_from_bytes(STACKS_SIGNER_MESSAGE.as_bytes().to_vec())?.serialize_to_vec();

    let unsigned = [
        stacks_signed_message.as_slice(),
        domain_separator,
        // signer_hash.as_slice(), TODO:
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
                // TODO: In Gateway, currently the contract-address is buff 32, check if to keep this or change
                (ClarityName::from("contract-address"), TypeSignature::PrincipalType),
                (
                    ClarityName::from("payload-hash"),
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(
                        18u32,
                    )?)),
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
            todo!()
        }
    }
}
