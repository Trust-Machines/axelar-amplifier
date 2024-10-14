use crate::error::ContractError;
use crate::Payload;
use axelar_wasm_std::hash::Hash;
use multisig::verifier_set::VerifierSet;
use router_api::Message as RouterMessage;
use sha3::{Digest, Keccak256};
use stacks_clarity::vm::types::PrincipalData;

#[derive(Debug)]
pub struct Message {
    pub source_chain: String,
    pub message_id: String,
    pub source_address: String,
    pub contract_address: PrincipalData,
    pub payload_hash: [u8; 32],
}

impl Message {
    pub fn encode(&self) {}
}

impl TryFrom<&RouterMessage> for Message {
    type Error = ContractError;

    fn try_from(msg: &RouterMessage) -> Result<Self, Self::Error> {
        let contract_address = PrincipalData::parse(msg.destination_address.as_str())
            .map_err(|_| ContractError::InvalidMessage)?;

        Ok(Message {
            source_chain: msg.cc_id.source_chain.to_string(),
            message_id: msg.cc_id.message_id.to_string(),
            source_address: msg.source_address.to_string(),
            contract_address,
            payload_hash: msg.payload_hash,
        })
    }
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    let data_hash = match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?;

            todo!()
        },
        Payload::VerifierSet(verifier_set) => {
            todo!()
        }
    };

    let unsigned = [];

    Ok(Keccak256::digest(unsigned).into())
}
