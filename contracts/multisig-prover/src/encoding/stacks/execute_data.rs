use crate::encoding::stacks::{ecdsa_key, encode_messages, payload_digest, WeightedSigners};
use crate::error::ContractError;
use crate::payload::Payload;
use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::ResultExt;
use k256::ecdsa::RecoveryId;
use multisig::key::Signature;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use stacks_clarity::common::codec::StacksMessageCodec;
use stacks_clarity::common::types::StacksEpochId;
use stacks_clarity::vm::representations::ClarityName;
use stacks_clarity::vm::types::signatures::{
    BufferLength, ListTypeData, SequenceSubtype, TypeSignature,
};
use stacks_clarity::vm::types::{TupleData, Value};

pub const APPROVE_MESSAGES_FUNCTION: &str = "approve-messages";
pub const ROTATE_SIGNERS_FUNCTION: &str = "rotate-signers";

pub struct Proof {
    pub signers: WeightedSigners,
    pub signatures: Vec<Value>,
}

impl Proof {
    pub fn new(
        verifier_set: &VerifierSet,
        signers_with_sigs: Vec<SignerWithSig>,
    ) -> Result<Self, ContractError> {
        let signers = WeightedSigners::try_from(verifier_set)?;

        let mut signers_with_sigs: Vec<(Vec<u8>, Signature)> = signers_with_sigs
            .into_iter()
            .map(|signer| {
                let key = ecdsa_key(&signer.signer.pub_key).expect("not ecdsa key");

                (key, signer.signature)
            })
            .collect::<Vec<_>>();

        signers_with_sigs.sort_by(|signer1, signer2| signer1.0.cmp(&signer2.0));

        let signatures = signers_with_sigs
            .into_iter()
            .map(|signer| Value::buff_from(signer.1.as_ref().to_vec()))
            .collect::<Result<_, _>>()?;

        Ok(Proof {
            signers,
            signatures,
        })
    }

    pub fn try_into_value(self) -> Result<Value, ContractError> {
        let signers = self.signers.try_into_value()?;
        let signatures = Value::list_with_type(
            &StacksEpochId::latest(),
            self.signatures,
            ListTypeData::new_list(
                TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    BufferLength::try_from(65u32).map_err(|_| ContractError::InvalidMessage)?,
                )),
                48,
            )?,
        )
        .map_err(|_| ContractError::InvalidMessage)?;

        let tuple_data = TupleData::from_data(vec![
            (ClarityName::from("signers"), signers),
            (ClarityName::from("signatures"), signatures),
        ])?;

        Ok(Value::from(tuple_data))
    }
}

pub fn encode(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload: &Payload,
) -> error_stack::Result<HexBinary, ContractError> {
    let signers = to_recoverable(
        payload_digest(domain_separator, verifier_set, payload)?,
        signers,
    );

    let proof = Proof::new(verifier_set, signers)?;

    let data = match payload {
        Payload::Messages(messages) => {
            let messages = encode_messages(messages)?.serialize_to_vec();
            let proof = proof.try_into_value()?.serialize_to_vec();

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from("function"),
                    Value::string_ascii_from_bytes(APPROVE_MESSAGES_FUNCTION.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from("data"),
                    Value::buff_from(messages).map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from("proof"),
                    Value::buff_from(proof).map_err(|_| ContractError::InvalidMessage)?,
                ),
            ])
            .change_context(ContractError::InvalidMessage)?;

            HexBinary::from(Value::from(tuple_data).serialize_to_vec())
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_verifier_set = WeightedSigners::try_from(new_verifier_set)?
                .try_into_value()?
                .serialize_to_vec();
            let proof = proof.try_into_value()?.serialize_to_vec();

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from("function"),
                    Value::string_ascii_from_bytes(ROTATE_SIGNERS_FUNCTION.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from("data"),
                    Value::buff_from(new_verifier_set)
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from("proof"),
                    Value::buff_from(proof).map_err(|_| ContractError::InvalidMessage)?,
                ),
            ])
            .change_context(ContractError::InvalidMessage)?;

            HexBinary::from(Value::from(tuple_data).serialize_to_vec())
        }
    };

    Ok(data)
}

fn to_recoverable<M>(msg: M, signers: Vec<SignerWithSig>) -> Vec<SignerWithSig>
where
    M: AsRef<[u8]>,
{
    let recovery_transform = |recovery_byte: RecoveryId| -> u8 { recovery_byte.to_byte() };

    signers
        .into_iter()
        .map(|mut signer| {
            if let Signature::Ecdsa(nonrecoverable) = signer.signature {
                signer.signature = nonrecoverable
                    .to_recoverable(msg.as_ref(), &signer.signer.pub_key, recovery_transform)
                    .map(Signature::EcdsaRecoverable)
                    .expect("failed to convert non-recoverable signature to recoverable");
            }

            signer
        })
        .collect()
}
