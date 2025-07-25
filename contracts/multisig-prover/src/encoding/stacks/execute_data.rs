use axelar_wasm_std::hash::Hash;
use clarity_serialization::representations::ClarityName;
use clarity_serialization::types::signatures::{BufferLength, ListTypeData, SequenceSubtype, TypeSignature};
use clarity_serialization::types::{TupleData, Value};
use clarity_serialization::stacks_types::StacksEpochId;
use cosmwasm_std::HexBinary;
use error_stack::ResultExt;
use k256::ecdsa::RecoveryId;
use multisig::key::Signature;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use stacks_types::constants::*;

use crate::encoding::stacks::{ecdsa_key, encode_messages, payload_digest, WeightedSigners};
use crate::error::ContractError;
use crate::payload::Payload;

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

        let mut signers_with_sigs = signers_with_sigs
            .into_iter()
            .map(|signer| ecdsa_key(&signer.signer.pub_key).map(|key| (key, signer.signature)))
            .collect::<Result<Vec<(Vec<u8>, Signature)>, _>>()?;

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
                    BufferLength::try_from(CLARITY_SIZE_SIGNATURES)
                        .map_err(|_| ContractError::InvalidMessage)?,
                )),
                CLARITY_MAX_LEN_SIGNATURES,
            )?,
        )
        .map_err(|_| ContractError::InvalidMessage)?;

        let tuple_data = TupleData::from_data(vec![
            (ClarityName::from(CLARITY_NAME_SIGNERS), signers),
            (ClarityName::from(CLARITY_NAME_SIGNATURES), signatures),
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
            let messages = encode_messages(messages)?
                .serialize_to_vec()
                .map_err(|_| ContractError::InvalidMessage)?;
            let proof = proof
                .try_into_value()?
                .serialize_to_vec()
                .map_err(|_| ContractError::InvalidMessage)?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from(CLARITY_NAME_FUNCTION),
                    Value::string_ascii_from_bytes(APPROVE_MESSAGES_FUNCTION.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from(CLARITY_NAME_DATA),
                    Value::buff_from(messages).map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from(CLARITY_NAME_PROOF),
                    Value::buff_from(proof).map_err(|_| ContractError::InvalidMessage)?,
                ),
            ])
            .change_context(ContractError::InvalidMessage)?;

            HexBinary::from(
                Value::from(tuple_data)
                    .serialize_to_vec()
                    .map_err(|_| ContractError::InvalidMessage)?,
            )
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_verifier_set = WeightedSigners::try_from(new_verifier_set)?
                .try_into_value()?
                .serialize_to_vec()
                .map_err(|_| ContractError::InvalidMessage)?;
            let proof = proof
                .try_into_value()?
                .serialize_to_vec()
                .map_err(|_| ContractError::InvalidMessage)?;

            let tuple_data = TupleData::from_data(vec![
                (
                    ClarityName::from(CLARITY_NAME_FUNCTION),
                    Value::string_ascii_from_bytes(ROTATE_SIGNERS_FUNCTION.as_bytes().to_vec())
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from(CLARITY_NAME_DATA),
                    Value::buff_from(new_verifier_set)
                        .map_err(|_| ContractError::InvalidMessage)?,
                ),
                (
                    ClarityName::from(CLARITY_NAME_PROOF),
                    Value::buff_from(proof).map_err(|_| ContractError::InvalidMessage)?,
                ),
            ])
            .change_context(ContractError::InvalidMessage)?;

            HexBinary::from(
                Value::from(tuple_data)
                    .serialize_to_vec()
                    .map_err(|_| ContractError::InvalidMessage)?,
            )
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

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use cosmwasm_std::HexBinary;
    use itertools::Itertools;
    use multisig::key::{KeyTyped, Signature};
    use multisig::msg::{Signer, SignerWithSig};
    use router_api::{CrossChainId, Message as RouterMessage};

    use crate::encoding::stacks::execute_data::encode;
    use crate::payload::Payload;
    use crate::test::test_data::{curr_verifier_set, domain_separator, verifier_set_from_pub_keys};

    #[test]
    fn rotate_signers_function_data() {
        let domain_separator = domain_separator();

        let new_pub_keys = vec![
            "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0",
            "039d9031e97dd78ff8c15aa86939de9b1e791066a0224e331bc962a2099a7b1f04",
        ];

        let mut new_verifier_set = verifier_set_from_pub_keys(new_pub_keys);
        new_verifier_set.created_at = 2024;

        let verifier_set = curr_verifier_set();

        // Generated signatures are already sorted by weight and pub key
        let sigs: Vec<_> = vec![
            "e3a7c09bfa26df8bbd207df89d7ba01100b809324b2987e1426081284a50485345a5a20b6d1d5844470513099937f1015ce8f4832d3df97d053f044103434d8c1b",
            "895dacfb63684da2360394d5127696129bd0da531d6877348ff840fb328297f870773df3c259d15dd28dbd51d87b910e4156ff2f3c1dc5f64d337dea7968a9401b",
            "7c685ecc8a42da4cd9d6de7860b0fddebb4e2e934357500257c1070b1a15be5e27f13b627cf9fa44f59d535af96be0a5ec214d988c48e2b5aaf3ba537d0215bb1b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::VerifierSet(new_verifier_set);

        assert_ok!(encode(
            &domain_separator,
            &verifier_set,
            signers_with_sigs,
            &payload,
        ));
    }

    #[test]
    fn approve_messages_function_data() {
        let domain_separator = domain_separator();
        let verifier_set = curr_verifier_set();

        // Generated signatures are already sorted by weight and pub key
        let sigs: Vec<_> = vec![
            "756473c3061df7ea3fef7c52e0e875dca2c93f08ce4f1d33e694d64c713a56842017d92f0a1b796afe1c5343677ff261a072fb210ff3d43cc2784c0774d4da7b1b",
            "5bdad2b95e700283402392a2f5878d185f92d588a6b4868460977c4f06f4216f0452c2e215c2878fe6e146db5b74f278716a99b418c6b2cb1d812ad28e686cd81c",
            "4c9c52a99a3941a384c4a80b3c5a14c059020d3d2f29be210717bdb9270ed55937fcec824313c90c198188ea8eb3b47c2bafe5e96c11f79ec793d589358024191b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let source_chain = "chain0";
        let message_id = "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0";
        let source_address = "0x52444f1835Adc02086c37Cb226561605e2E1699b";
        let destination_chain = "chain1";
        let destination_address = "ST2D4483A7FHNKV1ANCBWQ4TEDH31ZY1R8AG6WFCA";
        let payload_hash = "8c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0";

        let router_message = RouterMessage {
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

        let payload = Payload::Messages(vec![router_message]);

        assert_ok!(encode(
            &domain_separator,
            &verifier_set,
            signers_with_sigs,
            &payload
        ));
    }

    fn signers_with_sigs<'a>(
        signers: impl Iterator<Item = &'a Signer>,
        sigs: Vec<HexBinary>,
    ) -> Vec<SignerWithSig> {
        signers
            .sorted_by(|s1, s2| Ord::cmp(&s1.pub_key, &s2.pub_key))
            .zip(sigs)
            .map(|(signer, sig)| {
                signer.with_sig(Signature::try_from((signer.pub_key.key_type(), sig)).unwrap())
            })
            .collect()
    }
}
