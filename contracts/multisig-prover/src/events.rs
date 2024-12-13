use cosmwasm_std::Uint64;
use router_api::{ChainName, CrossChainId};

use crate::payload::PayloadId;

pub enum Event {
    ProofUnderConstruction {
        destination_chain: ChainName,
        payload_id: PayloadId,
        multisig_session_id: Uint64,
        msg_ids: Vec<CrossChainId>,
    },
    ItsHubClarityPayload {
        payload: Vec<u8>,
        payload_hash: [u8; 32],
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::ProofUnderConstruction {
                destination_chain,
                payload_id,
                multisig_session_id,
                msg_ids,
            } => cosmwasm_std::Event::new("proof_under_construction")
                .add_attribute(
                    "destination_chain",
                    serde_json::to_string(&destination_chain)
                        .expect("violated invariant: destination_chain is not serializable"),
                )
                .add_attribute(
                    "payload_id",
                    serde_json::to_string(&payload_id)
                        .expect("violated invariant: payload_id is not serializable"),
                )
                .add_attribute(
                    "multisig_session_id",
                    serde_json::to_string(&multisig_session_id)
                        .expect("violated invariant: multisig_session_id is not serializable"),
                )
                .add_attribute(
                    "message_ids",
                    serde_json::to_string(&msg_ids)
                        .expect("violated invariant: message_ids is not serializable"),
                ),
            Event::ItsHubClarityPayload {
                payload,
                payload_hash,
            } => cosmwasm_std::Event::new("its_hub_clarity_payload")
                .add_attribute(
                    "payload",
                    serde_json::to_string(&payload)
                        .expect("violated invariant: payload is not serializable"),
                )
                .add_attribute(
                    "payload_hash",
                    serde_json::to_string(&payload_hash)
                        .expect("violated invariant: payload_hash is not serializable"),
                ),
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;
    use router_api::Message;
    use serde_json::to_string;
    use sha3::{Digest, Keccak256};

    use super::*;
    use crate::payload::Payload;

    #[test]
    fn proof_under_construction_is_serializable() {
        let payload = Payload::Messages(vec![
            Message {
                cc_id: CrossChainId::new("ethereum", "some-id").unwrap(),
                source_address: "0x1234".parse().unwrap(),
                destination_chain: "avalanche".parse().unwrap(),
                destination_address: "0x5678".parse().unwrap(),
                payload_hash: [0; 32],
            },
            Message {
                cc_id: CrossChainId::new("fantom", "some-other-id").unwrap(),
                source_address: "0x1234".parse().unwrap(),
                destination_chain: "avalanche".parse().unwrap(),
                destination_address: "0x5678".parse().unwrap(),
                payload_hash: [0; 32],
            },
        ]);

        let event = Event::ProofUnderConstruction {
            destination_chain: "avalanche".parse().unwrap(),
            payload_id: payload.id(),
            multisig_session_id: Uint64::new(2),
            msg_ids: payload.message_ids().unwrap(),
        };

        assert!(to_string(&cosmwasm_std::Event::from(event)).is_ok());
    }

    #[test]
    fn its_hub_clarity_payload_is_serializable() {
        let payload =
            HexBinary::from_hex("0c0000000506706172616d7302000000420c00000002086f70657261746f72090d746f6b656e2d61646472657373061a555db886b8dda288a0a7695027c4d2656dacbc760e73616d706c652d7369702d3031300c736f757263652d636861696e0d0000000e6176616c616e6368652d66756a6908746f6b656e2d69640200000020dfbbd97a4e0c3ec2338d800be851dca6d08d4779398d4070d5cb18d2ebfe62d712746f6b656e2d6d616e616765722d74797065010000000000000000000000000000000204747970650100000000000000000000000000000002").unwrap();
        let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();

        let event = Event::ItsHubClarityPayload {
            payload: payload.to_vec(),
            payload_hash,
        };

        assert!(to_string(&cosmwasm_std::Event::from(event)).is_ok());
    }
}
