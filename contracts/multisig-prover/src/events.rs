use axelar_wasm_std::IntoEvent;
use cosmwasm_std::Uint64;
use router_api::{ChainName, CrossChainId};

use crate::payload::PayloadId;

#[derive(IntoEvent)]
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
        let event = cosmwasm_std::Event::from(event);

        goldie::assert_json!(event);
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
