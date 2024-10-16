use axelar_wasm_std::event::EventExt;
use router_api::{Address, ChainNameRaw, CrossChainId};

use crate::primitives::Message;

pub enum Event {
    MessageReceived {
        cc_id: CrossChainId,
        destination_chain: ChainNameRaw,
        message: Message,
    },
    ItsContractRegistered {
        chain: ChainNameRaw,
        address: Address,
    },
    ItsContractDeregistered {
        chain: ChainNameRaw,
    },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(event: Event) -> Self {
        match event {
            Event::MessageReceived {
                cc_id,
                destination_chain,
                message,
            } => make_message_event("message_received", cc_id, destination_chain, message),
            Event::ItsContractRegistered { chain, address } => {
                cosmwasm_std::Event::new("its_contract_registered")
                    .add_attribute("chain", chain.to_string())
                    .add_attribute("address", address.to_string())
            }
            Event::ItsContractDeregistered { chain } => {
                cosmwasm_std::Event::new("its_contract_deregistered")
                    .add_attribute("chain", chain.to_string())
            }
        }
    }
}

fn make_message_event(
    event_name: &str,
    cc_id: CrossChainId,
    destination_chain: ChainNameRaw,
    msg: Message,
) -> cosmwasm_std::Event {
    let event = cosmwasm_std::Event::new(event_name)
        .add_attribute("cc_id", cc_id.to_string())
        .add_attribute("destination_chain", destination_chain.to_string())
        .add_attribute("message_type", msg.as_ref().to_string());

    match msg {
        Message::InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        } => event
            .add_attribute("token_id", token_id.to_string())
            .add_attribute("source_address", source_address.to_string())
            .add_attribute("destination_address", destination_address.to_string())
            .add_attribute("amount", amount.to_string())
            .add_attribute_if_some("data", data.map(|data| data.to_string())),
        Message::DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        } => event
            .add_attribute("token_id", token_id.to_string())
            .add_attribute("name", name)
            .add_attribute("symbol", symbol)
            .add_attribute("decimals", decimals.to_string())
            .add_attribute_if_some("minter", minter.map(|minter| minter.to_string())),
        Message::DeployTokenManager {
            token_id,
            token_manager_type,
            params,
        } => event
            .add_attribute("token_id", token_id.to_string())
            .add_attribute(
                "token_manager_type",
                token_manager_type.as_ref().to_string(),
            )
            .add_attribute("params", params.to_string()),
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;
    use router_api::CrossChainId;

    use crate::events::Event;
    use crate::{Message, TokenId, TokenManagerType};

    #[test]
    fn message_received_with_all_attributes() {
        let test_cases: Vec<Message> = vec![
            Message::InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([1; 32]).try_into().unwrap(),
                destination_address: HexBinary::from([1, 2, 3, 4]).try_into().unwrap(),
                amount: 1u64.try_into().unwrap(),
                data: Some(HexBinary::from([1, 2, 3, 4]).try_into().unwrap()),
            },
            Message::DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "Test".try_into().unwrap(),
                symbol: "TST".try_into().unwrap(),
                decimals: 18,
                minter: Some(HexBinary::from([1; 32]).try_into().unwrap()),
            },
            Message::DeployTokenManager {
                token_id: TokenId::new([1; 32]),
                token_manager_type: TokenManagerType::MintBurn,
                params: HexBinary::from([1, 2, 3, 4]).try_into().unwrap(),
            },
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|message| {
                let event = Event::MessageReceived {
                    cc_id: CrossChainId::new("source", "hash").unwrap(),
                    destination_chain: "destination".parse().unwrap(),
                    message,
                };

                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }

    #[test]
    fn message_received_with_empty_attributes() {
        let test_cases: Vec<Message> = vec![
            Message::InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([1; 32]).try_into().unwrap(),
                destination_address: HexBinary::from([1, 2, 3, 4]).try_into().unwrap(),
                amount: 1u64.try_into().unwrap(),
                data: None,
            },
            Message::InterchainTransfer {
                token_id: TokenId::new([1; 32]),
                source_address: HexBinary::from([0u8]).try_into().unwrap(),
                destination_address: HexBinary::from([0u8]).try_into().unwrap(),
                amount: 1u64.try_into().unwrap(),
                data: None,
            },
            Message::DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "Test".try_into().unwrap(),
                symbol: "TST".try_into().unwrap(),
                decimals: 18,
                minter: None,
            },
            Message::DeployInterchainToken {
                token_id: TokenId::new([1; 32]),
                name: "t".try_into().unwrap(),
                symbol: "T".try_into().unwrap(),
                decimals: 0,
                minter: None,
            },
            Message::DeployTokenManager {
                token_id: TokenId::new([1; 32]),
                token_manager_type: TokenManagerType::MintBurn,
                params: HexBinary::from([0u8]).try_into().unwrap(),
            },
        ];

        let events: Vec<_> = test_cases
            .into_iter()
            .map(|message| {
                let event = Event::MessageReceived {
                    cc_id: CrossChainId::new("source", "hash").unwrap(),
                    destination_chain: "destination".parse().unwrap(),
                    message,
                };

                cosmwasm_std::Event::from(event)
            })
            .collect();

        goldie::assert_json!(events);
    }
}
