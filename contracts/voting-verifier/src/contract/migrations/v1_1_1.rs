#![allow(deprecated)]

use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{nonempty, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;
use router_api::ChainName;

use crate::contract::{BASE_VERSION, CONTRACT_NAME};

#[deprecated(since = "1.1.1", note = "only used during migration")]
const CONFIG: Item<OldConfig> = Item::new("config");

pub fn migrate(
    storage: &mut dyn Storage,
    its_hub_address: Addr,
) -> Result<(), axelar_wasm_std::error::ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    let config: OldConfig = CONFIG.load(storage)?;

    let new_config = crate::state::Config {
        service_name: config.service_name,
        service_registry_contract: config.service_registry_contract,
        source_gateway_address: config.source_gateway_address,
        voting_threshold: config.voting_threshold,
        block_expiry: config.block_expiry,
        confirmation_height: config.confirmation_height,
        source_chain: config.source_chain,
        rewards_contract: config.rewards_contract,
        msg_id_format: config.msg_id_format,
        address_format: config.address_format,
        its_hub_address,
    };

    CONFIG.remove(storage);
    crate::state::CONFIG.save(storage, &new_config)?;

    Ok(())
}

#[deprecated]
#[cw_serde]
pub struct OldConfig {
    pub service_registry_contract: Addr,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a poll expires
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_contract: Addr,
    pub msg_id_format: MessageIdFormat,
    pub address_format: AddressFormat,
}
