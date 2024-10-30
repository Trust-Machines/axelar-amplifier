#![allow(deprecated)]

// TODO: This can probably be deleted

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::{address, MajorityThreshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Api, Storage};
use cw_storage_plus::Item;
use multisig::key::KeyType;
use router_api::ChainName;

use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
use crate::{state, Encoder};

const BASE_VERSION: &str = "1.0.0";

pub fn migrate(
    storage: &mut dyn Storage,
    api: &dyn Api,
    its_hub_address: String,
) -> Result<(), ContractError> {
    let should_do_migration = cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION);

    // Skip migration if it is already done
    if should_do_migration.is_err() {
        cw2::assert_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        return Ok(());
    }

    let config = CONFIG.load(storage)?;
    CONFIG.remove(storage);

    let config = state::Config {
        gateway: config.gateway,
        multisig: config.multisig,
        coordinator: config.coordinator,
        service_registry: config.service_registry,
        voting_verifier: config.voting_verifier,
        signing_threshold: config.signing_threshold,
        service_name: config.service_name,
        chain_name: config.chain_name,
        verifier_set_diff_threshold: config.verifier_set_diff_threshold,
        encoder: config.encoder,
        key_type: config.key_type,
        domain_separator: config.domain_separator,
        its_hub_address: address::validate_cosmwasm_address(api, &its_hub_address)?,
    };

    state::CONFIG.save(storage, &config)?;

    cw2::set_contract_version(storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(())
}

#[cw_serde]
#[deprecated(since = "1.0.1", note = "only used during migration")]
pub struct Config {
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
    pub domain_separator: Hash,
}

#[deprecated(since = "1.0.1", note = "only used during migration")]
pub const CONFIG: Item<Config> = Item::new("config");

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{MajorityThreshold, Threshold};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
    use multisig::key::KeyType;

    use crate::contract::migrations::v1_0_1;
    use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
    use crate::encoding::Encoder;
    use crate::error::ContractError;
    use crate::msg::InstantiateMsg;
    use crate::state;

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        let deps = deps.as_mut();

        assert!(v1_0_1::migrate(deps.storage, deps.api, "its_hub".to_string()).is_err());

        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v1_0_1::BASE_VERSION).unwrap();

        assert!(v1_0_1::migrate(deps.storage, deps.api, "its_hub".to_string()).is_ok());
    }

    #[test]
    fn migrate_sets_its_hub_address() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut());

        let deps = deps.as_mut();

        v1_0_1::migrate(deps.storage, deps.api, "its_hub".to_string()).unwrap();

        let contract_version = cw2::get_contract_version(deps.storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);

        let config = state::CONFIG.load(deps.storage).unwrap();

        assert_eq!(config.its_hub_address, "its_hub");
    }

    fn instantiate_contract(deps: DepsMut) {
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InstantiateMsg {
                admin_address: "admin".to_string(),
                governance_address: "governance".to_string(),
                gateway_address: "gateway".to_string(),
                multisig_address: "multisig".to_string(),
                coordinator_address: "coordinator".to_string(),
                service_registry_address: "service_registry".to_string(),
                voting_verifier_address: "voting_verifier".to_string(),
                signing_threshold: Threshold::try_from((2u64, 3u64))
                    .and_then(MajorityThreshold::try_from)
                    .unwrap(),
                service_name: "service".to_string(),
                chain_name: "chain".to_string(),
                verifier_set_diff_threshold: 1,
                encoder: Encoder::Abi,
                key_type: KeyType::Ecdsa,
                domain_separator: [0; 32],
                its_hub_address: "its_hub".to_string(),
            },
        )
        .unwrap();
    }

    #[deprecated(since = "1.0.0", note = "only used to test the migration")]
    pub fn instantiate(
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v1_0_1::BASE_VERSION)?;

        let config = make_old_config(&deps, msg)?;
        v1_0_1::CONFIG.save(deps.storage, &config)?;

        Ok(Response::default())
    }

    fn make_old_config(
        deps: &DepsMut,
        msg: InstantiateMsg,
    ) -> Result<v1_0_1::Config, axelar_wasm_std::error::ContractError> {
        let gateway = deps.api.addr_validate(&msg.gateway_address)?;
        let multisig = deps.api.addr_validate(&msg.multisig_address)?;
        let coordinator = deps.api.addr_validate(&msg.coordinator_address)?;
        let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;
        let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;

        Ok(v1_0_1::Config {
            gateway,
            multisig,
            coordinator,
            service_registry,
            voting_verifier,
            signing_threshold: msg.signing_threshold,
            service_name: msg.service_name,
            chain_name: msg
                .chain_name
                .parse()
                .map_err(|_| ContractError::InvalidChainName)?,
            verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
            encoder: msg.encoder,
            key_type: msg.key_type,
            domain_separator: msg.domain_separator,
        })
    }
}
