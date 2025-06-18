use axelar_wasm_std::{address, permission_control};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response};
use error_stack::ResultExt;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};

pub mod execute;
mod migrations;
mod query;
mod reply;

pub use migrations::{migrate, MigrateMsg};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        gateway: address::validate_cosmwasm_address(deps.api, &msg.gateway_address)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig_address)?,
        coordinator: address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?,
        service_registry: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        voting_verifier: address::validate_cosmwasm_address(
            deps.api,
            &msg.voting_verifier_address,
        )?,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg.chain_name.parse()?,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        encoder: msg.encoder,
        key_type: msg.key_type,
        domain_separator: msg.domain_separator,
        its_hub_address: address::validate_cosmwasm_address(deps.api, &msg.its_hub_address)?,
        stacks_abi_transformer: address::validate_cosmwasm_address(
            deps.api,
            &msg.stacks_abi_transformer,
        )?,
        axelar_chain_name: msg.axelar_chain_name.parse()?,
    };
    CONFIG.save(deps.storage, &config)?;

    permission_control::set_admin(
        deps.storage,
        &address::validate_cosmwasm_address(deps.api, &msg.admin_address)?,
    )?;
    permission_control::set_governance(
        deps.storage,
        &address::validate_cosmwasm_address(deps.api, &msg.governance_address)?,
    )?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::ConstructProof(_) => unimplemented!(),
        ExecuteMsg::ConstructProofWithPayload(messages) => {
            Ok(execute::construct_proof_with_payload(deps, messages)?)
        }
        ExecuteMsg::UpdateVerifierSet {} => Ok(execute::update_verifier_set(deps, env)?),
        ExecuteMsg::ConfirmVerifierSet {} => Ok(execute::confirm_verifier_set(deps, info.sender)?),
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => Ok(execute::update_signing_threshold(
            deps,
            new_signing_threshold,
        )?),
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            Ok(execute::update_admin(deps, new_admin_address)?)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::proof(deps, multisig_session_id)?),
        QueryMsg::CurrentVerifierSet {} => to_json_binary(&query::current_verifier_set(deps)?),
        QueryMsg::NextVerifierSet {} => to_json_binary(&query::next_verifier_set(deps)?),
    }
    .change_context(ContractError::SerializeResponse)
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::nonempty::HexBinary;
    use axelar_wasm_std::permission_control::Permission;
    use axelar_wasm_std::{permission_control, MajorityThreshold, Threshold, VerificationStatus};
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        from_json, Addr, Empty, Fraction, OwnedDeps, SubMsgResponse, SubMsgResult, Uint128, Uint64,
    };
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use multisig_prover_api::encoding::Encoder;
    use prost::Message;
    use router_api::CrossChainId;

    use super::*;
    use crate::contract::execute::should_update_verifier_set;
    use crate::msg::{MessageIdWithPayload, ProofResponse, ProofStatus, VerifierSetResponse};
    use crate::test::test_data::{self, TestOperator};
    use crate::test::test_utils::{
        mock_querier_handler, mock_querier_handler_its_hub, ADMIN, COORDINATOR_ADDRESS,
        GATEWAY_ADDRESS, GOVERNANCE, ITS_HUB_ADDRESS, MULTISIG_ADDRESS, SERVICE_NAME,
        SERVICE_REGISTRY_ADDRESS, STACKS_ABI_TRANSFORMER, VOTING_VERIFIER_ADDRESS,
    };

    const RELAYER: &str = "relayer";
    const MULTISIG_SESSION_ID: Uint64 = Uint64::one();

    pub fn setup_test_case() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            InstantiateMsg {
                admin_address: api.addr_make(ADMIN).to_string(),
                governance_address: api.addr_make(GOVERNANCE).to_string(),
                gateway_address: api.addr_make(GATEWAY_ADDRESS).to_string(),
                multisig_address: api.addr_make(MULTISIG_ADDRESS).to_string(),
                coordinator_address: api.addr_make(COORDINATOR_ADDRESS).to_string(),
                service_registry_address: api.addr_make(SERVICE_REGISTRY_ADDRESS).to_string(),
                voting_verifier_address: api.addr_make(VOTING_VERIFIER_ADDRESS).to_string(),
                signing_threshold: test_data::threshold(),
                service_name: SERVICE_NAME.to_string(),
                chain_name: "ganache-0".to_string(),
                verifier_set_diff_threshold: 0,
                encoder: Encoder::Abi,
                key_type: multisig::key::KeyType::Ecdsa,
                domain_separator: [0; 32],
                its_hub_address: api.addr_make(ITS_HUB_ADDRESS).to_string(),
                stacks_abi_transformer: api.addr_make(STACKS_ABI_TRANSFORMER).to_string(),
                axelar_chain_name: "axelar".to_string(),
            },
        )
        .unwrap();

        deps
    }

    pub fn setup_test_case_its_hub(nb_messages: usize) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;

        let its_hub_address = api.addr_make(ITS_HUB_ADDRESS).to_string();
        let stacks_abi_transformer = api.addr_make(STACKS_ABI_TRANSFORMER).to_string();

        deps.querier.update_wasm(mock_querier_handler_its_hub(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
            its_hub_address.clone(),
            nb_messages,
        ));

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            InstantiateMsg {
                admin_address: api.addr_make(ADMIN).to_string(),
                governance_address: api.addr_make(GOVERNANCE).to_string(),
                gateway_address: api.addr_make(GATEWAY_ADDRESS).to_string(),
                multisig_address: api.addr_make(MULTISIG_ADDRESS).to_string(),
                coordinator_address: api.addr_make(COORDINATOR_ADDRESS).to_string(),
                service_registry_address: api.addr_make(SERVICE_REGISTRY_ADDRESS).to_string(),
                voting_verifier_address: api.addr_make(VOTING_VERIFIER_ADDRESS).to_string(),
                signing_threshold: test_data::threshold(),
                service_name: SERVICE_NAME.to_string(),
                chain_name: "ganache-0".to_string(),
                verifier_set_diff_threshold: 0,
                encoder: Encoder::Abi,
                key_type: multisig::key::KeyType::Ecdsa,
                domain_separator: [0; 32],
                its_hub_address,
                stacks_abi_transformer,
                axelar_chain_name: "axelar".to_string(),
            },
        )
        .unwrap();

        deps
    }

    fn execute_update_verifier_set(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateVerifierSet {};
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(ADMIN), &[]),
            msg,
        )
    }

    fn confirm_verifier_set(
        deps: DepsMut,
        sender: Addr,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::ConfirmVerifierSet {};
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_update_signing_threshold(
        deps: DepsMut,
        sender: Addr,
        new_signing_threshold: MajorityThreshold,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        };
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_update_admin(
        deps: DepsMut,
        sender: Addr,
        new_admin_address: String,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateAdmin { new_admin_address };
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_construct_proof_with_payload(
        deps: DepsMut,
        message_id: CrossChainId,
        payload: HexBinary,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::ConstructProofWithPayload(vec![MessageIdWithPayload {
            message_id,
            payload: payload.into(),
        }]);
        execute(
            deps,
            mock_env(),
            message_info(&Addr::unchecked(RELAYER), &[]),
            msg,
        )
    }

    fn reply_construct_proof(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();

        #[allow(deprecated)]
        // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
        let response = SubMsgResponse {
            events: vec![],
            // the reply data gets protobuf encoded when moving through the wasm module. We need to emulate this behaviour in tests as well
            data: Some(
                prost::bytes::Bytes::from(session_id.to_vec())
                    .encode_to_vec()
                    .into(),
            ),
            msg_responses: vec![],
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
                payload: vec![].into(),
                gas_used: 0,
            },
        )
    }

    fn query_proof(
        deps: Deps,
        multisig_session_id: Option<Uint64>,
    ) -> Result<ProofResponse, axelar_wasm_std::error::ContractError> {
        let multisig_session_id = match multisig_session_id {
            Some(id) => id,
            None => MULTISIG_SESSION_ID,
        };

        query(
            deps,
            mock_env(),
            QueryMsg::Proof {
                multisig_session_id,
            },
        )
        .map(|res| from_json(res).unwrap())
    }

    fn query_verifier_set(
        deps: Deps,
    ) -> Result<Option<VerifierSetResponse>, axelar_wasm_std::error::ContractError> {
        query(deps, mock_env(), QueryMsg::CurrentVerifierSet {}).map(|res| from_json(res).unwrap())
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = setup_test_case();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let api = MockApi::default();
        let instantiator = api.addr_make("instantiator");
        let admin = api.addr_make("admin");
        let governance = api.addr_make("governance");
        let gateway_address = api.addr_make("gateway_address");
        let multisig_address = api.addr_make("multisig_address");
        let coordinator_address = api.addr_make("coordinator_address");
        let service_registry_address = api.addr_make("service_registry_address");
        let voting_verifier_address = api.addr_make("voting_verifier");
        let its_hub_address = api.addr_make("its_hub");
        let stacks_abi_transformer = api.addr_make("stacks_abi_transformer");
        let signing_threshold = Threshold::try_from((
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let service_name = "service_name";
        for encoding in [Encoder::Abi, Encoder::Bcs, Encoder::Stacks] {
            let mut deps = mock_dependencies();
            let info = message_info(&instantiator, &[]);
            let env = mock_env();

            let msg = InstantiateMsg {
                admin_address: admin.to_string(),
                governance_address: governance.to_string(),
                gateway_address: gateway_address.to_string(),
                multisig_address: multisig_address.to_string(),
                coordinator_address: coordinator_address.to_string(),
                voting_verifier_address: voting_verifier_address.to_string(),
                service_registry_address: service_registry_address.to_string(),
                signing_threshold,
                service_name: service_name.to_string(),
                chain_name: "Ethereum".to_string(),
                verifier_set_diff_threshold: 0,
                encoder: encoding,
                key_type: multisig::key::KeyType::Ecdsa,
                domain_separator: [0; 32],
                its_hub_address: its_hub_address.to_string(),
                stacks_abi_transformer: stacks_abi_transformer.to_string(),
                axelar_chain_name: "axelar".to_string(),
            };

            let res = instantiate(deps.as_mut(), env, info, msg);

            assert!(res.is_ok());
            let res = res.unwrap();

            assert_eq!(res.messages.len(), 0);

            let config = CONFIG.load(deps.as_ref().storage).unwrap();
            assert_eq!(config.gateway, gateway_address);
            assert_eq!(config.multisig, multisig_address);
            assert_eq!(config.service_registry, service_registry_address);
            assert_eq!(config.signing_threshold, signing_threshold);
            assert_eq!(config.service_name, service_name);
            assert_eq!(config.encoder, encoding);

            assert_eq!(
                permission_control::sender_role(deps.as_ref().storage, &admin).unwrap(),
                Permission::Admin.into()
            );

            assert_eq!(
                permission_control::sender_role(deps.as_ref().storage, &governance).unwrap(),
                Permission::Governance.into()
            );
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn test_operators_to_verifier_set(operators: Vec<TestOperator>, nonce: u64) -> VerifierSet {
        let total_weight: Uint128 = operators
            .iter()
            .fold(Uint128::zero(), |acc, x| acc + x.weight);
        let quorum = total_weight.mul_ceil(test_data::threshold());
        VerifierSet {
            signers: operators
                .into_iter()
                .map(|op| {
                    (
                        op.address.clone().to_string(),
                        Signer {
                            address: op.address,
                            pub_key: op.pub_key,
                            weight: op.weight,
                        },
                    )
                })
                .collect(),
            threshold: quorum,
            created_at: nonce,
        }
    }

    #[test]
    fn test_update_verifier_set_fresh() {
        let mut deps = setup_test_case();
        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());
        assert!(verifier_set.unwrap().is_none());
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set.into());
    }

    #[test]
    fn test_update_verifier_set_from_non_admin_or_governance_should_fail() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("some random address"), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                permission_control::Error::PermissionDenied {
                    expected: Permission::Elevated.into(),
                    actual: Permission::NoPrivilege.into()
                }
            )
            .to_string()
        );
    }

    #[test]
    fn test_update_verifier_set_from_governance_should_succeed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_from_admin_should_succeed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_remove_one() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set.into());
    }

    #[test]
    fn test_update_verifier_set_add_one() {
        let mut deps = setup_test_case();

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(new_verifier_set, mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set.into());
    }

    #[test]
    fn test_update_verifier_set_change_public_key() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        let (a, b) = (
            new_verifier_set[0].pub_key.clone(),
            new_verifier_set[1].pub_key.clone(),
        );
        new_verifier_set[0].pub_key = b;
        new_verifier_set[1].pub_key = a;

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::SucceededOnSourceChain,
        ));
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set.into());
    }

    #[test]
    fn test_update_verifier_set_unchanged() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetUnchanged)
                .to_string()
        );
    }

    #[test]
    fn test_confirm_verifier_set_unconfirmed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let res = confirm_verifier_set(deps.as_mut(), api.addr_make("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetNotConfirmed)
                .to_string()
        );
    }

    #[test]
    fn test_confirm_verifier_set_wrong_set() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));
        execute_update_verifier_set(deps.as_mut()).unwrap();

        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));

        let res = confirm_verifier_set(deps.as_mut(), api.addr_make("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetNotConfirmed)
                .to_string()
        );
    }

    #[test]
    fn confirm_verifier_no_update_in_progress_should_fail() {
        let mut deps = setup_test_case();
        let api = deps.api;

        let res = confirm_verifier_set(deps.as_mut(), api.addr_make("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::NoVerifierSetToConfirm)
                .to_string()
        );
    }

    #[test]
    fn test_query_proof_with_payload() {
        let mut deps = setup_test_case_its_hub(1);
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let payload =
            HexBinary::try_from(cosmwasm_std::HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a6d756c7469766572737800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000002c2a94e0c1200b3432349f28ac617a7c9242bbc9d2c9cb46d7fe9ac55510471000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002077588c18055a483754b68c2378d5e7a6fa4e1d4e0302dadf5db12e7a50a1b5bf0000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        execute_construct_proof_with_payload(
            deps.as_mut(),
            CrossChainId::new(
                "axelar",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            payload.clone(),
        )
        .unwrap();
        reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig

        let res = query_proof(deps.as_ref(), None).unwrap();

        assert_eq!(res.multisig_session_id, MULTISIG_SESSION_ID);
        assert_eq!(res.message_ids.len(), 1);
        match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, cosmwasm_std::HexBinary::from_hex("64f1d85a000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002600000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000a4f10f76b86e01b98daf66a3d02a65e14adb0767ed9305978fd027c60310c48f29710503a2c9878a57deda4c99b87e504475595e00000000000000000000000000000000000000000000000000000000000000066178656c6172000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000443078666638323263383838303738353966663232366235386532346632343937346137306630346239343432353031616533386664363635623363363866333833342d30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043636f736d7761736d316434786e667578357276386e36666664777a66677270346338346e366d386b64763373796570796c63753733786c663939717773776a6b726a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000050000000000000000000000004ef5c8d81b6417fa80c320b5fc1d3900506dff5400000000000000000000000000000000000000000000000000000000000000010000000000000000000000006c51eec96bf0a8ec799cdd0bbcb4512f8334afe800000000000000000000000000000000000000000000000000000000000000010000000000000000000000007aeb4eebf1e8dcde3016d4e1dca52b4538cf7aaf0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c5b95c99d883c3204cfc2e73669ce3aa7437f4a60000000000000000000000000000000000000000000000000000000000000001000000000000000000000000ffffde829096dfe8b833997e939865ff57422ea900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000004172b242d7247fc31d14ce82b32f3ea911808f6f600f362150f9904c974315942927c25f9388cecdbbb0b3723164eea92206775870cd28e1ffd8f1cb9655fb3c4a1b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004186909155a6ba27f173edf15d283da6a0019fb6afe6b223ca68530464813f468f356e70788faf6d1d9ff7bfcfd9021b560d72408bef4c86c66e3a94b9dee0a34a1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000419b2d986652fdebe67554f1b33ae6161b205ea84e0dacb07ffde0889791bcab2e5be3b8229eae01f2c22805c87f15cb7f9642e9cba951489edcac5d12ace399391b00000000000000000000000000000000000000000000000000000000000000").unwrap());
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }

    #[test]
    fn test_construct_proof_with_payload() {
        let mut deps = setup_test_case_its_hub(1);
        execute_update_verifier_set(deps.as_mut()).unwrap();

        // Interchain transfer payload
        let payload =
            HexBinary::try_from(cosmwasm_std::HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a6d756c7469766572737800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000002c2a94e0c1200b3432349f28ac617a7c9242bbc9d2c9cb46d7fe9ac55510471000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002077588c18055a483754b68c2378d5e7a6fa4e1d4e0302dadf5db12e7a50a1b5bf0000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        execute_construct_proof_with_payload(
            deps.as_mut(),
            CrossChainId::new(
                "axelar",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            payload.clone(),
        )
        .unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());

        // test case where there is an existing payload
        execute_construct_proof_with_payload(
            deps.as_mut(),
            CrossChainId::new(
                "axelar",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            payload,
        )
        .unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig
        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_construct_proof_with_payload_multiple() {
        let mut deps = setup_test_case_its_hub(2);
        execute_update_verifier_set(deps.as_mut()).unwrap();

        // Interchain transfer payload
        let payload =
            HexBinary::try_from(cosmwasm_std::HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a6d756c7469766572737800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000002c2a94e0c1200b3432349f28ac617a7c9242bbc9d2c9cb46d7fe9ac55510471000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002077588c18055a483754b68c2378d5e7a6fa4e1d4e0302dadf5db12e7a50a1b5bf0000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();

        let msg = ExecuteMsg::ConstructProofWithPayload(vec![
            MessageIdWithPayload {
                message_id: CrossChainId::new(
                    "axelar",
                    "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
                )
                .unwrap(),
                payload: payload.clone().into(),
            },
            MessageIdWithPayload {
                message_id: CrossChainId::new(
                    "axelar",
                    "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-1", // other message id
                )
                .unwrap(),
                payload: payload.clone().into(),
            },
        ]);
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&Addr::unchecked(RELAYER), &[]),
            msg,
        )
        .unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_construct_proof_with_payload_non_its_hub_messages_should_fail() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        let payload =
            HexBinary::try_from(cosmwasm_std::HexBinary::from_hex("00").unwrap()).unwrap();

        let res = execute_construct_proof_with_payload(
            deps.as_mut(),
            CrossChainId::new(
                "ganache-1",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            payload,
        );

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidMessage).to_string()
        );
    }

    #[test]
    fn test_construct_proof_with_payload_wrong_payload() {
        let mut deps = setup_test_case_its_hub(1);
        execute_update_verifier_set(deps.as_mut()).unwrap();

        let payload =
            HexBinary::try_from(cosmwasm_std::HexBinary::from_hex("00").unwrap()).unwrap();

        let res = execute_construct_proof_with_payload(
            deps.as_mut(),
            CrossChainId::new(
                "axelar",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            payload,
        );

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidPayload).to_string()
        );
    }

    #[test]
    fn test_construct_proof_with_payload_no_verifier_set() {
        let mut deps = setup_test_case_its_hub(1);

        let payload =
            HexBinary::try_from(cosmwasm_std::HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a6d756c7469766572737800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000002c2a94e0c1200b3432349f28ac617a7c9242bbc9d2c9cb46d7fe9ac55510471000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002077588c18055a483754b68c2378d5e7a6fa4e1d4e0302dadf5db12e7a50a1b5bf0000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        let res = execute_construct_proof_with_payload(
            deps.as_mut(),
            CrossChainId::new(
                "axelar",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            payload,
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::NoVerifierSet).to_string()
        );
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            api.addr_make("random"),
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let governance = deps.api.addr_make(GOVERNANCE);
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            governance,
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_ok());
    }

    /// Calls update_signing_threshold, increasing the threshold by one.
    /// Returns (initial threshold, new threshold)
    fn update_signing_threshold_increase_by_one(deps: DepsMut) -> (Uint128, Uint128) {
        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
        let initial_threshold = verifier_set.threshold;
        let total_weight = verifier_set
            .signers
            .iter()
            .fold(Uint128::zero(), |acc, signer| {
                acc.checked_add(signer.1.weight).unwrap()
            });
        let new_threshold = initial_threshold.checked_add(Uint128::one()).unwrap();

        let governance = MockApi::default().addr_make(GOVERNANCE);
        execute_update_signing_threshold(
            deps,
            governance.clone(),
            Threshold::try_from((
                Uint64::try_from(new_threshold).unwrap(),
                Uint64::try_from(total_weight).unwrap(),
            ))
            .unwrap()
            .try_into()
            .unwrap(),
        )
        .unwrap();
        (initial_threshold, new_threshold)
    }

    #[test]
    fn update_signing_threshold_should_not_change_current_threshold() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
        assert_eq!(verifier_set.threshold, initial_threshold);
    }

    #[test]
    fn update_signing_threshold_should_change_future_threshold() {
        let mut deps = setup_test_case();
        let api = deps.api;

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let governance = api.addr_make(GOVERNANCE);
        confirm_verifier_set(deps.as_mut(), governance).unwrap();

        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
        assert_eq!(verifier_set.threshold, new_threshold);
    }

    #[test]
    fn should_confirm_new_threshold() {
        let mut deps = setup_test_case();
        let api = deps.api;

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let res = confirm_verifier_set(deps.as_mut(), api.addr_make("relayer"));
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
        assert_eq!(verifier_set.threshold, new_threshold);
    }

    #[test]
    fn should_update_verifier_set_no_change() {
        let verifier_set = test_data::new_verifier_set();
        assert!(!should_update_verifier_set(&verifier_set, &verifier_set, 0));
    }

    #[test]
    fn should_update_verifier_set_one_more() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_less() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &new_verifier_set,
            &verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_more_higher_threshold() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(!should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            1
        ));
    }

    #[test]
    fn should_update_verifier_set_diff_pub_key() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        let (first_key, first) = new_verifier_set.signers.pop_first().unwrap();
        let (last_key, last) = new_verifier_set.signers.pop_last().unwrap();
        new_verifier_set.signers.insert(
            last_key,
            Signer {
                pub_key: first.clone().pub_key,
                ..last.clone()
            },
        );
        new_verifier_set.signers.insert(
            first_key,
            Signer {
                pub_key: last.pub_key,
                ..first
            },
        );
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_admin(
            deps.as_mut(),
            api.addr_make("unauthorized"),
            "new admin".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let new_admin = api.addr_make("new admin");

        let res = execute_update_admin(
            deps.as_mut(),
            api.addr_make(GOVERNANCE),
            new_admin.to_string(),
        );
        assert!(res.is_ok(), "{:?}", res);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &new_admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &api.addr_make(ADMIN)).unwrap(),
            Permission::NoPrivilege.into()
        );
    }
}
