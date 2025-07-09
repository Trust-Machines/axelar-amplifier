#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use its_msg_translator_api::QueryMsg;

use crate::error::ContractError;

mod decode;
mod encode;
mod migrations;
mod query;

pub use migrations::{migrate, MigrateMsg};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::FromBytes { payload } => query::bytes_to_hub_message_query(payload),
        QueryMsg::ToBytes { message } => query::hub_message_to_bytes_query(message),
    }
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, HexBinary};
    use interchain_token_service_std::{DeployInterchainToken, HubMessage, Message, TokenId};
    use router_api::ChainNameRaw;

    use super::*;

    #[test]
    fn instantiate_should_succeed() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = Empty {};

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages.len(), 0);

        let version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(version.contract, CONTRACT_NAME);
        assert_eq!(version.version, CONTRACT_VERSION);
    }

    #[test]
    fn query_receive_from_hub_message() {
        let deps = mock_dependencies();
        let env = mock_env();

        let hub_message = HubMessage::ReceiveFromHub {
            source_chain: ChainNameRaw::try_from("ethereum").unwrap(),
            message: Message::DeployInterchainToken(DeployInterchainToken {
                token_id: TokenId::new([2u8; 32]),
                name: nonempty::String::try_from("Test Token".to_string()).unwrap(),
                symbol: nonempty::String::try_from("TEST".to_string()).unwrap(),
                decimals: 18,
                minter: Some(nonempty::HexBinary::try_from(vec![0xaa, 0xbb, 0xcc]).unwrap()),
            }),
        };

        let to_bytes_msg = QueryMsg::ToBytes {
            message: hub_message.clone(),
        };
        let bytes_result = query(deps.as_ref(), env.clone(), to_bytes_msg);

        assert!(bytes_result.is_ok());
    }

    #[test]
    fn query_from_bytes_invalid_payload() {
        let deps = mock_dependencies();
        let env = mock_env();

        let invalid_payload = HexBinary::from_hex("deadbeef").unwrap();
        let from_bytes_msg = QueryMsg::FromBytes {
            payload: invalid_payload,
        };

        let err = query(deps.as_ref(), env, from_bytes_msg).unwrap_err();
        assert_eq!(err, ContractError::InvalidPayload {});
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let info = message_info(&api.addr_make("sender"), &[]);
        let instantiate_msg = Empty {};

        assert_ok!(instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            instantiate_msg
        ));

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }
}
