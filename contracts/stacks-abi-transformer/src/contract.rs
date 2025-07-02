use axelar_wasm_std::FnExt;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

mod migrations;
mod query;
mod its_clarity_bytes_to_hub_message;
mod its_hub_message_to_clarity_bytes;

pub use migrations::{migrate, MigrateMsg};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    _deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::FromBytes { .. } => {
            unimplemented!()
            // TODO: Test this
            // to_json_binary(&query::clarity_bytes_to_hub_message(payload)?)
        }
        QueryMsg::ToBytes { message } => {
            to_json_binary(&query::hub_message_to_clarity_bytes(message)?)
        }
    }?
    .then(Ok)
}

#[cfg(test)]
mod tests {
    use crate::contract::{instantiate, query};
    use crate::msg::{InstantiateMsg, QueryMsg};
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Empty, HexBinary, OwnedDeps};
    use interchain_token_service::HubMessage;

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("admin"), &[]),
            InstantiateMsg {},
        )
        .unwrap();

        deps
    }

    #[test]
    fn test_query_to_bytes() {
        let deps = setup();

        let abi_payload =
            HexBinary::from_hex("0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a6d756c7469766572737800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000002c2a94e0c1200b3432349f28ac617a7c9242bbc9d2c9cb46d7fe9ac55510471000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000dbd2fc137a300000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000002077588c18055a483754b68c2378d5e7a6fa4e1d4e0302dadf5db12e7a50a1b5bf0000000000000000000000000000000000000000000000000000000000000014f12372616f9c986355414ba06b3ca954c0a7b0dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let message = HubMessage::abi_decode(abi_payload.as_slice()).unwrap();

        let res = query(deps.as_ref(), mock_env(), QueryMsg::ToBytes { message });

        assert!(res.is_ok());
    }
}
