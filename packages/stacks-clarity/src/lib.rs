// package contains copy-pasted code from https://github.com/stacks-network/stacks-core/tree/2.5.0.0.7/clarity

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::convert::TryInto;
use std::fmt;
use std::ops::Deref;

use crate::errors::{InterpreterResult, RuntimeErrorType};
use crate::common::c32;

mod common;
mod errors;
mod macros;

pub const CONTRACT_MIN_NAME_LENGTH: usize = 1;
pub const CONTRACT_MAX_NAME_LENGTH: usize = 40;
pub const MAX_STRING_LEN: u8 = 128;

lazy_static! {
    pub static ref STANDARD_PRINCIPAL_REGEX_STRING: String =
        "[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{28,41}".into();
    pub static ref CONTRACT_NAME_REGEX_STRING: String = format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
        // NOTE: this is deliberate.  Earlier versions of the node will accept contract principals whose names are up to
        // 128 bytes.  This behavior must be preserved for backwards-compatibility.
        MAX_STRING_LEN - 1
    );
    pub static ref CONTRACT_PRINCIPAL_REGEX_STRING: String = format!(
        r#"{}(\.){}"#,
        *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_NAME_REGEX_STRING
    );
    pub static ref PRINCIPAL_DATA_REGEX_STRING: String = format!(
        "({})|({})",
        *STANDARD_PRINCIPAL_REGEX_STRING, *CONTRACT_PRINCIPAL_REGEX_STRING
    );
    pub static ref CLARITY_NAME_REGEX_STRING: String =
        "^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$".into();
    pub static ref CLARITY_NAME_REGEX: Regex =
    {
        #[allow(clippy::unwrap_used)]
        Regex::new(CLARITY_NAME_REGEX_STRING.as_str()).unwrap()
    };
    pub static ref CONTRACT_NAME_REGEX: Regex =
    {
        #[allow(clippy::unwrap_used)]
        Regex::new(format!("^{}$|^__transient$", CONTRACT_NAME_REGEX_STRING.as_str()).as_str())
            .unwrap()
    };
}

guarded_string!(
    ContractName,
    "ContractName",
    CONTRACT_NAME_REGEX,
    MAX_STRING_LEN,
    RuntimeErrorType,
    RuntimeErrorType::BadNameValue
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct StandardPrincipalData(pub u8, pub [u8; 20]);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct QualifiedContractIdentifier {
    pub issuer: StandardPrincipalData,
    pub name: ContractName,
}

impl QualifiedContractIdentifier {
    pub fn new(issuer: StandardPrincipalData, name: ContractName) -> QualifiedContractIdentifier {
        Self { issuer, name }
    }

    pub fn parse(literal: &str) -> InterpreterResult<QualifiedContractIdentifier> {
        let split: Vec<_> = literal.splitn(2, '.').collect();
        if split.len() != 2 {
            return Err(RuntimeErrorType::ParseError(
                "Invalid principal literal: expected a `.` in a qualified contract name"
                    .to_string(),
            )
            .into());
        }
        let sender = PrincipalData::parse_standard_principal(split[0])?;
        let name = split[1].to_string().try_into()?;
        Ok(QualifiedContractIdentifier::new(sender, name))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PrincipalData {
    Standard(StandardPrincipalData),
    Contract(QualifiedContractIdentifier),
}

impl PrincipalData {
    pub fn parse(literal: &str) -> InterpreterResult<PrincipalData> {
        // be permissive about leading single-quote
        let literal = literal.strip_prefix('\'').unwrap_or(literal);

        if literal.contains('.') {
            PrincipalData::parse_qualified_contract_principal(literal)
        } else {
            PrincipalData::parse_standard_principal(literal).map(PrincipalData::from)
        }
    }

    pub fn parse_qualified_contract_principal(literal: &str) -> InterpreterResult<PrincipalData> {
        let contract_id = QualifiedContractIdentifier::parse(literal)?;
        Ok(PrincipalData::Contract(contract_id))
    }

    pub fn parse_standard_principal(literal: &str) -> InterpreterResult<StandardPrincipalData> {
        let (version, data) = c32::c32_address_decode(literal).map_err(|x| {
            RuntimeErrorType::ParseError(format!("Invalid principal literal: {}", x))
        })?;
        if data.len() != 20 {
            return Err(RuntimeErrorType::ParseError(
                "Invalid principal literal: Expected 20 data bytes.".to_string(),
            )
            .into());
        }
        let mut fixed_data = [0; 20];
        fixed_data.copy_from_slice(&data[..20]);
        Ok(StandardPrincipalData(version, fixed_data))
    }
}

impl From<StandardPrincipalData> for PrincipalData {
    fn from(p: StandardPrincipalData) -> Self {
        PrincipalData::Standard(p)
    }
}
