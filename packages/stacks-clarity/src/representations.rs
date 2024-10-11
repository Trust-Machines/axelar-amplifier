use crate::errors::RuntimeErrorType;
use crate::guarded_string;
use lazy_static::lazy_static;
use regex::Regex;
use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use serde::{Serialize, Deserialize};

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
    ClarityName,
    "ClarityName",
    CLARITY_NAME_REGEX,
    MAX_STRING_LEN,
    RuntimeErrorType,
    RuntimeErrorType::BadNameValue
);

guarded_string!(
    ContractName,
    "ContractName",
    CONTRACT_NAME_REGEX,
    MAX_STRING_LEN,
    RuntimeErrorType,
    RuntimeErrorType::BadNameValue
);
