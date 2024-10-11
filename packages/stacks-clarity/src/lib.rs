// package contains copy-pasted code from https://github.com/stacks-network/stacks-core/tree/2.5.0.0.7/clarity

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ops::Deref;

use crate::common::address::c32;
use crate::errors::{InterpreterError, InterpreterResult, RuntimeErrorType};
use crate::representations::{ClarityName, ContractName};
use crate::signatures::BufferLength;

pub mod common;
pub mod errors;
pub mod macros;
pub mod representations;
pub mod serialization;
mod signatures;

pub const MAX_VALUE_SIZE: u32 = 1024 * 1024; // 1MB

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

impl From<QualifiedContractIdentifier> for PrincipalData {
    fn from(principal: QualifiedContractIdentifier) -> Self {
        PrincipalData::Contract(principal)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Value {
    // Int(i128),
    // UInt(u128),
    // Bool(bool),
    Sequence(SequenceData),
    // Principal(PrincipalData),
    Tuple(TupleData),
    // Optional(OptionalData),
    // Response(ResponseData),
    // CallableContract(CallableData),
    // NOTE: any new value variants which may contain _other values_ (i.e.,
    //  compound values like `Optional`, `Tuple`, `Response`, or `Sequence(List)`)
    //  must be handled in the value sanitization routine!
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SequenceData {
    Buffer(BuffData),
    List(ListData),
    String(CharType),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuffData {
    pub data: Vec<u8>,
}

impl BuffData {
    pub fn len(&self) -> InterpreterResult<BufferLength> {
        self.data
            .len()
            .try_into()
            .map_err(|_| InterpreterError::Expect("Data length should be valid".into()).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListData {
    pub data: Vec<Value>,
}

impl ListData {
    pub fn len(&self) -> InterpreterResult<u32> {
        self.data
            .len()
            .try_into()
            .map_err(|_| InterpreterError::Expect("Data length should be valid".into()).into())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CharType {
    UTF8(UTF8Data),
    ASCII(ASCIIData),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UTF8Data {
    pub data: Vec<Vec<u8>>,
}

impl UTF8Data {
    pub fn len(&self) -> InterpreterResult<BufferLength> {
        self.data
            .len()
            .try_into()
            .map_err(|_| InterpreterError::Expect("Data length should be valid".into()).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ASCIIData {
    pub data: Vec<u8>,
}

impl ASCIIData {
    pub fn len(&self) -> InterpreterResult<BufferLength> {
        self.data
            .len()
            .try_into()
            .map_err(|_| InterpreterError::Expect("Data length should be valid".into()).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleData {
    pub data_map: BTreeMap<ClarityName, Value>,
}
