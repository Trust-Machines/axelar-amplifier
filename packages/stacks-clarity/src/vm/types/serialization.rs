use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::common::codec::{Error as codec_error, StacksMessageCodec};
use crate::define_u8_enum;
use crate::vm::errors::IncomparableError;
use crate::vm::representations::{ClarityName, ContractName, MAX_STRING_LEN};
use crate::vm::types::{
    CallableData, OptionalData, PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
    Value,
};

#[derive(Debug, PartialEq)]
pub enum SerializationError {
    IOError(IncomparableError<std::io::Error>),
    // BadTypeError(CheckErrors),
    DeserializationError(String),
    // DeserializeExpected(TypeSignature),
    LeftoverBytesInDeserialization,
    SerializationError(String),
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SerializationError::IOError(e) => {
                write!(f, "Serialization error caused by IO: {}", e.err)
            }
            // SerializationError::BadTypeError(e) => {
            //     write!(f, "Deserialization error, bad type, caused by: {}", e)
            // }
            SerializationError::DeserializationError(e) => {
                write!(f, "Deserialization error: {}", e)
            }
            SerializationError::SerializationError(e) => {
                write!(f, "Serialization error: {}", e)
            }
            // SerializationError::DeserializeExpected(e) => write!(
            //     f,
            //     "Deserialization expected the type of the input to be: {}",
            //     e
            // ),
            SerializationError::LeftoverBytesInDeserialization => {
                write!(f, "Deserialization error: bytes left over in buffer")
            }
        }
    }
}

impl From<std::io::Error> for SerializationError {
    fn from(err: std::io::Error) -> Self {
        SerializationError::IOError(IncomparableError { err })
    }
}

impl From<&str> for SerializationError {
    fn from(e: &str) -> Self {
        SerializationError::DeserializationError(e.into())
    }
}

define_u8_enum!(TypePrefix {
    Int = 0,
    UInt = 1,
    Buffer = 2,
    BoolTrue = 3,
    BoolFalse = 4,
    PrincipalStandard = 5,
    PrincipalContract = 6,
    ResponseOk = 7,
    ResponseErr = 8,
    OptionalNone = 9,
    OptionalSome = 10,
    List = 11,
    Tuple = 12,
    StringASCII = 13,
    StringUTF8 = 14
});

impl From<&PrincipalData> for TypePrefix {
    fn from(v: &PrincipalData) -> TypePrefix {
        use super::PrincipalData::*;
        match v {
            Standard(_) => TypePrefix::PrincipalStandard,
            Contract(_) => TypePrefix::PrincipalContract,
        }
    }
}

impl From<&Value> for TypePrefix {
    fn from(v: &Value) -> TypePrefix {
        use super::CharType;
        use super::SequenceData::*;
        use super::Value::*;

        match v {
            Int(_) => TypePrefix::Int,
            UInt(_) => TypePrefix::UInt,
            Bool(value) => {
                if *value {
                    TypePrefix::BoolTrue
                } else {
                    TypePrefix::BoolFalse
                }
            }
            Principal(p) => TypePrefix::from(p),
            Response(response) => {
                if response.committed {
                    TypePrefix::ResponseOk
                } else {
                    TypePrefix::ResponseErr
                }
            }
            Optional(OptionalData { data: None }) => TypePrefix::OptionalNone,
            Optional(OptionalData { data: Some(_) }) => TypePrefix::OptionalSome,
            Tuple(_) => TypePrefix::Tuple,
            Sequence(Buffer(_)) => TypePrefix::Buffer,
            Sequence(List(_)) => TypePrefix::List,
            Sequence(String(CharType::ASCII(_))) => TypePrefix::StringASCII,
            Sequence(String(CharType::UTF8(_))) => TypePrefix::StringUTF8,
            &CallableContract(_) => TypePrefix::PrincipalContract,
        }
    }
}

impl PrincipalData {
    fn inner_consensus_serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[TypePrefix::from(self) as u8])?;
        match self {
            PrincipalData::Standard(p) => p.serialize_write(w),
            PrincipalData::Contract(contract_identifier) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)
            }
        }
    }

    pub fn inner_consensus_deserialize<R: Read>(
        r: &mut R,
    ) -> Result<PrincipalData, SerializationError> {
        let mut header = [0];
        r.read_exact(&mut header)?;

        let prefix = TypePrefix::from_u8(header[0]).ok_or("Bad principal prefix")?;

        match prefix {
            TypePrefix::PrincipalStandard => {
                StandardPrincipalData::deserialize_read(r).map(PrincipalData::from)
            }
            TypePrefix::PrincipalContract => {
                let issuer = StandardPrincipalData::deserialize_read(r)?;
                let name = ContractName::deserialize_read(r)?;
                Ok(PrincipalData::from(QualifiedContractIdentifier {
                    issuer,
                    name,
                }))
            }
            _ => Err("Bad principal prefix".into()),
        }
    }
}

impl StacksMessageCodec for PrincipalData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.inner_consensus_serialize(fd)
            .map_err(codec_error::WriteError)
    }
}

trait ClarityValueSerializable<T: std::marker::Sized> {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
}

// In the official library, this is part of ClarityValueSerializable, but we only need it form Decoding Principals
trait ClarityValueDeserializable<T: std::marker::Sized> {
    fn deserialize_read<R: Read>(r: &mut R) -> Result<T, SerializationError>;
}

impl ClarityValueSerializable<StandardPrincipalData> for StandardPrincipalData {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[self.0])?;
        w.write_all(&self.1)
    }
}

impl ClarityValueDeserializable<StandardPrincipalData> for StandardPrincipalData {
    fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, SerializationError> {
        let mut version = [0; 1];
        let mut data = [0; 20];
        r.read_exact(&mut version)?;
        r.read_exact(&mut data)?;
        Ok(StandardPrincipalData(version[0], data))
    }
}

macro_rules! serialize_guarded_string {
    ($Name:ident) => {
        impl ClarityValueSerializable<$Name> for $Name {
            fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
                w.write_all(&self.len().to_be_bytes())?;
                // self.as_bytes() is always len bytes, because this is only used for GuardedStrings
                //   which are a subset of ASCII
                w.write_all(self.as_str().as_bytes())
            }
        }
    };
}

// In the official implementation, this is part of the serialize_guarded_string macro, but we only need it for decoding principal
macro_rules! deserialize_guarded_string {
    ($Name:ident) => {
        impl ClarityValueDeserializable<$Name> for $Name {
            fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, SerializationError> {
                let mut len = [0; 1];
                r.read_exact(&mut len)?;
                let len = u8::from_be_bytes(len);
                if len > MAX_STRING_LEN {
                    return Err(SerializationError::DeserializationError(
                        "String too long".to_string(),
                    ));
                }

                let mut data = vec![0; len as usize];
                r.read_exact(&mut data)?;

                String::from_utf8(data)
                    .map_err(|_| "Non-UTF8 string data".into())
                    .and_then(|x| $Name::try_from(x).map_err(|_| "Illegal Clarity string".into()))
            }
        }
    };
}

serialize_guarded_string!(ClarityName);
serialize_guarded_string!(ContractName);

deserialize_guarded_string!(ContractName);

impl Value {
    pub fn serialize_write<W: Write>(&self, w: &mut W) -> Result<(), SerializationError> {
        use super::CharType::*;
        use super::PrincipalData::*;
        use super::SequenceData::{self, *};
        use super::Value::*;

        w.write_all(&[TypePrefix::from(self) as u8])?;
        match self {
            Int(value) => w.write_all(&value.to_be_bytes())?,
            UInt(value) => w.write_all(&value.to_be_bytes())?,
            Principal(Standard(data)) => data.serialize_write(w)?,
            Principal(Contract(contract_identifier))
            | CallableContract(CallableData {
                contract_identifier,
                trait_identifier: _,
            }) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)?;
            }
            Response(response) => response.data.serialize_write(w)?,
            // // Bool types don't need any more data.
            Bool(_) => {}
            // // None types don't need any more data.
            Optional(OptionalData { data: None }) => {}
            Optional(OptionalData { data: Some(value) }) => {
                value.serialize_write(w)?;
            }
            Sequence(List(data)) => {
                let len_bytes = data
                    .len()
                    .map_err(|e| SerializationError::SerializationError(e.to_string()))?
                    .to_be_bytes();
                w.write_all(&len_bytes)?;
                for item in data.data.iter() {
                    item.serialize_write(w)?;
                }
            }
            Sequence(Buffer(value)) => {
                let len_bytes = u32::from(
                    value
                        .len()
                        .map_err(|e| SerializationError::SerializationError(e.to_string()))?,
                )
                .to_be_bytes();
                w.write_all(&len_bytes)?;
                w.write_all(&value.data)?
            }
            Sequence(SequenceData::String(UTF8(value))) => {
                let total_len: u32 = value.data.iter().fold(0u32, |len, c| len + c.len() as u32);
                w.write_all(&(total_len.to_be_bytes()))?;
                for bytes in value.data.iter() {
                    w.write_all(bytes)?
                }
            }
            Sequence(SequenceData::String(ASCII(value))) => {
                let len_bytes = u32::from(
                    value
                        .len()
                        .map_err(|e| SerializationError::SerializationError(e.to_string()))?,
                )
                .to_be_bytes();
                w.write_all(&len_bytes)?;
                w.write_all(&value.data)?
            }
            Tuple(data) => {
                let len_bytes = u32::try_from(data.data_map.len())
                    .map_err(|e| SerializationError::SerializationError(e.to_string()))?
                    .to_be_bytes();
                w.write_all(&len_bytes)?;
                for (key, value) in data.data_map.iter() {
                    key.serialize_write(w)?;
                    value.serialize_write(w)?;
                }
            }
        };

        Ok(())
    }
}

impl StacksMessageCodec for Value {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.serialize_write(fd).map_err(|e| match e {
            SerializationError::IOError(io_e) => codec_error::WriteError(io_e.err),
            other => codec_error::SerializeError(other.to_string()),
        })
    }
}
