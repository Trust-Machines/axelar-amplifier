use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A container for public keys (compressed secp256k1 public keys)
pub struct StacksPublicKeyBuffer(pub [u8; 33]);

pub trait Address: Clone + fmt::Debug + fmt::Display {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_string(from: &str) -> Option<Self>
    where
        Self: Sized;
    fn is_burn(&self) -> bool;
}

pub const PEER_VERSION_EPOCH_1_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_05: u8 = 0x05;
pub const PEER_VERSION_EPOCH_2_1: u8 = 0x06;

// sliding burnchain window over which a miner's past block-commit payouts will be used to weight
// its current block-commit in a sortition.
// This is the value used in epoch 2.x
pub const MINING_COMMITMENT_WINDOW: u8 = 6;

// how often a miner must commit in its mining commitment window in order to even be considered for
// sortition.
// Only relevant for Nakamoto (epoch 3.x)
pub const MINING_COMMITMENT_FREQUENCY_NAKAMOTO: u8 = 3;

#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Copy, Serialize, Deserialize)]
pub enum StacksEpochId {
    Epoch10 = 0x01000,
    Epoch20 = 0x02000,
    Epoch2_05 = 0x02005,
    Epoch21 = 0x0200a,
    Epoch22 = 0x0200f,
    Epoch23 = 0x02014,
    Epoch24 = 0x02019,
    Epoch25 = 0x0201a,
    Epoch30 = 0x03000,
}

impl StacksEpochId {
    pub fn latest() -> StacksEpochId {
        StacksEpochId::Epoch30
    }

    /// Returns whether or not this Epoch should perform
    ///  memory checks during analysis
    pub fn analysis_memory(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24 => false,
            StacksEpochId::Epoch25 | StacksEpochId::Epoch30 => true,
        }
    }

    /// Returns whether or not this Epoch should perform
    ///  Clarity value sanitization
    pub fn value_sanitizing(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23 => false,
            StacksEpochId::Epoch24 | StacksEpochId::Epoch25 | StacksEpochId::Epoch30 => true,
        }
    }

    /// Does this epoch support unlocking PoX contributors that miss a slot?
    ///
    /// Epoch 2.0 - 2.05 didn't support this feature, but they weren't epoch-guarded on it. Instead,
    ///  the behavior never activates in those epochs because the Pox1 contract does not provide
    ///  `contibuted_stackers` information. This check maintains that exact semantics by returning
    ///  true for all epochs before 2.5. For 2.5 and after, this returns false.
    pub fn supports_pox_missed_slot_unlocks(&self) -> bool {
        self < &StacksEpochId::Epoch25
    }

    /// What is the sortition mining commitment window for this epoch?
    pub fn mining_commitment_window(&self) -> u8 {
        MINING_COMMITMENT_WINDOW
    }

    /// How often must a miner mine in order to be considered for sortition in its commitment
    /// window?
    pub fn mining_commitment_frequency(&self) -> u8 {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => 0,
            StacksEpochId::Epoch30 => MINING_COMMITMENT_FREQUENCY_NAKAMOTO,
        }
    }
}

impl std::fmt::Display for StacksEpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StacksEpochId::Epoch10 => write!(f, "1.0"),
            StacksEpochId::Epoch20 => write!(f, "2.0"),
            StacksEpochId::Epoch2_05 => write!(f, "2.05"),
            StacksEpochId::Epoch21 => write!(f, "2.1"),
            StacksEpochId::Epoch22 => write!(f, "2.2"),
            StacksEpochId::Epoch23 => write!(f, "2.3"),
            StacksEpochId::Epoch24 => write!(f, "2.4"),
            StacksEpochId::Epoch25 => write!(f, "2.5"),
            StacksEpochId::Epoch30 => write!(f, "3.0"),
        }
    }
}

impl TryFrom<u32> for StacksEpochId {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<StacksEpochId, Self::Error> {
        match value {
            x if x == StacksEpochId::Epoch10 as u32 => Ok(StacksEpochId::Epoch10),
            x if x == StacksEpochId::Epoch20 as u32 => Ok(StacksEpochId::Epoch20),
            x if x == StacksEpochId::Epoch2_05 as u32 => Ok(StacksEpochId::Epoch2_05),
            x if x == StacksEpochId::Epoch21 as u32 => Ok(StacksEpochId::Epoch21),
            x if x == StacksEpochId::Epoch22 as u32 => Ok(StacksEpochId::Epoch22),
            x if x == StacksEpochId::Epoch23 as u32 => Ok(StacksEpochId::Epoch23),
            x if x == StacksEpochId::Epoch24 as u32 => Ok(StacksEpochId::Epoch24),
            x if x == StacksEpochId::Epoch25 as u32 => Ok(StacksEpochId::Epoch25),
            x if x == StacksEpochId::Epoch30 as u32 => Ok(StacksEpochId::Epoch30),
            _ => Err("Invalid epoch"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct StacksEpoch<L> {
    pub epoch_id: StacksEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: L,
    pub network_epoch: u8,
}

impl<L> StacksEpoch<L> {
    /// Determine which epoch, if any, in a list of epochs, a given burnchain height falls into.
    /// Returns Some(index) if there is such an epoch in the list.
    /// Returns None if not.
    pub fn find_epoch(epochs: &[StacksEpoch<L>], height: u64) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.start_height <= height && height < epoch.end_height {
                return Some(i);
            }
        }
        None
    }

    /// Find an epoch by its ID
    /// Returns Some(index) if the epoch is in the list
    /// Returns None if not
    pub fn find_epoch_by_id(epochs: &[StacksEpoch<L>], epoch_id: StacksEpochId) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.epoch_id == epoch_id {
                return Some(i);
            }
        }
        None
    }
}

// StacksEpochs are ordered by start block height
impl<L: PartialEq> PartialOrd for StacksEpoch<L> {
    fn partial_cmp(&self, other: &StacksEpoch<L>) -> Option<Ordering> {
        self.epoch_id.partial_cmp(&other.epoch_id)
    }
}

impl<L: PartialEq + Eq> Ord for StacksEpoch<L> {
    fn cmp(&self, other: &StacksEpoch<L>) -> Ordering {
        self.epoch_id.cmp(&other.epoch_id)
    }
}
