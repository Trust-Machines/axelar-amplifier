/*
   Clarity names for general properties
*/
pub const CLARITY_NAME_TYPE: &str = "type";
pub const CLARITY_NAME_SOURCE_CHAIN: &str = "source-chain";
pub const CLARITY_NAME_TOKEN_ID: &str = "token-id";
pub const CLARITY_NAME_SOURCE_ADDRESS: &str = "source-address";
pub const CLARITY_NAME_DESTINATION_ADDRESS: &str = "destination-address";
pub const CLARITY_NAME_AMOUNT: &str = "amount";
pub const CLARITY_NAME_DATA: &str = "data";
pub const CLARITY_NAME_NAME: &str = "name";
pub const CLARITY_NAME_SYMBOL: &str = "symbol";
pub const CLARITY_NAME_DECIMALS: &str = "decimals";
pub const CLARITY_NAME_MINTER_BYTES: &str = "minter-bytes";
pub const CLARITY_NAME_DESTINATION_CHAIN: &str = "destination-chain";
pub const CLARITY_NAME_PAYLOAD: &str = "payload";
pub const CLARITY_NAME_MINTER: &str = "minter";
pub const CLARITY_NAME_SIGNERS: &str = "signers";
pub const CLARITY_NAME_SIGNATURES: &str = "signatures";
pub const CLARITY_NAME_FUNCTION: &str = "function";
pub const CLARITY_NAME_PROOF: &str = "proof";
pub const CLARITY_NAME_MESSAGE_ID: &str = "message-id";
pub const CLARITY_NAME_CONTRACT_ADDRESS: &str = "contract-address";
pub const CLARITY_NAME_PAYLOAD_HASH: &str = "payload-hash";
pub const CLARITY_NAME_SIGNER: &str = "signer";
pub const CLARITY_NAME_WEIGHT: &str = "weight";
pub const CLARITY_NAME_THRESHOLD: &str = "threshold";
pub const CLARITY_NAME_NONCE: &str = "nonce";

/*
   Clarity names for GMP properties
*/
pub const APPROVE_MESSAGES_FUNCTION: &str = "approve-messages";
pub const ROTATE_SIGNERS_FUNCTION: &str = "rotate-signers";

pub const TYPE_APPROVE_MESSAGES: &str = "approve-messages";
pub const TYPE_ROTATE_SIGNERS: &str = "rotate-signers";
pub const STACKS_SIGNER_MESSAGE: &str = "Stacks Signed Message";

pub const CLARITY_MAX_LEN_MESSAGES: u32 = 10;

/*
   Clarity sizes for GMP constants
*/
pub const CLARITY_SIZE_SIGNATURES: u32 = 65; // size of ECDSA signature
pub const CLARITY_MAX_LEN_SIGNATURES: u32 = 100; // Stacks supports a max of 100 signers
pub const CLARITY_SIZE_SOURCE_CHAIN: u32 = 19;
pub const CLARITY_SIZE_MESSAGE_ID: u32 = 128;
pub const CLARITY_SIZE_SOURCE_ADDRESS: u32 = 128;
pub const CLARITY_SIZE_PAYLOAD_HASH: u32 = 32;
pub const CLARITY_SIZE_SIGNER: u32 = 33; // size of ECDSA public key

/*
   Clarity sizes for ITS constants
*/
pub const CLARITY_SIZE_DESTINATION_CHAIN: u32 = 19;
pub const CLARITY_SIZE_PAYLOAD: u32 = 63_000; // max cross chain payload is 64_000, hence the wrapped payload needs to be slightly smaller
pub const CLARITY_SIZE_TOKEN_ID: u32 = 32;
pub const CLARITY_SIZE_DESTINATION_ADDRESS: u32 = 128;
pub const CLARITY_SIZE_DATA: u32 = 62_000; // the contract payload in case of ITS call contract needs to be smaller than the wrapped payload above
pub const CLARITY_SIZE_NAME: u32 = 32;
pub const CLARITY_SIZE_SYMBOL: u32 = 32;
pub const CLARITY_SIZE_MINTER: u32 = 128;

/*
   ITS message type constants
*/
pub const MESSAGE_TYPE_INTERCHAIN_TRANSFER: u128 = 0;
pub const MESSAGE_TYPE_DEPLOY_INTERCHAIN_TOKEN: u128 = 1;
pub const MESSAGE_TYPE_SEND_TO_HUB: u128 = 3;
