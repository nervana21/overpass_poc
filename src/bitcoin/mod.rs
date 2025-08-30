// ./src/bitcoin/mod.rs

pub mod bitcoin_transaction;
pub mod bitcoin_types;
pub mod client;
pub mod rpc_client;
pub mod scripts;
pub mod stealth_addresses;
pub mod wallet;
pub mod zkp_handler;

pub use bitcoin_transaction::BitcoinTransaction;
pub use bitcoin_types::{BitcoinLockState, HTLCParameters, StealthAddress};
pub use client::BitcoinClient;
pub use rpc_client::{BitcoinRpcClient, BitcoinRpcConfig};
pub use stealth_addresses::{StealthAddressGenerator, StealthAddressManager};
pub use wallet::{StealthKeyPair, Wallet};
pub use zkp_handler::BitcoinHtlcProof;
