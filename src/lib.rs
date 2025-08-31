// ./src/lib.rs

pub mod channel;
pub mod commitments;
pub mod error;
pub mod global_root_contract;
pub mod merkle;
pub mod pedersen_parameters;
pub mod state;
pub mod state_proof;
pub mod state_transition;
pub mod tree;
pub mod types;
pub mod wallet;

pub use channel::ChannelState;
pub use pedersen_parameters::PedersenParameters;
pub use state::StateProof;
pub use tree::MerkleTree;
pub use types::Bytes32;
pub use wallet::WalletContract;
