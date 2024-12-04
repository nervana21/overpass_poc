// File: overpass_core/src/state/mod.rs

pub mod bitcoin_state;
pub mod wallet_state;
pub mod channel_state;
pub mod global_state;
pub mod coordinator;

pub use wallet_state::WalletState;
pub use channel_state::ChannelState;
pub use global_state::GlobalState;
pub use coordinator::StateCoordinator;
pub  use bitcoin_state::BitcoinState;