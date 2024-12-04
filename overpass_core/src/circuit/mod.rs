// src/circuit/mod.rs

pub mod wallet_circuit;
pub mod channel_circuit;
pub mod bitcoin_bridge_circuit;
pub mod global_merkle_circuit;
pub mod transfer_circuit;
pub mod common_circuit_types;

pub use wallet_circuit::WalletCircuit;
pub use channel_circuit::ChannelCircuit;
pub use bitcoin_bridge_circuit::BitcoinBridgeCircuit;
pub use transfer_circuit::TransferCircuit;
pub use global_merkle_circuit::GlobalMerkleCircuit;
pub use common_circuit_types::{
    ChannelState, WalletState}; 
use crate::error::client_errors::{SystemError, SystemErrorType};


#[derive(Debug, Clone, Copy)]
pub enum CircuitType {
    Global,
    Wallet,
    Channel,
    Bridge,
}

pub struct CircuitManager {
    pub global_circuit: GlobalMerkleCircuit,
    pub wallet_circuit: WalletCircuit,
    pub channel_circuit: ChannelCircuit,
    pub bridge_circuit: BitcoinBridgeCircuit,
}

impl CircuitManager {
    pub fn new(initial_balance: u64) -> Result<Self, SystemError> {
        Ok(Self {
            global_circuit: GlobalMerkleCircuit::new()
                .map_err(|e| SystemError::new(SystemErrorType::CircuitError, e.to_string()))?,
            wallet_circuit: WalletCircuit::new(wallet_circuit::WalletState { balance: initial_balance, nonce: 0 }, wallet_circuit::WalletState { balance: initial_balance, nonce: 0 })
                .map_err(|e| SystemError::new(SystemErrorType::CircuitError, e.to_string()))?,
            channel_circuit: ChannelCircuit::new(channel_circuit::ChannelState { balances: [0, 0], nonce: 0 }, channel_circuit::ChannelState { balances: [0, 0], nonce: 0 })
                .map_err(|e| SystemError::new(SystemErrorType::CircuitError, e.to_string()))?,
            bridge_circuit: BitcoinBridgeCircuit::create(
                bitcoin_bridge_circuit::OverpassBitcoinState::new([0; 32], 0, [0; 20], 0, None, None)
                    .map_err(|e| SystemError::new(SystemErrorType::CircuitError, e.to_string()))?,
                bitcoin_bridge_circuit::OverpassBitcoinState::new([0; 32], 0, [0; 20], 0, None, None)
                    .map_err(|e| SystemError::new(SystemErrorType::CircuitError, e.to_string()))?,
                256
            )
                .map_err(|e| SystemError::new(SystemErrorType::CircuitError, e.to_string()))?,
        })
    }}