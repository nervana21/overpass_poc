// ./src/circuit/common_circuit_types.rs

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::client_errors::{SystemError, SystemErrorType};

#[derive(Error, Debug)]
pub enum CircuitType {
    Global,
    Wallet,
    Channel,
    Bridge,
}

impl std::fmt::Display for CircuitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitType::Global => write!(f, "Global"),
            CircuitType::Wallet => write!(f, "Wallet"),
            CircuitType::Channel => write!(f, "Channel"),
            CircuitType::Bridge => write!(f, "Bridge"),
        }
    }
}

pub trait Circuit {
    fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> Result<bool, SystemError>;
    fn prove(&self, inputs: &[u8]) -> Result<Vec<u8>, SystemError>;
}

// src/circuit/wallet_circuit.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    pub balance: u64,
    pub nonce: u64,
}

impl Circuit for WalletState {
    fn verify(&self, _proof: &[u8], _public_inputs: &[u8]) -> Result<bool, SystemError> {
        // Implement wallet verification
        Ok(true)
    }

    fn prove(&self, _inputs: &[u8]) -> Result<Vec<u8>, SystemError> {
        // Implement wallet proof generation
        Ok(Vec::new())
    }
}   

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelState {
    pub balances: [u64; 2],
    pub nonce: u64,
}   

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            balances: [0, 0],
            nonce: 0,
        }
    }
}

impl Circuit for ChannelState {
    fn verify(&self, _proof: &[u8], _public_inputs: &[u8]) -> Result<bool, SystemError> {
        // Implement channel verification
        Ok(true)
    }

    fn prove(&self, _inputs: &[u8]) -> Result<Vec<u8>, SystemError> {
        // Implement channel proof generation
        Ok(Vec::new())
    }
}

// src/circuit/bitcoin_bridge_circuit.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverpassBitcoinState {
    pub block_hash: [u8; 32],
    pub height: u32,
    pub address: [u8; 20],
    pub amount: u64,
    pub proof: Option<Vec<u8>>,
    pub merkle_proof: Option<Vec<Vec<u8>>>,
}

impl OverpassBitcoinState {
    pub fn new(
        block_hash: [u8; 32],
        height: u32,
        address: [u8; 20],
        amount: u64,
        proof: Option<Vec<u8>>,
        merkle_proof: Option<Vec<Vec<u8>>>,
    ) -> Result<Self, SystemError> {
        Ok(Self {
            block_hash,
            height,
            address,
            amount,
            proof,
            merkle_proof,
        })
    }
}