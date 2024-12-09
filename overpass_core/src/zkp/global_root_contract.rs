// global.rs
use bitcoincore_rpc::Auth;
use crate::zkp::channel::ChannelState;
use bitcoincore_rpc::Client;
/// This module provides global constants and functions for the Overpass project.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::Network;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::services::overpass::OverpassService;
use crate::services::overpass_db::OverpassDB as OtherOverpassDB;
use crate::zkp::helpers::{compute_global_root, verify_wallet_proof, Bytes32, StateProof};
use crate::zkp::pedersen_parameters::PedersenParameters;
use crate::zkp::tree::MerkleTree;

#[derive(Debug)]
pub struct OverpassDB;

/// Global configuration for the Overpass project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub network: Network,
    pub initial_balance: u64,
    pub security_bits: u32,
    pub version: String,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            initial_balance: 100,
            security_bits: 256,
            version: "0.1.0".to_string(),
        }
    }
}   /// Represents the local state of the Overpass project.    
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalState {
    pub nonce: u64,
    pub balance: u64,
    pub merkle_root: Bytes32,
    pub proof: StateProof,
}   /// Represents the local state of the Overpass project. 
#[derive(Debug, Clone, Serialize, Deserialize)]
// Remove the duplicate struct definition

impl LocalState {
    pub fn new(nonce: u64, balance: u64, merkle_root: Bytes32, proof: StateProof) -> Self {
        Self {
            nonce,
            balance,
            merkle_root,
            proof,
        }
    }
}

type LocalOverpassService = OverpassService;

/// Represents the global state of the Overpass project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalState {
    #[serde(skip)]
    pub db: Arc<OverpassDB>,
    #[serde(skip)]
    pub service: Arc<OverpassService>,
    pub config: GlobalConfig,
}

/// Represents errors in GlobalRootContract operations.
#[derive(Error, Debug)]
pub enum GlobalRootError {
    #[error("Wallet already registered.")]
    WalletAlreadyRegistered,
    #[error("Wallet not found.")]
    WalletNotFound,
    #[error("Proof verification failed.")]
    ProofVerificationFailed,
}

/// Network Layer aka Storage Nodes (Level 1)
/// Only stores wallet roots and their verification proofs.
pub struct GlobalRootContract {
    /// Mapping from wallet ID to their Merkle root.
    wallet_roots: HashMap<Bytes32, Bytes32>,
    /// Latest proofs per wallet.
    latest_proofs: HashMap<Bytes32, StateProof>,
    /// Cryptographic parameters.
    params: PedersenParameters,
    /// Merkle root of all wallet roots.
    merkle_root: Bytes32,
    /// Merkle tree of wallet roots.
    merkle_tree: MerkleTree,
}

impl Default for GlobalState {
    fn default() -> Self {
        Self {
            db: Arc::new(OverpassDB),
            service: Arc::new(OverpassService),
            config: GlobalConfig::default(),
        }
    }
}

impl GlobalState {
    /// Initializes the global state with default values.
    pub fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        let initial_state = ChannelState {
            balances: vec![100, 50],
            nonce: 0,
            metadata: Vec::new(),
            merkle_root: [0u8; 32],
            proof: StateProof::default(),
        };
        // Assuming OverpassDB has a put method
        // self.db.put(b"state", &initial_state.serialize()?)?;
        Ok(())
    }

    /// Initializes the global state with the provided values.
    pub fn initialize_with_values(&self, initial_state: ChannelState) -> Result<(), Box<dyn std::error::Error>> {
        // Assuming OverpassDB has a put method
        // self.db.put(b"state", &initial_state.serialize()?)?;
        Ok(())
    }

    /// Initializes the global state with the provided values and nonce.
    pub fn initialize_with_values_and_nonce(&self, initial_state: ChannelState, nonce: u64) -> Result<(), Box<dyn std::error::Error>> {
        // Assuming OverpassDB has a put method
        // self.db.put(b"state", &initial_state.serialize()?)?;
        // self.db.put(b"nonce", &nonce.to_le_bytes())?;
        Ok(())
    }
}

/// Implementation of GlobalRootContract.
impl GlobalRootContract {
    /// Creates a new GlobalRootContract with given parameters.
    pub fn new(params: PedersenParameters) -> Self {
        Self {
            wallet_roots: HashMap::new(),
            latest_proofs: HashMap::new(),
            params,
            merkle_root: [0u8; 32],
            merkle_tree: MerkleTree::new(),
        }
    }

    /// Registers a new wallet in the global SMT.
    /// Returns an error if wallet is already registered.
    pub fn register_wallet(&mut self, wallet_id: Bytes32, initial_root: Bytes32) -> Result<(), GlobalRootError> {
        if self.wallet_roots.contains_key(&wallet_id) {
            return Err(GlobalRootError::WalletAlreadyRegistered);
        }

        self.wallet_roots.insert(wallet_id, initial_root);
        self.merkle_tree.insert(initial_root);
        self.merkle_root = compute_global_root(&self.wallet_roots);
        Ok(())
    }

    /// Verifies and updates wallet state.
    pub fn update_wallet(&mut self, wallet_id: Bytes32, new_root: Bytes32, proof: StateProof) -> Result<(), GlobalRootError> {
        // Ensure wallet exists
        if !self.wallet_roots.contains_key(&wallet_id) {
            return Err(GlobalRootError::WalletNotFound);
        }

        // Verify proof
        let old_root = self.wallet_roots.get(&wallet_id).unwrap().clone();
        if !verify_wallet_proof(&old_root, &new_root, &proof, &self.params) {
            return Err(GlobalRootError::ProofVerificationFailed);
        }

        // Update the wallet root
        self.wallet_roots.insert(wallet_id, new_root);
        self.merkle_tree.update(old_root, new_root);
        self.merkle_root = compute_global_root(&self.wallet_roots);

        // Update latest proof
        self.latest_proofs.insert(wallet_id, proof);

        Ok(())
    }

    /// Retrieves the Merkle root of all wallet roots.
    pub fn get_global_merkle_root(&self) -> Bytes32 {
        self.merkle_root
    }

    /// Generates a Merkle proof for a given wallet.
    pub fn generate_proof(&self, wallet_id: Bytes32) -> Option<Vec<Bytes32>> {
        self.wallet_roots.get(&wallet_id).and_then(|root| self.merkle_tree.get_proof(root))
    }

    /// Verifies a Merkle proof for a given wallet root.
    pub fn verify_proof(&self, wallet_id: Bytes32, proof: &[Bytes32]) -> Option<bool> {
        self.wallet_roots.get(&wallet_id).map(|wallet_root| {
            self.merkle_tree.verify_proof(wallet_root, proof, &self.merkle_root)
        })
    }
}

/// Represents the global configuration for the Overpass project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub network: Network,
    pub initial_balance: u64,
    pub security_bits: u32,
    pub version: String,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            initial_balance: 100,
            security_bits: 256,
            version: "0.1.0".to_string(),
        }
    }
}