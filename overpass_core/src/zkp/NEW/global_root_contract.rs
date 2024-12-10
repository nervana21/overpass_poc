// global.rs
use crate::zkp::helpers::verify_wallet_proof;
use crate::zkp::helpers::compute_global_root;
use serde::Deserialize;
use serde::Serialize;
use crate::zkp::channel::ChannelState;

/// This module provides global constants and functions for the Overpass project.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::Network;
use thiserror::Error;

use crate::zkp::tree::MerkleTree;

use super::compressed_transaction::Bytes32;
use super::helpers::StateProof;

#[derive(Debug, Default)]
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
}

/// Represents the local state of the Overpass project.    
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalState {
    pub nonce: u64,
    pub balance: u64,
    pub merkle_root: crate::zkp::compressed_transaction::Bytes32,
    pub proof: StateProof,
}

impl LocalState {
    pub fn create(nonce: u64, balance: u64, merkle_root: Bytes32, proof: StateProof) -> Self {
        Self {
            nonce,
            balance,
            merkle_root,
            proof,
        }
    }

    pub fn new(nonce: u64, balance: u64, merkle_root: Bytes32, proof: StateProof) -> Self {
        Self {
            nonce,
            balance,
            merkle_root,
            proof,
        }
    }
}

type LocalOverpassService = Arc<dyn overpass_service::OverpassService>;
/// Represents the global state of the Overpass project.        
/// Represents the global state of the Overpass project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalState<OverpassService> {
    #[serde(skip)]
    pub db: Arc<OverpassDB>,
    #[serde(skip)]
    #[allow(dead_code)]
    pub service: Arc<LocalOverpassService>,
    pub config: GlobalConfig,
}

// Remove the #[derive(Debug)] attribute as it's not applied to a struct, enum, or union
impl GlobalState {}
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
            db: Arc::new(OverpassDB::new("default_path", 1024, 10, false, None).unwrap()),
            service: Arc::new(OverpassService::new()), // Assuming OverpassService::new() is the correct way to create a new instance
            config: GlobalConfig::default(),
        }
    }
}
impl GlobalRootContract {
    /// Creates a new GlobalRootContract.
    pub fn new(params: PedersenParameters) -> Self {
        let merkle_tree = MerkleTree::new();
        let merkle_root = merkle_tree.root();
        Self {
            wallet_roots: HashMap::new(),
            latest_proofs: HashMap::new(),
            params,
            merkle_root,
            merkle_tree,
        }
    }

    /// Registers a new wallet.
    /// Returns true if successful, otherwise false.
    pub fn register_wallet(&mut self, wallet_id: Bytes32) -> bool {
        if self.wallet_roots.contains_key(&wallet_id) {
            return false;
        }

        let merkle_root = self.merkle_tree.root();
        self.wallet_roots.insert(wallet_id, merkle_root);
        self.merkle_tree.insert(merkle_root);
        true
    }

    /// Updates the proof for a wallet.
    /// Returns true if successful, otherwise false.
    pub fn update_wallet(&mut self, wallet_id: Bytes32, proof: StateProof) -> bool {
        if !self.wallet_roots.contains_key(&wallet_id) {
            return false;
        }

        let old_root = self.wallet_roots.get(&wallet_id).unwrap().clone();
        if !verify_wallet_proof(&old_root, &proof, &self.params) {
            return false;
        }

        self.wallet_roots.insert(wallet_id, proof.public_inputs[0]);
        self.merkle_tree.update(old_root, proof.public_inputs[0]);
        true
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
            db: Arc::new(OverpassDB::new("default_path", 1024, 10, false, None).unwrap()),
            service: Arc::new(OverpassService::new()), // Assuming OverpassService::new() is the correct way to create a new instance
            config: GlobalConfig::default(),
        }
    }
}
impl GlobalRootContract {
    /// Creates a new GlobalRootContract.
    pub fn new(params: PedersenParameters) -> Self {
        Self {
            wallet_roots: HashMap::new(),
            latest_proofs: HashMap::new(),
            params,
            merkle_root: [0u8; 32],
            merkle_tree: MerkleTree::new(),
        }
    }
    // Added a function to save PedersenParameters to a file
    pub fn save_pedersen_parameters_to_file(params: PedersenParameters, file_path: &str) -> std::io::Result<()> {
        let serde_params: SerdePedersenParameters = params.into();
        let serialized = bip39::to_string(&serde_params).unwrap();
        std::fs::write(file_path, serialized)
    }
    // Added a function to load PedersenParameters from a file
    pub fn load_pedersen_parameters_from_file(file_path: &str) -> std::io::Result<PedersenParameters> {
        let serialized = std::fs::read_to_string(file_path)?;
        let serde_params: SerdePedersenParameters = bip39::from_string(&serialized).unwrap();
        Ok(serde_params.into())
    }
    /// Registers a new wallet.
    /// Returns true if successful, otherwise false.
    pub fn register_wallet(&mut self, wallet_id: Bytes32) -> bool {
        if self.wallet_roots.contains_key(&wallet_id) {
            return false;
        }

        let merkle_root = self.merkle_tree.root();
        self.wallet_roots.insert(wallet_id, merkle_root);
        self.merkle_tree.insert(merkle_root);
        true
    }

    /// Updates the proof for a wallet.
    /// Returns true if successful, otherwise false.
    pub fn update_wallet(&mut self, wallet_id: Bytes32, proof: StateProof) -> bool {
        if !self.wallet_roots.contains_key(&wallet_id) {
            return false;
        }

        let old_root = self.wallet_roots.get(&wallet_id).unwrap().clone();
        if !verify_wallet_proof(&old_root, &proof.public_inputs[0], &proof, &self.params) {
            return false;
        }

        self.wallet_roots.insert(wallet_id, proof.public_inputs[0]);
        self.merkle_tree.update(old_root, proof.public_inputs[0]);
        true
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalState<OverpassService> {
    #[serde(skip)]
    pub db: Arc<OverpassDB>,
    #[serde(skip)]
    #[allow(dead_code)]
    pub service: Arc<LocalOverpassService>,
    pub config: GlobalConfig,
}

// Remove the #[derive(Debug)] attribute as it's not applied to a struct, enum, or union
impl GlobalState {}
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
            db: Arc::new(OverpassDB::new("default_path", 1024, 10, false, None).unwrap()),
            service: Arc::new(LocalOverpassService::new()), // Assuming OverpassService::new() is the correct way to create a new instance
            config: GlobalConfig::default(),
        }
    }
}
}
impl GlobalState {
    /// Initializes the global state with default values.
    pub fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _initial_state = ChannelState {
            balances: vec![100, 50],
            nonce: 0,
            metadata: Vec::new(),
            merkle_root: [0u8; 32],
            proof: StateProof::default(), // Assuming StateProof implements Default
        };
        // Assuming OverpassDB has a put method
        // self.db.put(b"state", &initial_state.serialize()?)?;
        Ok(())
    }

    /// Initializes the global state with the provided values.
    pub fn initialize_with_values(&self, initial_state: ChannelState) -> Result<(), Box<dyn std::error::Error>> {
        // Generate proof for initial state
        let initial_proof = initial_state.generate_self_proving_state()?;
        
        // Verify the proof locally
        if !initial_proof.verify() {
            return Err(Box::new(GlobalRootError::ProofVerificationFailed));
        }

        // Update Merkle root with initial state
        let new_root = self.db.update_merkle_root(&initial_state)?;

        // Store state, proof and root atomically
        self.db.atomic_batch()
            .put(b"state", &initial_state.serialize()?)?
            .put(b"proof", &initial_proof.serialize()?)?
            .put(b"root", &new_root)?
            .put(b"nonce", &initial_state.nonce.to_le_bytes())?
            .commit()?;

        Ok(())
    }

    /// Initializes the global state with the provided values and nonce.
    /// 
    /// # Arguments
    /// * `initial_state` - The initial channel state to set
    /// * `nonce` - The initial nonce value
    ///
    /// # Returns
    /// Result indicating success or error
    pub fn initialize_with_values_and_nonce(&self, initial_state: ChannelState, nonce: u64) -> Result<(), Box<dyn std::error::Error>> {
        // Generate proof for initial state
        let initial_proof = initial_state.generate_self_proving_state()?;
        
        // Verify the proof locally
        if !initial_proof.verify() {
            return Err(Box::new(GlobalRootError::ProofVerificationFailed));
        }

        // Update Merkle root with initial state
        let new_root = self.db.update_merkle_root(&initial_state)?;

        // Store state, proof, root and nonce atomically
        self.db.atomic_batch()
            .put(b"state", &initial_state.serialize()?)?
            .put(b"proof", &initial_proof.serialize()?)?
            .put(b"root", &new_root)?
            .put(b"nonce", &nonce.to_le_bytes())?
            .commit()?;

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