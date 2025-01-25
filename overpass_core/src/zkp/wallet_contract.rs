use crate::zkp::channel::ChannelState;
use crate::zkp::global_root_contract::{GlobalRootContract, GlobalRootContractError};
use crate::zkp::helpers::{
    compute_global_root, generate_random_blinding, generate_state_proof, pedersen_commit, Bytes32,
};
use crate::zkp::mobile_optimized_storage::{MobileOptimizedStorage, StorageError};
use crate::zkp::pedersen_parameters::PedersenParameters;
use anyhow::Result;
use serde_json;
use std::collections::HashMap;

use super::state_proof;

/// Local Verification Layer (Level 2)
/// Manages channels and generates network proofs.
pub struct WalletContract {
    pub wallet_id: Bytes32,
    pub params: PedersenParameters,
    pub channels: HashMap<Bytes32, ChannelState>,
    pub merkle_root: Bytes32,
    pub storage: MobileOptimizedStorage,
    pub global_contract: GlobalRootContract,
}

/// Represents errors in WalletContract operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletContractError {
    #[error("Hash computation failed: {0}")]
    HashError(String),
    #[error("Merkle root computation failed: {0}")]
    MerkleRootError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Global root contract error: {0}")]
    GlobalRootError(#[from] GlobalRootContractError),
    #[error("State proof generation failed: {0}")]
    ProofGenerationError(String),
}

impl From<StorageError> for WalletContractError {
    fn from(err: StorageError) -> Self {
        WalletContractError::StorageError(err.to_string())
    }
}

impl From<serde_json::Error> for WalletContractError {
    fn from(err: serde_json::Error) -> Self {
        WalletContractError::StorageError(err.to_string())
    }
}

impl WalletContract {
    /// Creates a new WalletContract.
    pub fn new(
        wallet_id: Bytes32,
        params: PedersenParameters,
        global_contract: GlobalRootContract,
    ) -> Self {
        // Initialize Merkle root based on initial channels (empty at creation)
        let merkle_root = match compute_global_root(&HashMap::new()) {
            Ok(root) => root,
            Err(_) => [0u8; 32],
        };

        Self {
            wallet_id,
            params,
            channels: HashMap::new(),
            merkle_root,
            storage: MobileOptimizedStorage::new(100, 30 * 24 * 3600),
            global_contract,
        }
    }

    /// Registers a new channel.
    pub fn register_channel(
        &mut self,
        channel_id: Bytes32,
        initial_balance: u64,
        _counterparty: Bytes32,
        metadata: Vec<u8>,
    ) -> Result<bool, WalletContractError> {
        if self.channels.contains_key(&channel_id) {
            return Ok(false); // Channel already exists
        }

        // Sanitize metadata
        let sanitized_metadata = Self::sanitize_metadata(metadata).unwrap_or_else(Vec::new);
        let channel = ChannelState {
            balances: vec![initial_balance],
            nonce: 0,
            metadata: sanitized_metadata,
            merkle_root: [0u8; 32], // Initial Merkle root for the channel
            proof: None,
        };

        self.channels.insert(channel_id, channel);

        // Update the Merkle root to reflect the new channel
        self.update_merkle_root()?;

        // Register wallet in global root contract
        self.global_contract
            .register_wallet(self.wallet_id, self.merkle_root)
            .map_err(WalletContractError::from)?;

        Ok(true)
    }

    /// Helper to sanitize metadata, ensuring it's valid.
    fn sanitize_metadata(metadata: Vec<u8>) -> Option<Vec<u8>> {
        if metadata.is_empty() {
            None
        } else {
            Some(metadata)
        }
    }

    /// Updates the Merkle root for the wallet, based on channel states.
    fn update_merkle_root(&mut self) -> Result<(), WalletContractError> {
        // Compute channel hashes
        let mut channel_hashes = HashMap::new();
        for (channel_id, channel_state) in &self.channels {
            let channel_hash = channel_state
                .hash()
                .map_err(|e| WalletContractError::HashError(e.to_string()))?;
            channel_hashes.insert(*channel_id, channel_hash);
        }

        // Compute the new global Merkle root based on all channel hashes
        self.merkle_root = compute_global_root(&channel_hashes)
            .map_err(|e| WalletContractError::MerkleRootError(e.to_string()))?;

        Ok(())
    }

    /// Updates a channel's state and generates a proof.
    pub fn update_channel(
        &mut self,
        channel_id: Bytes32,
        new_balance: u64,
        metadata: Vec<u8>,
    ) -> Result<bool, WalletContractError> {
        // First, check if channel exists and get required data
        let (old_merkle_root, old_commitment_hash) = match self.channels.get(&channel_id) {
            Some(channel) => {
                let hash = channel
                    .hash()
                    .map_err(|e| WalletContractError::HashError(e.to_string()))?;
                (channel.merkle_root, hash)
            }
            None => return Ok(false),
        };

        // Generate new commitment and proof
        let blinding = generate_random_blinding();
        let new_commitment = pedersen_commit(new_balance, blinding, &self.params);

        let helper_proof = generate_state_proof(
            old_merkle_root,
            new_commitment,
            self.merkle_root,
            &self.params,
        );

        // Convert helpers::StateProof to state_proof::StateProof
        let state_proof = state_proof::StateProof {
            pi: helper_proof.pi,
            public_inputs: helper_proof.public_inputs,
            timestamp: helper_proof.timestamp,
        };

        // Now update the channel
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.balances = vec![new_balance];
            channel.nonce += 1;
            channel.metadata = metadata;
            channel.merkle_root = new_commitment;
        }

        // Store transaction
        self.storage
            .store_transaction(
                channel_id,
                old_commitment_hash,
                new_commitment,
                state_proof.clone(),
                serde_json::Value::Null,
            )
            .map_err(|e| WalletContractError::StorageError(e.to_string()))?;

        // Update merkle root
        self.update_merkle_root()?;

        // Update global root contract
        self.global_contract
            .update_wallet(self.wallet_id, self.merkle_root, state_proof)
            .map_err(WalletContractError::from)?;

        Ok(true)
    }

    /// Gets the current merkle root.
    pub fn get_merkle_root(&self) -> Bytes32 {
        self.merkle_root
    }

    /// Gets a channel by ID.
    pub fn get_channel(&self, channel_id: &Bytes32) -> Option<&ChannelState> {
        self.channels.get(channel_id)
    }

    /// Lists all channel IDs.
    pub fn list_channels(&self) -> Vec<Bytes32> {
        self.channels.keys().copied().collect()
    }

    /// Checks if a channel exists.
    pub fn has_channel(&self, channel_id: &Bytes32) -> bool {
        self.channels.contains_key(channel_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_wallet() -> WalletContract {
        let wallet_id = [1u8; 32];
        let params = PedersenParameters::default();
        let global_contract = GlobalRootContract::new(params.clone());
        WalletContract::new(wallet_id, params, global_contract)
    }

    #[test]
    fn test_register_channel() -> Result<(), WalletContractError> {
        let mut wallet = setup_test_wallet();
        let channel_id = [2u8; 32];

        // Register new channel
        let result = wallet.register_channel(channel_id, 100, [0u8; 32], vec![1, 2, 3])?;
        assert!(result);
        assert!(wallet.has_channel(&channel_id));

        // Try registering same channel again
        let result = wallet.register_channel(channel_id, 200, [0u8; 32], vec![4, 5, 6])?;
        assert!(!result);

        Ok(())
    }

    #[test]
    fn test_update_channel() -> Result<(), WalletContractError> {
        let mut wallet = setup_test_wallet();
        let channel_id = [2u8; 32];

        // Register channel
        wallet.register_channel(channel_id, 100, [0u8; 32], vec![1, 2, 3])?;

        // Update channel
        let result = wallet.update_channel(channel_id, 150, vec![4, 5, 6])?;
        assert!(result);

        // Verify update
        let channel = wallet.get_channel(&channel_id).unwrap();
        assert_eq!(channel.balances[0], 150);
        assert_eq!(channel.metadata, vec![4, 5, 6]);
        assert_eq!(channel.nonce, 1);

        Ok(())
    }

    #[test]
    fn test_list_channels() -> Result<(), WalletContractError> {
        let mut wallet = setup_test_wallet();
        let channel_ids: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        // Register multiple channels
        for &id in &channel_ids {
            wallet.register_channel(id, 100, [0u8; 32], vec![1, 2, 3])?;
        }

        let listed_channels = wallet.list_channels();
        assert_eq!(listed_channels.len(), channel_ids.len());
        for id in channel_ids {
            assert!(listed_channels.contains(&id));
        }

        Ok(())
    }
}
