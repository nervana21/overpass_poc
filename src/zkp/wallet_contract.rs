// src/zkp/wallet_contract.rs

use std::collections::HashMap;
use std::fmt;

use anyhow::Result;
use serde_json;

use crate::zkp::channel::ChannelState;
use crate::zkp::global_root_contract::{GlobalRootContract, GlobalRootContractError};
use crate::zkp::helpers::commitments::Bytes32;
use crate::zkp::helpers::merkle::{compute_global_root, compute_global_root_from_sorted};
use crate::zkp::helpers::state::hash_state;
use crate::zkp::mobile_optimized_storage::{MobileOptimizedStorage, StorageError};
use crate::zkp::pedersen_parameters::PedersenParameters;

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
    fn from(err: StorageError) -> Self { WalletContractError::StorageError(err.to_string()) }
}

impl From<serde_json::Error> for WalletContractError {
    fn from(err: serde_json::Error) -> Self { WalletContractError::StorageError(err.to_string()) }
}

impl WalletContract {
    /// Creates a new WalletContract.
    pub fn new(
        wallet_id: Bytes32,
        params: PedersenParameters,
        global_contract: GlobalRootContract,
    ) -> Self {
        // Initialize Merkle root based on initial channels (empty at creation)
        let merkle_root = compute_global_root(&HashMap::new()).unwrap_or_default();

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
        balances: [u64; 2],
        _counterparty: Bytes32,
        metadata: Vec<u8>,
    ) -> Result<bool, WalletContractError> {
        if self.channels.contains_key(&channel_id) {
            return Ok(false); // Channel already exists
        }

        let channel = ChannelState::new(channel_id, balances, metadata, &self.params);

        self.channels.insert(channel_id, channel);

        // Update the Merkle root to reflect the new channel
        self.update_merkle_root()?;

        Ok(true)
    }
    /// Updates the Merkle root for the wallet, based on channel states.
    fn update_merkle_root(&mut self) -> Result<(), WalletContractError> {
        // Compute channel hashes and collect them into a vector.
        let mut channel_hashes: Vec<(Bytes32, Bytes32)> = self
            .channels
            .iter()
            .map(|(channel_id, channel_state)| {
                let channel_hash = hash_state(channel_state)
                    .map_err(|e| WalletContractError::HashError(e.to_string()))?;
                Ok::<(Bytes32, Bytes32), WalletContractError>((*channel_id, channel_hash))
            })
            .collect::<Result<_, _>>()?;

        // Sort the channel hashes by channel ID to ensure canonical ordering.
        channel_hashes.sort_by_key(|(channel_id, _)| *channel_id);

        // Extract the sorted list of hashes.
        let sorted_hashes: Vec<Bytes32> = channel_hashes.iter().map(|(_, hash)| *hash).collect();

        // Compute the new global Merkle root using the sorted channel hashes.
        self.merkle_root = compute_global_root_from_sorted(&sorted_hashes);
        Ok(())
    }

    /// Gets the current merkle root.
    pub fn get_merkle_root(&self) -> Bytes32 { self.merkle_root }

    /// Gets a channel by ID.
    pub fn get_channel(&self, channel_id: &Bytes32) -> Option<&ChannelState> {
        self.channels.get(channel_id)
    }

    /// Lists all channel IDs.
    pub fn list_channels(&self) -> Vec<Bytes32> { self.channels.keys().copied().collect() }

    /// Checks if a channel exists.
    pub fn has_channel(&self, channel_id: &Bytes32) -> bool {
        self.channels.contains_key(channel_id)
    }
}

impl fmt::Display for WalletContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Wallet Contract:")?;
        writeln!(f, "  ID: 0x{}", hex::encode(self.wallet_id))?;
        // writeln!(f, "  {:?}", self.params)?;
        writeln!(f, "  Merkle Root: 0x{}", hex::encode(self.merkle_root))?;
        writeln!(f, "  Channels: {}", self.channels.len())?;

        // Display individual channels
        for (channel_id, state) in &self.channels {
            writeln!(f, "\n  Channel 0x{}:", hex::encode(channel_id))?;
            writeln!(f, "    Balance: {} units", state.sender_balance)?;
            writeln!(f, "    Nonce: {}", state.nonce)?;
            if !state.metadata.is_empty() {
                writeln!(f, "    Metadata: {} bytes", state.metadata.len())?;
            }
        }

        Ok(())
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
    fn test_new_wallet_contract() {
        let wallet = setup_test_wallet();

        let expected_wallet_id: Bytes32 = [1u8; 32];
        assert_eq!(wallet.wallet_id, expected_wallet_id);

        // Verify that channels are initialized empty.
        assert!(wallet.channels.is_empty(), "Channels should be empty on initialization");

        // Compute the expected Merkle root based on an empty set of channels.
        let expected_merkle_root = compute_global_root(&HashMap::new())
            .expect("compute_global_root should succeed with an empty channel map");
        assert_eq!(
            wallet.merkle_root, expected_merkle_root,
            "Merkle root should be computed from an empty channel map"
        );
    }

    #[test]
    fn test_wallet_contract_display() {
        let wallet = setup_test_wallet();

        // Convert wallet to string and verify basic components
        let wallet_string = wallet.to_string();

        // Basic assertions to verify the display output contains expected components
        assert!(wallet_string.contains("Wallet Contract:"));
        assert!(wallet_string.contains("ID: 0x"));
        assert!(wallet_string.contains("Merkle Root: 0x"));
        assert!(wallet_string.contains("Channels: 0")); // Initially 0 channels

        // Print the wallet display for visual inspection
        // println!("Wallet Display:\n{}", wallet_string);
    }

    #[test]
    fn test_register_channel() -> Result<(), WalletContractError> {
        let mut wallet = setup_test_wallet();
        let channel_id = [2u8; 32];

        // Register new channel
        let result = wallet.register_channel(channel_id, [100, 0], [0u8; 32], vec![1, 2, 3])?;
        assert!(result);
        assert!(wallet.has_channel(&channel_id));

        // Try registering same channel again
        let result = wallet.register_channel(channel_id, [200, 0], [0u8; 32], vec![4, 5, 6])?;
        assert!(!result);

        Ok(())
    }

    #[test]
    fn test_list_channels() -> Result<(), WalletContractError> {
        let mut wallet = setup_test_wallet();
        let channel_ids: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        // Register multiple channels
        for &id in &channel_ids {
            wallet.register_channel(id, [100, 0], [0u8; 32], vec![1, 2, 3])?;
        }

        let listed_channels = wallet.list_channels();
        assert_eq!(listed_channels.len(), channel_ids.len());
        for id in channel_ids {
            assert!(listed_channels.contains(&id));
        }

        Ok(())
    }

    #[test]
    fn test_update_merkle_root() -> Result<(), WalletContractError> {
        let mut wallet = setup_test_wallet();

        // Initially, the wallet's Merkle root should be all zeros.
        assert_eq!(wallet.merkle_root, [0u8; 32]);

        // Define several channel IDs for testing.
        let channel_ids: Vec<Bytes32> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        // Register multiple channels in the wallet.
        for &id in &channel_ids {
            wallet.register_channel(id, [100, 0], [0u8; 32], vec![1, 2, 3])?;
        }

        // Update the Merkle root for the wallet.
        wallet.update_merkle_root()?;

        // After updating, the Merkle root should no longer be all zeros.
        assert_ne!(wallet.merkle_root, [0u8; 32]);

        // To verify correctness, re-compute the expected Merkle root using canonical ordering:
        let mut expected_channel_hashes: Vec<(Bytes32, Bytes32)> = channel_ids
            .iter()
            .map(|id| {
                let channel_state = wallet.get_channel(id).expect("Channel should exist");
                let channel_hash = hash_state(&channel_state)
                    .map_err(|e| WalletContractError::HashError(e.to_string()))?;
                Ok((*id, channel_hash))
            })
            .collect::<Result<_, WalletContractError>>()?;

        // Sort the expected channel hashes by channel ID.
        expected_channel_hashes.sort_by_key(|(channel_id, _)| *channel_id);

        // Extract the sorted list of hashes.
        let sorted_hashes: Vec<Bytes32> =
            expected_channel_hashes.iter().map(|(_, hash)| *hash).collect();

        // Compute the expected global Merkle root.
        let expected_root = compute_global_root_from_sorted(&sorted_hashes);

        // Finally, check that the wallet's stored Merkle root matches the expected value.
        assert_eq!(
            wallet.merkle_root, expected_root,
            "The computed Merkle root should match the expected root"
        );

        Ok(())
    }
}
