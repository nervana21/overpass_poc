// src/zkp/mobile_optimized_storage.rs
use crate::zkp::channel::ChannelState;
/// Local Storage Layer (Level 3)
/// Hybrid hot/cold storage optimized for mobile devices.
use crate::zkp::compressed_transaction::CompressedTransaction;
use crate::zkp::helpers::{hash_pair, Bytes32};
use crate::zkp::state_proof::StateProof;
use lru::LruCache;
use std::fmt;
use std::num::NonZero;

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Represents errors in storage operations.
#[derive(Debug)]
pub enum StorageError {
    TransactionTooOld,
    StorageLimitExceeded,
    Other(String),
}

/// MobileOptimizedStorage handles hybrid hot/cold storage for mobile devices.
pub struct MobileOptimizedStorage {
    /// Hot storage (active data): channels and recent transactions.
    #[allow(dead_code)]
    active_channels: LruCache<Bytes32, ChannelState>,
    recent_transactions: LruCache<Bytes32, Vec<CompressedTransaction>>,

    /// Cold storage (compressed historical data).
    transaction_history: HashMap<Bytes32, Vec<CompressedTransaction>>,
    #[allow(dead_code)]
    channel_roots: HashMap<Bytes32, Bytes32>,

    /// Performance parameters.
    compression_threshold: usize, // Number of transactions before compression
    #[allow(dead_code)]
    retention_period: u64, // Retention period in seconds
}
impl MobileOptimizedStorage {
    /// Creates a new MobileOptimizedStorage instance.
    pub fn new(compression_threshold: usize, retention_period: u64) -> Self {
        Self {
            active_channels: LruCache::new(NonZero::new(5).unwrap()),
            recent_transactions: LruCache::new(NonZero::new(100).unwrap()),
            transaction_history: HashMap::new(),
            channel_roots: HashMap::new(),
            compression_threshold,
            retention_period,
        }
    }

    /// Checks whether this MobileOptimizedStorage is empty.
    /// Returns `true` if active_channels, recent_transactions, transaction_history,
    /// and channel_roots are all empty.
    pub fn is_empty(&self) -> bool {
        self.active_channels.len() == 0
            && self.recent_transactions.len() == 0
            && self.transaction_history.is_empty()
            && self.channel_roots.is_empty()
    }

    /// Stores a transaction, possibly compressing history.
    pub fn store_transaction(
        &mut self,
        channel_id: Bytes32,
        old_commitment: Bytes32,
        new_commitment: Bytes32,
        proof: StateProof,
        metadata: serde_json::Value,
    ) -> Result<(), StorageError> {
        let timestamp = proof.timestamp;
        let metadata_hash = sha256_hash(
            &serde_json::to_vec(&metadata).map_err(|e| StorageError::Other(e.to_string()))?,
        );
        let merkle_root = compute_merkle_root(&self.transaction_history, &channel_id);

        let compressed_tx = CompressedTransaction {
            timestamp,
            old_commitment,
            new_commitment,
            metadata_hash,
            merkle_root,
        };

        // Add to recent transactions
        if let Some(txs) = self.recent_transactions.get_mut(&channel_id) {
            txs.push(compressed_tx.clone());
            if txs.len() >= self.compression_threshold {
                self.compress_transactions(channel_id)?;
            }
        } else {
            self.recent_transactions
                .put(channel_id, vec![compressed_tx.clone()]);
        }

        // Add to transaction history
        self.transaction_history
            .entry(channel_id)
            .or_default()
            .push(compressed_tx);

        Ok(())
    }
    /// Compresses transactions for a channel.
    fn compress_transactions(&mut self, channel_id: Bytes32) -> Result<(), StorageError> {
        if let Some(recent_txs) = self.recent_transactions.pop(&channel_id) {
            if recent_txs.is_empty() {
                return Ok(());
            }
            // Compress recent_txs into one
            let compressed = CompressedTransaction {
                timestamp: recent_txs.last().unwrap().timestamp,
                old_commitment: recent_txs.first().unwrap().old_commitment,
                new_commitment: recent_txs.last().unwrap().new_commitment,
                metadata_hash: sha256_hash(&serialize_metadata(&recent_txs)),
                merkle_root: compute_merkle_root(&self.transaction_history, &channel_id),
            };
            // Add to history
            self.transaction_history
                .entry(channel_id)
                .or_default()
                .push(compressed);
        }
        Ok(())
    }
}

/// Computes SHA256 hash.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Serializes metadata for hashing.
fn serialize_metadata(txs: &[CompressedTransaction]) -> Vec<u8> {
    serde_json::to_vec(txs).unwrap_or_default()
}

/// Computes Merkle root from transaction history for a channel.
fn compute_merkle_root(
    transaction_history: &HashMap<Bytes32, Vec<CompressedTransaction>>,
    channel_id: &Bytes32,
) -> [u8; 32] {
    if let Some(txs) = transaction_history.get(channel_id) {
        let leaves: Vec<[u8; 32]> = txs.iter().map(|tx| tx.merkle_root).collect();
        compute_merkle_root_helper(leaves)
    } else {
        [0u8; 32]
    }
}

/// Computes the Merkle root from a list of leaves.
fn compute_merkle_root_helper(leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut current_level = leaves;
    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            current_level.push(*current_level.last().unwrap());
        }
        current_level = current_level
            .chunks(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    current_level[0]
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::TransactionTooOld => write!(f, "Transaction is too old"),
            StorageError::StorageLimitExceeded => write!(f, "Storage limit exceeded"),
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::channel::ChannelState;
    use crate::zkp::helpers::Bytes32;
    use crate::zkp::pedersen_parameters::PedersenParameters;

    #[test]
    fn test_mobile_optimized_storage_is_empty_initially() {
        // Create a new MobileOptimizedStorage instance.
        let storage = MobileOptimizedStorage::new(100, 30 * 24 * 3600);

        // Verify that all internal collections are empty.
        assert!(
            storage.is_empty(),
            "Storage should be empty after initialization"
        );
    }

    #[test]
    fn test_mobile_optimized_storage_not_empty_after_insertion() {
        // Create a new MobileOptimizedStorage instance.
        let mut storage = MobileOptimizedStorage::new(100, 30 * 24 * 3600);
        let channel_id: Bytes32 = [1u8; 32];

        let params = PedersenParameters::default();
        let channel_state = ChannelState::new(channel_id, vec![100, 0], vec![1, 2, 3], &params);

        // Insert the dummy channel state into active_channels.
        storage.active_channels.put(channel_id, channel_state);

        // Verify that the storage is no longer empty.
        assert!(
            !storage.is_empty(),
            "Storage should not be empty after inserting an active channel"
        );
    }
}
