// src/zkp/channel.rs
//! Channel state management and operations
//!
//! This module provides functionality for managing unidirectional state channels

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::commitments::{generate_random_blinding, pedersen_commit, Bytes32};
use crate::pedersen_parameters::PedersenParameters;
use crate::state::{generate_state_proof, hash_state};
use crate::state_proof;
use crate::tree::{MerkleTree, MerkleTreeError};

/// Type alias for channel ID
pub type ChannelId = Bytes32;

/// Represents the state of a unidirectional state channel
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChannelState {
    /// Balance of the sender
    pub sender_balance: u64,
    /// Balance of the receiver
    pub receiver_balance: u64,
    /// Additional metadata associated with the channel
    pub metadata: Vec<u8>,
    /// Current nonce value
    pub nonce: u64,
    /// Merkle root for ZKP integration
    pub merkle_root: Bytes32,
    /// ZKP proof for state verification
    pub proof: Option<Vec<u8>>,
}

impl ChannelState {
    /// Creates a new `ChannelState` with the given initial `sender_balance`.
    /// The `receiver_balance` starts at 0 as a constructor invariant.
    pub fn new(sender_balance: u64) -> Self {
        // TODO: Disallow zero balance for initial state
        Self {
            sender_balance,
            receiver_balance: 0,
            metadata: vec![],
            nonce: 0,
            merkle_root: [0u8; 32],
            proof: None,
        }
    }

    /// Creates a new ZKP-enabled `ChannelState` with the given initial `sender_balance`.
    /// The `receiver_balance` starts at 0 as a constructor invariant.
    /// `metadata` is the metadata for the channel.
    pub fn new_with_zkp(sender_balance: u64, metadata: Vec<u8>) -> Self {
        // TODO: Disallow zero balance for initial state
        let params = PedersenParameters::default();

        // compute channel root commitment
        let blinding = generate_random_blinding();
        // receiver balance is 0 for initial state
        let commitment = pedersen_commit(sender_balance, 0, blinding, &params);

        // generate helper proof for the initial state
        let helper_proof = generate_state_proof(
            commitment, // Old commitment = initial state
            commitment, // New commitment = same for initial state
            commitment, // Merkle root = commitment for single channel
            &params,
        );

        let state_proof = state_proof::StateProof {
            pi: helper_proof.pi,
            public_inputs: helper_proof.public_inputs,
            timestamp: helper_proof.timestamp,
        };

        let proof = Some(state_proof.pi.to_vec());

        Self {
            sender_balance,
            receiver_balance: 0,
            nonce: 0,
            metadata,
            merkle_root: [0u8; 32],
            proof,
        }
    }

    /// Verifies that the transition from old_state to self is valid.
    pub fn verify_transition(&self, old_state: &ChannelState) -> bool {
        // Nonce should increment by exactly 1

        if old_state.nonce == u64::MAX {
            return false; // TODO: Handle overflow with nonce overflow error
        }
        if self.nonce != old_state.nonce + 1 {
            return false;
        }

        // Total balance should remain constant
        let old_total = old_state.sender_balance + old_state.receiver_balance;
        let new_total = self.sender_balance + self.receiver_balance;
        if old_total != new_total {
            return false;
        }

        true
    }

    /// Updates the Sparse Merkle Tree with the new state.
    pub fn update_in_tree(
        &self,
        smt: &mut MerkleTree,
        old_state: &ChannelState,
    ) -> Result<(Bytes32, Bytes32), MerkleTreeError> {
        if !self.verify_transition(old_state) {
            return Err(MerkleTreeError::InvalidInput("Invalid state transition".to_string()));
        }

        let old_leaf =
            hash_state(old_state).map_err(|e| MerkleTreeError::InvalidInput(e.to_string()))?;
        let new_leaf =
            hash_state(self).map_err(|e| MerkleTreeError::InvalidInput(e.to_string()))?;

        smt.update(old_leaf, new_leaf)?;

        let new_root = smt.root;

        Ok((new_leaf, new_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_state(sender_balance: u64, receiver_balance: u64, nonce: u64) -> ChannelState {
        ChannelState {
            sender_balance,
            receiver_balance,
            metadata: vec![],
            nonce,
            merkle_root: [0u8; 32],
            proof: None,
        }
    }

    #[test]
    fn test_new() {
        let sender_balance = 100;
        let channel = ChannelState::new(sender_balance);

        // Test constructor
        assert_eq!(channel.sender_balance, sender_balance);
        assert_eq!(channel.receiver_balance, 0);
        assert_eq!(channel.metadata, Vec::<u8>::new());
        assert_eq!(channel.nonce, 0);
        assert_eq!(channel.merkle_root, [0u8; 32]);
        assert_eq!(channel.proof, None);
    }

    #[test]
    fn test_new_with_zkp() {
        // Test basic initialization
        let channel = ChannelState::new_with_zkp(100, vec![1, 2, 3]);
        assert_eq!(channel.sender_balance, 100);
        assert_eq!(channel.metadata, vec![1, 2, 3]);
        assert!(channel.proof.is_some());

        // Test edge cases: empty metadata and zero balance
        let empty_metadata = ChannelState::new_with_zkp(100, Vec::new());
        assert_eq!(empty_metadata.metadata, Vec::<u8>::new());
        assert!(empty_metadata.proof.is_some());

        // Test zero balance TODO: should throw error
        let zero_balance = ChannelState::new_with_zkp(0, Vec::new());
        assert_eq!(zero_balance.sender_balance, 0);
        assert!(zero_balance.proof.is_some());

        // Verify different inputs produce different proofs
        let different_channel = ChannelState::new_with_zkp(200, vec![1, 2, 3]);
        assert_ne!(channel.proof, different_channel.proof);
    }

    #[test]
    fn test_verify_transition() {
        let old = create_state(100, 0, 0);
        let new = create_state(90, 10, 1);
        assert!(new.verify_transition(&old));

        // Test invalid nonce increment
        let invalid_nonce = create_state(90, 10, 2);
        assert!(!invalid_nonce.verify_transition(&old));

        // Test invalid balance total
        let invalid_balance = create_state(90, 15, 1);
        assert!(!invalid_balance.verify_transition(&old));

        // Test nonce overflow
        let max_nonce = create_state(100, 0, u64::MAX);
        let overflow = create_state(90, 10, 0);
        assert!(!overflow.verify_transition(&max_nonce));
    }

    #[test]
    fn test_update_in_tree() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();

        let old = create_state(100, 0, 0);
        let new = create_state(90, 10, 1);

        // Insert the old state's hash into the tree
        let old_leaf =
            hash_state(&old).map_err(|e| MerkleTreeError::InvalidInput(e.to_string()))?;
        tree.insert(old_leaf)?;

        // Test successful update
        let (new_leaf, new_root) = new.update_in_tree(&mut tree, &old)?;
        assert_ne!(new_leaf, [0u8; 32]);
        assert_ne!(new_root, [0u8; 32]);

        // Test invalid transition
        let invalid_state = create_state(90, 15, 2);
        assert!(invalid_state.update_in_tree(&mut tree, &old).is_err());

        // Test hash_state error
        let mut invalid_hash_state = create_state(90, 10, 1);
        invalid_hash_state.metadata = vec![0u8; 1000000];
        assert!(invalid_hash_state.update_in_tree(&mut tree, &old).is_err());

        // Test MerkleTree update error
        let non_existent_old = create_state(200, 0, 0);
        let new_state = create_state(180, 20, 1);
        assert!(new_state
            .update_in_tree(&mut tree, &non_existent_old)
            .is_err());

        Ok(())
    }
}
