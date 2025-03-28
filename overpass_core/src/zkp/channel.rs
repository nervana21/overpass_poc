// src/zkp/channel.rs

use super::helpers::generate_random_blinding;
use super::helpers::hash_state;
use super::helpers::{compute_channel_root, generate_state_proof, pedersen_commit, Bytes32};
use super::pedersen_parameters::PedersenParameters;
use super::state_proof;
use crate::zkp::tree::{MerkleTree, MerkleTreeError};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Represents the state of a channel.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelState {
    pub balances: Vec<u64>,
    pub nonce: u64,
    pub metadata: Vec<u8>,
    pub merkle_root: Bytes32,
    pub proof: Option<Vec<u8>>,
}

impl ChannelState {
    pub fn new(
        channel_id: Bytes32,
        balances: Vec<u64>,
        metadata: Vec<u8>,
        params: &PedersenParameters,
    ) -> Self {
        // compute channel root commitment
        let blinding = generate_random_blinding();
        let commitment = compute_channel_root(
            channel_id,
            pedersen_commit(balances.clone(), blinding, params),
            0,
        );

        // generate helper proof for the initial state
        let helper_proof = generate_state_proof(
            commitment, // Old commitment = initial state
            commitment, // New commitment = same for initial state
            commitment, // Merkle root = commitment for single channel
            params,
        );

        let state_proof = state_proof::StateProof {
            pi: helper_proof.pi,
            public_inputs: helper_proof.public_inputs,
            timestamp: helper_proof.timestamp,
        };

        let proof = Some(state_proof.pi.to_vec());

        Self {
            balances,
            nonce: 0,
            metadata,
            merkle_root: commitment,
            proof,
        }
    }

    /// Verifies that the transition from old_state to self is valid.
    pub fn verify_transition(&self, old_state: &ChannelState) -> bool {
        // Example verification: nonce should increment and balances should not decrease
        if self.nonce != old_state.nonce + 1 {
            return false;
        }
        if self.balances.len() != old_state.balances.len() {
            return false;
        }
        for (new_balance, old_balance) in self.balances.iter().zip(old_state.balances.iter()) {
            if *new_balance < *old_balance {
                return false;
            }
        }
        true
    }

    /// Updates the Sparse Merkle Tree with the new state.
    pub fn update_in_tree(
        &self,
        smt: &mut MerkleTree,
        old_state: &ChannelState,
        key: Bytes32,
    ) -> Result<(Bytes32, Bytes32), MerkleTreeError> {
        if !self.verify_transition(old_state) {
            return Err(MerkleTreeError::InvalidInput(
                "Invalid state transition".to_string(),
            ));
        }

        let new_leaf =
            hash_state(self).map_err(|e| MerkleTreeError::InvalidInput(e.to_string()))?;

        smt.update(key, new_leaf)?;

        let new_root = smt.root;

        Ok((new_leaf, new_root))
    }

    // / Calculates hash of the channel state for consistent referencing.
    // pub fn hash(&self) -> Result<Bytes32> {
    // self.hash_state()
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::{
        state_transition::apply_transition,
        tree::{MerkleTree, MerkleTreeError},
    };

    fn setup_test_channel_state_params() -> (Bytes32, Vec<u64>, Vec<u8>, PedersenParameters) {
        // Setup test parameters
        let channel_id = [1u8; 32];
        let balances: Vec<u64> = vec![100, 0];
        let metadata = vec![1, 2, 3];
        let params = PedersenParameters::default();

        (channel_id, balances, metadata, params)
    }

    #[test]
    fn test_channel_state_new() {
        let (channel_id, balances, metadata, params) = setup_test_channel_state_params();

        // Test case 1: Basic initialization with non-empty metadata
        let channel = ChannelState::new(channel_id, balances, metadata.clone(), &params);

        assert_eq!(channel.balances, vec![100, 0]);
        assert_eq!(channel.nonce, 0);
        assert_eq!(channel.metadata, metadata);
        assert!(channel.proof.is_some()); // Proof should be generated

        // Verify merkle_root is not zero (should be computed from commitment)
        assert_ne!(channel.merkle_root, [0u8; 32]);

        // Test case 2: Initialization with empty metadata
        let channel_empty_metadata =
            ChannelState::new(channel_id, channel.balances, Vec::<u8>::new(), &params);
        assert_eq!(channel_empty_metadata.metadata, Vec::<u8>::new());
        assert!(channel_empty_metadata.proof.is_some());

        // Test case 3: Initialization with zero balance
        let channel_zero_balance =
            ChannelState::new(channel_id, vec![0, 0], Vec::<u8>::new(), &params);
        assert_eq!(channel_zero_balance.balances, vec![0, 0]);
        assert!(channel_zero_balance.proof.is_some());

        // Verify that different channel_ids produce different merkle roots
        let different_channel_id = [2u8; 32];
        let different_channel =
            ChannelState::new(different_channel_id, vec![100, 0], metadata, &params);
        assert_ne!(channel.merkle_root, different_channel.merkle_root);
    }

    #[test]
    fn test_state_transition_with_smt() -> Result<(), MerkleTreeError> {
        // Create a new, empty Merkle tree.
        let mut tree = MerkleTree::new();

        // Retrieve test parameters.
        let (channel_id, _balances, _metadata, params) = setup_test_channel_state_params();

        // Create the initial channel state with given balances and metadata.
        let initial_state = ChannelState::new(channel_id, vec![100, 0], vec![1, 2, 3], &params);

        // Compute the initial state commitment (hash) and insert it into the tree.
        let initial_leaf = hash_state(&initial_state).unwrap();
        tree.insert(initial_leaf)?;

        // Now, simulate a state transition: for example, the balances change.
        let new_state = ChannelState {
            balances: vec![95, 5],
            nonce: 1,
            metadata: vec![1, 2, 3],
            merkle_root: [0u8; 32], // This will be recalculated inside update_in_tree.
            proof: None,
        };

        // Compute the new state commitment.
        let new_leaf = hash_state(&new_state).unwrap();

        // Update the tree: replace the initial state commitment with the new one.
        tree.update(initial_leaf, new_leaf)?;
        let new_root = tree.root; // The updated tree root.

        // Generate a Merkle proof for the new state commitment.
        let proof = tree.get_proof(&new_leaf).unwrap();

        // Verify the Merkle proof.
        let verified = tree.verify_proof(&new_leaf, &proof, &new_root);
        assert!(verified, "Proof of new state should be valid");

        Ok(())
    }

    #[test]
    fn test_valid_transition() -> Result<()> {
        let initial_state = ChannelState {
            balances: vec![100, 0],
            nonce: 0,
            metadata: vec![],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let channel_id = [1u8; 32];
        let mut transition_data = [0u8; 32];
        transition_data[0..4].copy_from_slice(&(-10i32).to_le_bytes());
        transition_data[4..8].copy_from_slice(&(10i32).to_le_bytes());
        let result = apply_transition(channel_id, &initial_state, &transition_data)?;
        assert_eq!(result.balances[0], 90);
        assert_eq!(result.balances[1], 10);
        assert_eq!(result.nonce, 1);
        Ok(())
    }

    #[test]
    fn test_insufficient_funds() -> Result<()> {
        let initial_state = ChannelState {
            balances: vec![10, 0],
            nonce: 0,
            metadata: vec![],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let channel_id = [1u8; 32];
        let mut transition_data = [0u8; 32];
        transition_data[0..4].copy_from_slice(&(-20i32).to_le_bytes());
        transition_data[4..8].copy_from_slice(&(20i32).to_le_bytes());
        let result = apply_transition(channel_id, &initial_state, &transition_data);
        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.unwrap_err()),
            "Negative balance is not allowed"
        );
        Ok(())
    }

    #[test]
    fn test_nonce_overflow() -> Result<()> {
        let initial_state = ChannelState {
            balances: vec![100, 0],
            nonce: u64::MAX,
            metadata: vec![],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let channel_id = [1u8; 32];
        let mut transition_data = [0u8; 32];
        transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());
        let result = apply_transition(channel_id, &initial_state, &transition_data);
        assert!(result.is_err());
        assert_eq!(format!("{}", result.unwrap_err()), "Nonce overflow");
        Ok(())
    }

    #[test]
    fn test_negative_balance() -> Result<()> {
        let initial_state = ChannelState {
            balances: vec![10, 10],
            nonce: 0,
            metadata: vec![],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let channel_id = [1u8; 32];
        let mut transition_data = [0u8; 32];
        transition_data[0..4].copy_from_slice(&(-20i32).to_le_bytes());
        let result = apply_transition(channel_id, &initial_state, &transition_data);
        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.unwrap_err()),
            "Negative balance is not allowed"
        );
        Ok(())
    }
}
