// src/zkp/channel.rs
//! Channel state management and operations
//!
//! This module provides functionality for managing unidirectional
//! state channels.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::commitments::generate_random_blinding;
use crate::commitments::pedersen_commit;
use crate::error::ChannelError;
use crate::merkle::compute_channel_root;
use crate::pedersen_parameters::PedersenParameters;
use crate::state::generate_state_proof;
use crate::state::hash_state;
use crate::state_proof;
use crate::tree::MerkleTree;
use crate::tree::MerkleTreeError;
use crate::types::Bytes32;

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
    /// ZKP proof for state verification
    pub proof: Option<Vec<u8>>,
}

impl ChannelState {
    /// Creates a new unidirectional state channel `ChannelState`
    /// with the given initial `sender_balance` and `metadata`.
    /// The `receiver_balance` starts at 0 as a constructor invariant.
    /// `metadata` is the metadata for the channel.
    ///
    /// Returns an error if the initial sender balance is zero.
    pub fn new(sender_balance: u64, metadata: Vec<u8>) -> Result<Self, ChannelError> {
        if sender_balance == 0 {
            return Err(ChannelError::InvalidZeroBalance);
        }

        // TODO: Consider making params static
        let params = PedersenParameters::default();

        // Compute Pedersen commitment for channel state
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

        Ok(Self {
            sender_balance,
            receiver_balance: 0,
            nonce: 0,
            metadata,
            proof,
        })
    }

    /// Create a new state by transferring amount from sender to receiver
    pub fn transfer(&self, amount: u64) -> Result<Self, ChannelError> {
        if amount == 0 {
            return Err(ChannelError::InvalidZeroTransfer);
        }

        let mut next_state = self.clone();

        let next_sender_balance = self
            .sender_balance
            .checked_sub(amount)
            .ok_or(ChannelError::InsufficientBalance)?;
        let next_receiver_balance = self
            .receiver_balance
            .checked_add(amount)
            .ok_or(ChannelError::BalanceOverflow)?;

        next_state.sender_balance = next_sender_balance;
        next_state.receiver_balance = next_receiver_balance;
        next_state.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(ChannelError::ChannelNonceOverflow)?;

        Ok(next_state)
    }

    // Apply the transfer to the channel state
    pub fn apply_transfer(&mut self, channel_id: Bytes32, amount: u64) -> Result<(), ChannelError> {
        let old_state = self.clone();
        *self = self.transfer(amount)?;

        // Generate proof for the state transition
        let proof = self
            .generate_transition_proof(channel_id, &old_state)
            .map_err(|_| ChannelError::InvalidBalanceChange)?;

        self.proof = Some(proof);
        Ok(())
    }

    pub fn transfer_with_proof(
        &mut self,
        channel_id: Bytes32,
        amount: u64,
    ) -> Result<(), anyhow::Error> {
        let new_state = self.transfer(amount)?;
        let proof = new_state.generate_transition_proof(channel_id, self)?;

        // Update self
        *self = new_state;
        self.proof = Some(proof);

        Ok(())
    }

    /// Verifies that the transition from prior to self is valid.
    /// Used for external state validation (network messages, etc.)
    pub fn verify_transition(&self, prior: &ChannelState) -> Result<(), ChannelError> {
        // Verify nonce increment
        let expected_nonce = prior
            .nonce
            .checked_add(1)
            .ok_or(ChannelError::ChannelNonceOverflow)?;

        if self.nonce != expected_nonce {
            return Err(ChannelError::InvalidNonceIncrement);
        }

        // Verify balance conservation (total balance should remain the same)
        let old_total = prior.sender_balance + prior.receiver_balance;
        let new_total = self.sender_balance + self.receiver_balance;

        if old_total != new_total {
            return Err(ChannelError::InvalidBalanceChange);
        }

        Ok(())
    }

    // Generate commitment for the channel
    pub fn generate_commitment(&self) -> (Bytes32, Bytes32) {
        let blinding = generate_random_blinding();
        let params = PedersenParameters::default();
        let commitment = pedersen_commit(
            self.sender_balance,
            self.receiver_balance,
            blinding,
            &params,
        );
        (commitment, blinding)
    }

    // Generate state proof for the channel
    pub fn generate_state_proof(
        &self,
        channel_id: Bytes32,
        old_commitment: Bytes32,
        new_commitment: Bytes32,
    ) -> Result<crate::state::StateProof, anyhow::Error> {
        let params = PedersenParameters::default();
        let proof = generate_state_proof(
            old_commitment,
            new_commitment,
            self.compute_merkle_root(channel_id)?,
            &params,
        );
        Ok(proof) // Return the state::StateProof directly, don't convert
    }

    // Verify a ZK proof
    pub fn verify_proof(&self, proof: &Bytes32, public_inputs: &[Bytes32]) -> bool {
        let params = PedersenParameters::default();
        crate::state::verify_zk_proof(proof, public_inputs, &params)
    }

    /// Generate proof for this state transition
    pub fn generate_transition_proof(
        &self,
        channel_id: Bytes32,
        prior: &ChannelState,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // Verify transition first
        self.verify_transition(prior)?;

        let (old_commitment, _) = prior.generate_commitment();
        let (new_commitment, _) = self.generate_commitment();

        let state_proof = self.generate_state_proof(channel_id, old_commitment, new_commitment)?;
        Ok(state_proof.pi.to_vec())
    }

    /// Updates the Sparse Merkle Tree with the new state.
    pub fn update_in_tree(
        &self,
        smt: &mut MerkleTree,
        old_state: &ChannelState,
    ) -> Result<(Bytes32, Bytes32), MerkleTreeError> {
        if !self.verify_transition(old_state).is_ok() {
            return Err(MerkleTreeError::InvalidInput(
                "Invalid state transition".to_string(),
            ));
        }

        let old_leaf =
            hash_state(old_state).map_err(|e| MerkleTreeError::InvalidInput(e.to_string()))?;
        let new_leaf =
            hash_state(self).map_err(|e| MerkleTreeError::InvalidInput(e.to_string()))?;

        smt.update(old_leaf, new_leaf)?;

        let new_root = smt.root;

        Ok((new_leaf, new_root))
    }

    /// Check if the channel has a valid proof
    pub fn has_valid_proof(&self) -> bool {
        self.proof.is_some()
    }

    /// Computes the merkle root for a channel given its ID, current state hash, and nonce.
    pub fn compute_merkle_root(&self, channel_id: Bytes32) -> Result<Bytes32, anyhow::Error> {
        let hash = hash_state(self)?;
        Ok(compute_channel_root(channel_id, hash, self.nonce))
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
            proof: None,
        }
    }

    #[test]
    fn test_new() {
        let sender_balance = 100;
        let metadata = vec![1, 2, 3];
        let channel = ChannelState::new(sender_balance, metadata.clone()).unwrap();

        // Test constructor
        assert_eq!(channel.sender_balance, sender_balance);
        assert_eq!(channel.receiver_balance, 0);
        assert_eq!(channel.metadata, metadata);
        assert_eq!(channel.nonce, 0);
        assert!(channel.proof.is_some());
        assert!(channel.has_valid_proof());
    }

    #[test]
    fn test_new_simple() {
        let sender_balance = 100;
        let channel = ChannelState::new(sender_balance, Vec::new()).unwrap();

        // Test constructor
        assert_eq!(channel.sender_balance, sender_balance);
        assert_eq!(channel.receiver_balance, 0);
        assert_eq!(channel.metadata, Vec::<u8>::new());
        assert_eq!(channel.nonce, 0);
        assert!(channel.has_valid_proof());
    }

    #[test]
    fn test_verify_transition() {
        let old = create_state(100, 0, 0);
        let new = create_state(90, 10, 1);

        let transition_result = new.verify_transition(&old);
        assert!(transition_result.is_ok());

        // Test invalid nonce increment
        let invalid_nonce = create_state(90, 10, 2);
        let invalid_nonce_result = invalid_nonce.verify_transition(&old);
        assert!(invalid_nonce_result.is_err());

        // Test invalid balance total
        let invalid_balance = create_state(90, 15, 1);
        let invalid_balance_result = invalid_balance.verify_transition(&old);
        assert!(invalid_balance_result.is_err());

        // Test nonce overflow
        let max_nonce = create_state(100, 0, u64::MAX);
        let overflow = create_state(90, 10, 0);
        let overflow_result = overflow.verify_transition(&max_nonce);
        assert!(overflow_result.is_err());
    }

    #[test]
    fn test_transfer() {
        let channel = ChannelState::new(100, Vec::new()).unwrap();

        // Test successful transfer
        let transfer_result = channel.transfer(30);
        let new_channel = transfer_result.unwrap();
        assert_eq!(new_channel.sender_balance, 70);
        assert_eq!(new_channel.receiver_balance, 30);
        assert_eq!(new_channel.nonce, 1);
        assert!(new_channel.has_valid_proof());

        // Test insufficient balance
        let insufficient_result = new_channel.transfer(80);
        assert!(insufficient_result.is_err());

        // Test zero transfer
        let zero_result = new_channel.transfer(0);
        assert!(zero_result.is_err());
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
