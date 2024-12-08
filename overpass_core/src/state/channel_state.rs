use serde::{Deserialize, Serialize};
use plonky2::{
    hash::hash_types::HashOut,
    field::goldilocks_field::GoldilocksField,
};
use thiserror::Error;
use crate::smt::channel_sparse_merkle_tree::{SparseMerkleTreeChannel, MerkleTreeErrorChannel};

#[derive(Error, Debug)]
pub enum ChannelStateError {
    #[error("Invalid participant index")]
    InvalidParticipant,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Merkle tree error: {0}")]
    MerkleTreeError(#[from] MerkleTreeErrorChannel),
    #[error("Invalid state transition")]
    InvalidStateTransition,
}

// Wrapper type for HashOut serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashOutSerializable(#[serde(with = "hash_out_serde")] HashOut<GoldilocksField>);

impl From<HashOut<GoldilocksField>> for HashOutSerializable {
    fn from(hash: HashOut<GoldilocksField>) -> Self {
        HashOutSerializable(hash)
    }
}

impl From<HashOutSerializable> for HashOut<GoldilocksField> {
    fn from(hash: HashOutSerializable) -> Self {
        hash.0
    }
}

// Custom serialization for HashOut
mod hash_out_serde {
    use super::*;
    use plonky2_field::types::{Field, PrimeField64};
    use serde::{Serializer, Deserializer};
    use serde::de::Error;

    pub fn serialize<S>(
        hash: &HashOut<GoldilocksField>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = hash.elements
            .iter()
            .flat_map(|e| e.to_canonical_u64().to_le_bytes())
            .collect();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashOut<GoldilocksField>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("invalid hash length"));
        }

        let mut elements = [GoldilocksField::ZERO; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut bytes_arr = [0u8; 8];
            bytes_arr.copy_from_slice(chunk);
            elements[i] = GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes_arr));
        }

        Ok(HashOut { elements })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    pub siblings: Vec<HashOutSerializable>,
    pub value: Vec<u8>,
    pub key_fragments: Vec<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelState {
    pub balances: [u64; 2],
    pub nonce: u64,
    #[serde(with = "hash_out_serde")]
    pub merkle_root: HashOut<GoldilocksField>,
    pub proof: Option<SparseMerkleProof>,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            balances: [0, 0],
            nonce: 0,
            merkle_root: HashOut::ZERO,
            proof: None,
        }
    }
}

impl ChannelState {
    /// Creates a new channel state with initial balances
    pub fn new(initial_balances: [u64; 2]) -> Result<Self, ChannelStateError> {
        let mut tree = SparseMerkleTreeChannel::new(32);
        
        // Initialize tree with balances
        for (i, &balance) in initial_balances.iter().enumerate() {
            let key = [i as u8; 32];
            let value = balance.to_le_bytes();
            tree.update(&key, &value)?;
        }

        Ok(Self {
            balances: initial_balances,
            nonce: 0,
            merkle_root: tree.root,
            proof: None,
        })
    }

    /// Performs a transfer between participants
    pub fn transfer(&self, from: usize, to: usize, amount: u64) -> Result<Self, ChannelStateError> {
        // Validate indices
        if from >= 2 || to >= 2 {
            return Err(ChannelStateError::InvalidParticipant);
        }

        // Check balance
        if self.balances[from] < amount {
            return Err(ChannelStateError::InsufficientBalance);
        }

        // Update balances
        let mut new_balances = self.balances;
        new_balances[from] = new_balances[from]
            .checked_sub(amount)
            .ok_or(ChannelStateError::InsufficientBalance)?;
        new_balances[to] = new_balances[to]
            .checked_add(amount)
            .ok_or(ChannelStateError::InvalidStateTransition)?;

        // Update Merkle tree
        let mut tree = SparseMerkleTreeChannel::new(32);
        for (i, &balance) in new_balances.iter().enumerate() {
            let key = [i as u8; 32];
            let value = balance.to_le_bytes();
            tree.update(&key, &value)?;
        }

        // Generate proof for the sender's balance
        let proof = tree.generate_proof(&[from as u8; 32])?;
        
        Ok(Self {
            balances: new_balances,
            nonce: self.nonce + 1,
            merkle_root: tree.root,
            proof: Some(crate::state::channel_state::SparseMerkleProof {
                siblings: proof.siblings.into_iter().map(|h| h.into()).collect(),
                value: proof.value,
                key_fragments: proof.key_fragments,
            }),
        })
    }

    /// Verifies a state transition
    pub fn verify_state_transition(&self, next_state: &Self) -> Result<bool, ChannelStateError> {
        // Verify nonce increment
        if self.nonce + 1 != next_state.nonce {
            return Ok(false);
        }

        // Verify conservation of total balance
        let total_balance_self: u64 = self.balances.iter().sum();
        let total_balance_next: u64 = next_state.balances.iter().sum();
        if total_balance_self != total_balance_next {
            return Ok(false);
        }

        // Verify Merkle proof
        if let Some(proof) = &next_state.proof {
            let tree = SparseMerkleTreeChannel::new(32);
            let smt_proof = crate::smt::channel_sparse_merkle_tree::SparseMerkleProofChannel {
                siblings: proof.siblings.iter().map(|h| h.clone().into()).collect(),
                value: proof.value.clone(),
                key_fragments: proof.key_fragments.clone(),
            };
            tree.verify_proof(&smt_proof)
                .map_err(ChannelStateError::from)
        } else {
            Ok(false)
        }
    }

    /// Gets the balance for a participant
    pub fn get_balance(&self, participant: usize) -> Result<u64, ChannelStateError> {
        if participant >= 2 {
            return Err(ChannelStateError::InvalidParticipant);
        }
        Ok(self.balances[participant])
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_channel_state() -> Result<(), ChannelStateError> {
        let initial_balances = [100, 200];
        let state = ChannelState::new(initial_balances)?;
        
        assert_eq!(state.balances, initial_balances);
        assert_eq!(state.nonce, 0);
        assert!(state.proof.is_none());
        Ok(())
    }

    #[test]
    fn test_valid_transfer() -> Result<(), ChannelStateError> {
        let initial_balances = [100, 200];
        let state = ChannelState::new(initial_balances)?;
        
        let next_state = state.transfer(0, 1, 50)?;
        
        assert_eq!(next_state.balances, [50, 250]);
        assert_eq!(next_state.nonce, 1);
        assert!(next_state.proof.is_some());
        assert!(state.verify_state_transition(&next_state)?);
        Ok(())
    }

    #[test]
    fn test_insufficient_balance() {
        let initial_balances = [100, 200];
        let state = ChannelState::new(initial_balances).unwrap();
        
        assert!(matches!(
            state.transfer(0, 1, 150),
            Err(ChannelStateError::InsufficientBalance)
        ));
    }

    #[test]
    fn test_invalid_participant() {
        let initial_balances = [100, 200];
        let state = ChannelState::new(initial_balances).unwrap();
        
        assert!(matches!(
            state.transfer(2, 1, 50),
            Err(ChannelStateError::InvalidParticipant)
        ));
        
        assert!(matches!(
            state.transfer(0, 2, 50),
            Err(ChannelStateError::InvalidParticipant)
        ));
    }

    #[test]
    fn test_balance_overflow() {
        let initial_balances = [100, u64::MAX];
        let state = ChannelState::new(initial_balances).unwrap();
        
        assert!(matches!(
            state.transfer(0, 1, 50),
            Err(ChannelStateError::InvalidStateTransition)
        ));
    }
}