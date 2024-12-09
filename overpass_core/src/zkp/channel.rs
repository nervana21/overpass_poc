use plonky2::field::types::Field;
use plonky2_field::types::PrimeField64;
use serde::{Deserialize, Serialize};
use crate::zkp::tree::{SparseMerkleError, SparseMerkleTree};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelState {
    pub balances: Vec<u64>,     // e.g., multiple participants
    pub nonce: u64,
    pub metadata: Vec<u8>,
}

impl ChannelState {
    pub fn is_valid(&self) -> bool {
        !self.balances.is_empty()
    }

    pub fn hash_state(&self) -> [u8; 32] {
        use plonky2::field::goldilocks_field::GoldilocksField;
        use plonky2::hash::poseidon::PoseidonHash;
        use plonky2::plonk::config::Hasher;

        let mut inputs = vec![];
        for &b in &self.balances {
            let fe = GoldilocksField::from_canonical_u64(b);
            inputs.push(fe);
        }
        inputs.push(GoldilocksField::from_canonical_u64(self.nonce));
        let meta_sum = self.metadata.iter().fold(0u64, |acc, &x| acc + (x as u64));
        inputs.push(GoldilocksField::from_canonical_u64(meta_sum));

        let hash_out = PoseidonHash::hash_no_pad(&inputs);
        let mut leaf = [0u8; 32];
        for (i, &element) in hash_out.elements.iter().enumerate() {
            let chunk = element.to_canonical_u64().to_le_bytes();
            leaf[i*8..(i+1)*8].copy_from_slice(&chunk);
        }
        leaf
    }

    pub fn verify_transition(&self, old_state: &ChannelState) -> bool {
        if self.nonce <= old_state.nonce {
            return false;
        }
        if !self.is_valid() || !old_state.is_valid() {
            return false;
        }
        true
    }

    pub fn update_in_tree(
        &self,
        smt: &mut SparseMerkleTree,
        old_state: &ChannelState,
        old_key: [u8; 32],
        _new_key: [u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), SparseMerkleError> {
        if !self.verify_transition(old_state) {
            return Err(SparseMerkleError::InvalidInput);
        }

        let new_leaf = self.hash_state();

        smt.update(old_key, new_leaf)?;

        let new_root = smt.root;

        Ok((new_leaf, new_root))
    }}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::tree::SparseMerkleTree;

    #[test]
    fn test_state_transition_with_smt() {
        let mut smt = SparseMerkleTree::new(32);

        let old_state = ChannelState {
            balances: vec![100, 50],
            nonce: 15,
            metadata: vec![1,2,3],
        };
        let old_key = [1u8; 32];
        let old_leaf = old_state.hash_state();

        smt.update(old_key, old_leaf).unwrap();

        let new_state = ChannelState {
            balances: vec![97, 53],
            nonce: 16,
            metadata: vec![1,2,3,4],
        };
        let new_key = old_key;

        let (new_leaf, new_root) = new_state.update_in_tree(&mut smt, &old_state, old_key, new_key).unwrap();

        let proof = smt.generate_proof(new_key, new_leaf).unwrap();
        let verified = SparseMerkleTree::verify_proof(new_root, &proof, new_key).unwrap();
        assert!(verified, "Proof of new state should be valid");
    }
}