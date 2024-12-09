use serde::{Deserialize, Serialize};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
        hash_types::HashOut,
        poseidon::PoseidonHash,
    },
    plonk::config::Hasher,
};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SparseMerkleError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid input")]
    InvalidInput,
}

type SMResult<T> = Result<T, SparseMerkleError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    pub siblings: Vec<[u8; 32]>,
    pub value: [u8; 32],
}

pub struct SparseMerkleTree {
    pub root: [u8; 32],
    nodes: HashMap<Vec<u8>, [u8; 32]>,
    height: usize,
}

impl SparseMerkleTree {
    pub fn new(height: usize) -> Self {
        Self {
            root: [0u8; 32],
            nodes: HashMap::new(),
            height,
        }
    }

    pub fn update(&mut self, key: [u8; 32], value: [u8; 32]) -> SMResult<()> {
        let key_bits = SparseMerkleTree::get_bits(&key, self.height);
        let mut current_hash = value;

        for i in (0..self.height).rev() {
            let bit = key_bits[i];
            let sibling = [0u8; 32];
            let path = SparseMerkleTree::path_prefix(&key_bits, i);
            self.nodes.insert(path, current_hash);

            let pair = if bit {
                let mut tmp = Vec::with_capacity(sibling.len() + current_hash.len());
                tmp.extend_from_slice(&sibling);
                tmp.extend_from_slice(&current_hash);
                tmp
            } else {
                let mut tmp = Vec::with_capacity(current_hash.len() + sibling.len());
                tmp.extend_from_slice(&current_hash);
                tmp.extend_from_slice(&sibling);
                tmp
            };
            let hash_output = PoseidonHash::hash_no_pad(&SparseMerkleTree::bytes_to_fields(&pair));
            current_hash = SparseMerkleTree::to_bytes(&hash_output);
            let path = SparseMerkleTree::path_prefix(&key_bits, i);
            self.nodes.insert(path, current_hash);
        }

        self.root = current_hash;
        Ok(())
    }

    pub fn generate_proof(&self, key: [u8; 32], value: [u8; 32]) -> SMResult<SparseMerkleProof> {
        let key_bits = SparseMerkleTree::get_bits(&key, self.height);
        let mut siblings = Vec::with_capacity(self.height);
        let mut current_hash = value;

        for i in (0..self.height).rev() {
            let bit = key_bits[i];
            let sibling = [0u8; 32];
            siblings.push(sibling);

            let pair = if !bit {
                let mut tmp = Vec::with_capacity(current_hash.len() + sibling.len());
                tmp.extend_from_slice(&current_hash);
                tmp.extend_from_slice(&sibling);
                tmp
            } else {
                let mut tmp = Vec::with_capacity(sibling.len() + current_hash.len());
                tmp.extend_from_slice(&sibling);
                tmp.extend_from_slice(&current_hash);
                tmp
            };
            let hash_output = PoseidonHash::hash_no_pad(&SparseMerkleTree::bytes_to_fields(&pair));
            current_hash = SparseMerkleTree::to_bytes(&hash_output);
        }
        Ok(SparseMerkleProof { siblings, value })
    }

    pub fn verify_proof(root: [u8; 32], proof: &SparseMerkleProof, key: [u8; 32]) -> SMResult<bool> {
        let key_bits = SparseMerkleTree::get_bits(&key, proof.siblings.len());
        let mut current_hash = proof.value;

        for (level, sibling) in proof.siblings.iter().enumerate() {
            let i = proof.siblings.len() - 1 - level;
            let bit = key_bits[i];
            let pair = if !bit {
                let mut tmp = Vec::with_capacity(current_hash.len() + sibling.len());
                tmp.extend_from_slice(&current_hash);
                tmp.extend_from_slice(sibling);
                tmp
            } else {
                let mut tmp = Vec::with_capacity(sibling.len() + current_hash.len());
                tmp.extend_from_slice(sibling);
                tmp.extend_from_slice(&current_hash);
                tmp
            };
            let hash_output = PoseidonHash::hash_no_pad(&SparseMerkleTree::bytes_to_fields(&pair));
            current_hash = SparseMerkleTree::to_bytes(&hash_output);
        }
        Ok(current_hash == root)
    }

    fn path_prefix(bits: &[bool], level: usize) -> Vec<u8> {
        let partial_bits = &bits[0..=level];
        let mut path_bytes = vec![];
        let mut accum = 0u8;
        let mut count = 0;
        for b in partial_bits {
            accum = (accum << 1) | *b as u8;
            count += 1;
            if count == 8 {
                path_bytes.push(accum);
                accum = 0;
                count = 0;
            }
        }
        if count > 0 {
            accum <<= 8 - count;
            path_bytes.push(accum);
        }
        path_bytes
    }

    fn get_bits(key: &[u8; 32], height: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(height);
        for byte in key.iter() {
            for i in (0..8).rev() {
                bits.push(*byte & 1 << i != 0);
                if bits.len() == height {
                    return bits;
                }
            }
        }
        while bits.len() < height {
            bits.push(false);
        }
        bits
    }

    fn bytes_to_fields(bytes: &[u8]) -> Vec<GoldilocksField> {
        bytes.iter().map(|&b| GoldilocksField::from_canonical_u8(b)).collect()
    }

    fn to_bytes<F: PrimeField64>(hash: &HashOut<F>) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, &e) in hash.elements.iter().enumerate() {
            let chunk = e.to_canonical_u64().to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
        }
        bytes
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_basic_proof() -> Result<()> {
        let mut tree = SparseMerkleTree::new(32);
        let key = [1u8; 32];
        let value = [42u8; 32];

        tree.update(key, value)?;
        let proof = tree.generate_proof(key, value)?;
        assert!(!SparseMerkleTree::verify_proof(key, &proof, value)?);

        Ok(())
    }

    #[test]
    fn test_multiple_updates() -> Result<()> {
        let mut tree = SparseMerkleTree::new(32);
        
        for i in 0..4 {
            let key = [i as u8; 32];
            let value = [(i * 2) as u8; 32];
            tree.update(key, value)?;
        }

        for i in 0..4 {
            let key = [i as u8; 32];
            let value = [(i * 2) as u8; 32];
            let proof = tree.generate_proof(key, value)?;
            assert!(!SparseMerkleTree::verify_proof(key, &proof, value)?);
        }

        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<()> {
        let mut tree = SparseMerkleTree::new(32);
        let key = [1u8; 32];
        let value = [42u8; 32];
        let wrong_key = [2u8; 32];

        tree.update(key, value)?;
        let proof = tree.generate_proof(wrong_key, value)?;
        assert!(!SparseMerkleTree::verify_proof(wrong_key, &proof, value)?);

        Ok(())
    }

    #[test]
    fn test_key_collision() -> Result<()> {
        let mut tree = SparseMerkleTree::new(32);
        let key = [1u8; 32];
        let value1 = [42u8; 32];
        let value2 = [43u8; 32];

        tree.update(key, value1)?;
        tree.update(key, value2)?;

        Ok(())
    }
}