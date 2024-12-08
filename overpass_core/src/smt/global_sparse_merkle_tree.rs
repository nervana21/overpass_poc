use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum MerkleTreeErrorGlobal {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
    #[error("Cache error")]
    CacheError,
    #[error("Hashing error")]
    HashingError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleProoGlobal {
    pub path: Vec<Vec<u8>>,
    pub value: Vec<u8>,
    pub siblings: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleTreeGlobal {
    pub root: [u8; 32],
    nodes: HashMap<Vec<u8>, Vec<u8>>,
    #[serde(skip)]
    cache: HashMap<Vec<u8>, Vec<u8>>, // Manual cache replacement to avoid LruCache serialization issues
    height: usize,
}

impl Default for SparseMerkleTreeGlobal {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SparseMerkleTreeGlobal {
    pub fn new(height: usize) -> Self {
        let empty_root = [0u8; 32];
        Self {
            root: empty_root,
            nodes: HashMap::new(),
            cache: HashMap::new(),
            height,
        }
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), MerkleTreeErrorGlobal> {
        if key.is_empty() || value.is_empty() {
            return Err(MerkleTreeErrorGlobal::InvalidKey("Key or value cannot be empty".to_string()));
        }

        let mut current_hash = value.to_vec();
        let key_bits = self.get_bits(key);

        for i in (0..self.height).rev() {
            let bit = key_bits[i];
            let sibling = vec![0u8; 32];

            let pair = if bit {
                [sibling.as_slice(), current_hash.as_slice()].concat()
            } else {
                [current_hash.as_slice(), sibling.as_slice()].concat()
            };

            let hash_output = PoseidonHash::hash_no_pad(&bytes_to_fields(&pair));
            current_hash = hash_out_to_bytes(&hash_output);
            let path_key = self.path_key(key, i);
            self.nodes.insert(path_key.clone(), current_hash.clone());
            self.cache.insert(path_key, current_hash.clone());
        }

        self.root.copy_from_slice(&current_hash);
        Ok(())
    }

    pub fn generate_proof(&self, key: &[u8]) -> Result<SparseMerkleProoGlobal, MerkleTreeErrorGlobal> {
        if key.is_empty() {
            return Err(MerkleTreeErrorGlobal::InvalidKey("Key cannot be empty".to_string()));
        }

        let mut path = Vec::new();
        let mut siblings = Vec::new();
        let key_bits = self.get_bits(key);
        let value = self.get_value(key)?;

        for i in 0..self.height {
            let sibling_key = self.path_key(key, i);
            let sibling = self
                .cache
                .get(&sibling_key)
                .or_else(|| self.nodes.get(&sibling_key))
                .cloned()
                .unwrap_or_else(|| vec![0u8; 32]);
            path.push(sibling.clone());
            siblings.push(sibling);
        }

        Ok(SparseMerkleProoGlobal {
            path,
            value,
            siblings,
        })
    }

    pub fn verify_proof(root: &[u8; 32], proof: &SparseMerkleProoGlobal, key: &[u8]) -> Result<bool, MerkleTreeErrorGlobal> {
        if key.is_empty() || proof.path.is_empty() {
            return Err(MerkleTreeErrorGlobal::InvalidProof);
        }

        let mut current_hash = proof.value.clone();
        let key_bits = Self::get_bits_static(key, proof.path.len());

        for (i, sibling) in proof.path.iter().enumerate().rev() {
            if sibling.len() != 32 {
                return Err(MerkleTreeErrorGlobal::InvalidProof);
            }

            let pair = if key_bits[i] {
                [sibling.as_slice(), current_hash.as_slice()].concat()
            } else {
                [current_hash.as_slice(), sibling.as_slice()].concat()
            };

            let hash_output = PoseidonHash::hash_no_pad(&bytes_to_fields(&pair));
            current_hash = hash_out_to_bytes(&hash_output);
        }

        Ok(current_hash == root.to_vec())
    }

    fn get_value(&self, key: &[u8]) -> Result<Vec<u8>, MerkleTreeErrorGlobal> {
        let path_key = self.path_key(key, 0);
        self.nodes
            .get(&path_key)
            .cloned()
            .ok_or_else(|| MerkleTreeErrorGlobal::InvalidKey(format!("Key not found: {:?}", key)))
    }

    fn get_bits(&self, key: &[u8]) -> Vec<bool> {
        Self::get_bits_static(key, self.height)
    }

    fn get_bits_static(key: &[u8], height: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(height);
        for byte in key {
            for i in (0..8).rev() {
                bits.push((*byte & (1 << i)) != 0);
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

    fn path_key(&self, key: &[u8], level: usize) -> Vec<u8> {
        let mut path_key = key.to_vec();
        path_key.push(level as u8);
        path_key
    }
}

fn bytes_to_fields(bytes: &[u8]) -> Vec<GoldilocksField> {
    bytes.iter().map(|&b| GoldilocksField::from_canonical_u8(b)).collect()
}

fn hash_out_to_bytes<F: PrimeField64>(hash: &HashOut<F>) -> Vec<u8> {
    hash.elements.iter().flat_map(|&e| e.to_canonical_u64().to_le_bytes()).collect()
}