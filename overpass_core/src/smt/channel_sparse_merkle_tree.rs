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
use std::{collections::HashMap, num::NonZero};
use lru::LruCache;
use thiserror::Error;


#[derive(Error, Debug)]
pub enum MerkleTreeErrorChannel {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid value length")]
    InvalidValueLength,
    #[error("Invalid proof length")]
    InvalidProofLength,
    #[error("Hashing error: {0}")]
    HashingError(String),
    #[error("Key collision detected")]
    KeyCollision,
    #[error("Invalid node state")]
    InvalidNodeState,
    #[error("Cache error: {0}")]
    CacheError(String),
}

#[derive(Debug, Clone)]
pub struct SparseMerkleProofChannel {
    pub siblings: Vec<HashOut<GoldilocksField>>,
    pub value: Vec<u8>,
    pub key_fragments: Vec<bool>,
}

pub struct SparseMerkleTreeChannel {
    pub root: HashOut<GoldilocksField>,
    nodes: HashMap<Vec<bool>, HashOut<GoldilocksField>>,
    node_cache: LruCache<Vec<bool>, HashOut<GoldilocksField>>,
    height: usize,
    max_cache_size: usize,
}

impl SparseMerkleTreeChannel {
    pub fn new(height: usize) -> Self {
        Self {
            root: HashOut::ZERO,
            nodes: HashMap::new(),
            node_cache: LruCache::new(NonZero::new(1000).unwrap()), // Configurable cache size
            height,
            max_cache_size: 1000,
        }
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), MerkleTreeErrorChannel> {
        let key_fragments = self.get_key_fragments(key)?;
        
        // Check for existing value to prevent key collisions
        if let Some(existing_value) = self.get_value(key)? {
            if existing_value != value {
                return Err(MerkleTreeErrorChannel::KeyCollision);
            }
        }
        
        let value_field = self.value_to_field(value)?;
        let mut current_hash = value_field;

        for (level, &bit) in key_fragments.iter().enumerate().rev() {
            let sibling = self.get_cached_node(&key_fragments[..level])
                .unwrap_or(HashOut::ZERO);

            current_hash = self.hash_pair(
                if bit { sibling } else { current_hash },
                if bit { current_hash } else { sibling },
            )?;

            let path = key_fragments[..=level].to_vec();
            self.nodes.insert(path.clone(), current_hash);
            self.update_cache(&path, current_hash)?;
        }

        self.root = current_hash;
        Ok(())
    }

    pub fn generate_proof(&self, key: &[u8]) -> Result<SparseMerkleProofChannel, MerkleTreeErrorChannel> {  
        let key_fragments = self.get_key_fragments(key)?;
        if key_fragments.len() != self.height {
            return Err(MerkleTreeErrorChannel::InvalidKeyLength);
        }

        let mut siblings = Vec::with_capacity(self.height);

        for i in 0..self.height {
            let mut sibling_path = key_fragments[..i].to_vec();
            sibling_path.push(!key_fragments[i]);
            let sibling = self.get_cached_node(&sibling_path)
                .unwrap_or(HashOut::ZERO);
            siblings.push(sibling);
        }

        Ok(SparseMerkleProofChannel {
            siblings,
            value: self.get_value(key)?.unwrap_or_default(),
            key_fragments,
        })
    }

    pub fn verify_proof(&self, proof: &SparseMerkleProofChannel) -> Result<bool, MerkleTreeErrorChannel> {
        if proof.siblings.len() != self.height {
            return Err(MerkleTreeErrorChannel::InvalidProofLength);
        }

        if proof.key_fragments.len() != self.height {
            return Err(MerkleTreeErrorChannel::InvalidKeyLength);
        }

        let mut current_hash = self.value_to_field(&proof.value)?;

        for (i, sibling) in proof.siblings.iter().enumerate().rev() {
            let bit = proof.key_fragments[i];
            current_hash = self.hash_pair(
                if bit { *sibling } else { current_hash },
                if bit { current_hash } else { *sibling },
            )?;
        }

        Ok(current_hash == self.root)
    }

    fn get_key_fragments(&self, key: &[u8]) -> Result<Vec<bool>, MerkleTreeErrorChannel> {
        let required_bytes = (self.height + 7) / 8;
        if key.len() < required_bytes {
            return Err(MerkleTreeErrorChannel::InvalidKeyLength);
        }

        let mut fragments = Vec::with_capacity(self.height);
        
        for byte in key.iter().take((self.height + 7) / 8) {
            for i in (0..8).rev() {
                fragments.push((*byte & (1 << i)) != 0);
                if fragments.len() == self.height {
                    return Ok(fragments);
                }
            }
        }

        Ok(fragments)
    }

    fn get_cached_node(&self, path: &[bool]) -> Option<HashOut<GoldilocksField>> {
        self.node_cache
            .peek(&path.to_vec())
            .copied()
            .or_else(|| self.nodes.get(path).copied())
    }

    fn update_cache(&mut self, path: &Vec<bool>, hash: HashOut<GoldilocksField>) -> Result<(), MerkleTreeErrorChannel> {
        if self.node_cache.len() >= self.max_cache_size {
            self.node_cache.pop_lru();
        }
        self.node_cache.put(path.clone(), hash);
        Ok(())
    }

    fn get_node(&self, path: &[bool]) -> Option<HashOut<GoldilocksField>> {
        self.get_cached_node(path)
    }

    fn get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, MerkleTreeErrorChannel> {
        let key_fragments = self.get_key_fragments(key)?;
        Ok(self.nodes.get(&key_fragments)
            .map(|hash| field_to_bytes(hash)))
    }

    fn hash_pair(
        &self,
        left: HashOut<GoldilocksField>,
        right: HashOut<GoldilocksField>,
    ) -> Result<HashOut<GoldilocksField>, MerkleTreeErrorChannel> {
        let input = [
            left.elements.to_vec(),
            right.elements.to_vec(),
        ].concat();

        Ok(PoseidonHash::hash_no_pad(&input))
    }

    fn value_to_field(&self, value: &[u8]) -> Result<HashOut<GoldilocksField>, MerkleTreeErrorChannel> {
        if value.len() > 32 {
            return Err(MerkleTreeErrorChannel::InvalidValueLength);
        }

        let mut field_elements = Vec::new();
        for chunk in value.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            field_elements.push(GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes)));
        }

        while field_elements.len() < 4 {
            field_elements.push(GoldilocksField::ZERO);
        }

        Ok(HashOut {
            elements: field_elements.try_into().map_err(|_| MerkleTreeErrorChannel::InvalidNodeState)?
        })
    }
}

fn field_to_bytes(hash: &HashOut<GoldilocksField>) -> Vec<u8> {
    hash.elements
        .iter()
        .flat_map(|&e| e.to_canonical_u64().to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_proof() -> Result<(), MerkleTreeErrorChannel> {
        let mut tree = SparseMerkleTreeChannel::new(32);
        let key = [1u8; 32];
        let value = [42u8; 32];

        tree.update(&key, &value)?;
        let proof = tree.generate_proof(&key)?;
        assert!(tree.verify_proof(&proof)?);

        Ok(())
    }

    #[test]
    fn test_multiple_updates() -> Result<(), MerkleTreeErrorChannel> {
        let mut tree = SparseMerkleTreeChannel::new(32);
        
        for i in 0..4 {
            let key = [i as u8; 32];
            let value = [(i * 2) as u8; 32];
            tree.update(&key, &value)?;
        }

        for i in 0..4 {
            let key = [i as u8; 32];
            let proof = tree.generate_proof(&key)?;
            assert!(tree.verify_proof(&proof)?);
        }

        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<(), MerkleTreeErrorChannel> {
        let mut tree = SparseMerkleTreeChannel::new(32);
        let key = [1u8; 32];
        let value = [42u8; 32];
        let wrong_key = [2u8; 32];

        tree.update(&key, &value)?;
        let proof = tree.generate_proof(&wrong_key)?;
        assert!(!tree.verify_proof(&proof)?);

        Ok(())
    }

    #[test]
    fn test_key_collision() -> Result<(), MerkleTreeErrorChannel> {
        let mut tree = SparseMerkleTreeChannel::new(32);
        let key = [1u8; 32];
        let value1 = [42u8; 32];
        let value2 = [43u8; 32];

        tree.update(&key, &value1)?;
        assert!(tree.update(&key, &value2).is_err());

        Ok(())
    }
}