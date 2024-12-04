use crate::circuit::{
    global_merkle_circuit::{GlobalMerkleCircuitError},
    transfer_circuit::GlobalCircuitError,
};
use serde::{Deserialize, Serialize};
use plonky2::{
    hash::{
        hash_types::HashOut,
        poseidon::PoseidonHash,
    },
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    plonk::config::Hasher,
};
use rand::Rng;
use thiserror::Error;
use std::collections::HashMap;
use anyhow::Result;

#[derive(Error, Debug)]
pub enum GlobalStateError {
    #[error("Circuit error: {0}")]
    CircuitError(#[from] GlobalCircuitError),
    #[error("Invalid state transition")]
    InvalidStateTransition,
    #[error("Balance overflow")]
    BalanceOverflow,
    #[error("Merkle proof verification failed")]
    ProofVerificationFailed,
    #[error("Global Merkle Circuit error: {0}")]
    GlobalMerkleCircuitError(#[from] GlobalMerkleCircuitError),
    #[error("System error: {0}")]
    SystemError(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Default)]
pub struct SparseMerkleTreeGlobal {
    pub root: [u8; 32],
    nodes: HashMap<Vec<u8>, Vec<u8>>,
    height: usize,
}

impl SparseMerkleTreeGlobal {
    pub fn new(height: usize) -> Self {
        Self {
            root: [0u8; 32],
            nodes: HashMap::new(),
            height,
        }
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), GlobalStateError> {
        let mut current_hash = value.to_vec();
        let _key_bits = Self::get_bits_static(key, self.height);

        for i in (0..self.height).rev() {
            let bit = _key_bits[i];
            let sibling = vec![0u8; 32];

            let pair = if bit {
                [sibling.as_slice(), current_hash.as_slice()].concat()
            } else {
                [current_hash.as_slice(), sibling.as_slice()].concat()
            };

            let hash_output = PoseidonHash::hash_no_pad(&Self::bytes_to_fields(&pair));
            current_hash = Self::hash_out_to_bytes(&hash_output);
            let path_key = Self::path_key(key, i);
            self.nodes.insert(path_key.clone(), current_hash.clone());
        }

        self.root.copy_from_slice(&current_hash);
        Ok(())
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

    fn bytes_to_fields(bytes: &[u8]) -> Vec<GoldilocksField> {
        bytes.iter().map(|&b| GoldilocksField::from_canonical_u8(b)).collect()
    }

    fn hash_out_to_bytes<F: PrimeField64>(hash: &HashOut<F>) -> Vec<u8> {
        hash.elements.iter().flat_map(|&e| e.to_canonical_u64().to_le_bytes()).collect()
    }

    fn path_key(key: &[u8], level: usize) -> Vec<u8> {
        let mut path_key = key.to_vec();
        path_key.push(level as u8);
        path_key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalState {
    pub balance: u64,
    pub nonce: u64,
    pub merkle_root: [u8; 32],
    #[serde(skip)] // Skip serialization for runtime state
    pub merkle_tree: SparseMerkleTreeGlobal,
}

impl Default for GlobalState {
    fn default() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            merkle_tree: SparseMerkleTreeGlobal::default(),
        }
    }
}

impl GlobalState {
    pub fn new() -> Self {
        let nonce = rand::thread_rng().gen();
        let merkle_tree = SparseMerkleTreeGlobal::default();

        Self {
            balance: 0,
            nonce,
            merkle_root: merkle_tree.root,
            merkle_tree,
        }
    }

    pub fn update_balance(&mut self, new_balance: u64) -> Result<(), GlobalStateError> {
        if new_balance > self.balance {
            return Err(GlobalStateError::BalanceOverflow);
        }

        let key = self.nonce.to_le_bytes();
        let value = new_balance.to_le_bytes();
        self.merkle_tree.update(&key, &value)?;
        self.merkle_root = self.merkle_tree.root;

        self.balance = new_balance;
        self.nonce += 1;

        Ok(())
    }
}