use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use std::collections::HashMap;

#[derive(Debug)]
pub struct SparseMerkleProof {
    pub path: Vec<Vec<u8>>,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct SparseMerkleTree {
    pub root: [u8; 32],
    nodes: HashMap<Vec<u8>, Vec<u8>>,
    height: usize,
}

impl SparseMerkleTree {
    pub fn new(height: usize) -> Self {
        let empty_root = [0u8; 32];
        Self {
            root: empty_root,
            nodes: HashMap::new(),
            height,
        }
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) {
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
            self.nodes.insert(self.path_key(key, i), current_hash.clone());
        }

        self.root.copy_from_slice(&current_hash);
    }

    pub fn generate_proof(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();
        let key_bits = self.get_bits(key);

        for i in 0..self.height {
            let sibling_key = self.path_key(key, i);
            let sibling = self.nodes.get(&sibling_key).cloned().unwrap_or_else(|| vec![0u8; 32]);
            proof.push(sibling);
        }

        proof
    }

    pub fn verify_proof(root: &[u8; 32], proof: &[Vec<u8>], key: &[u8], value: &[u8]) -> bool {
        let mut current_hash = value.to_vec();
        let key_bits = Self::get_bits_static(key, proof.len());

        for (i, sibling) in proof.iter().enumerate().rev() {
            let pair = if key_bits[i] {
                [sibling.as_slice(), current_hash.as_slice()].concat()
            } else {
                [current_hash.as_slice(), sibling.as_slice()].concat()
            };

            let hash_output = PoseidonHash::hash_no_pad(&bytes_to_fields(&pair));
            current_hash = hash_out_to_bytes(&hash_output);
        }

        current_hash == root.to_vec()
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
