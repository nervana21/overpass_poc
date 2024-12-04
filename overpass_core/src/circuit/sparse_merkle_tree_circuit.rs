// src/circuit/sparse_merkle_circuit.rs

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{PoseidonGoldilocksConfig, Hasher},
        proof::ProofWithPublicInputs,
    },
    iop::target::Target,
    field::types::Field,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleCircuitError {
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePublicInputs {
    pub root: HashOut<GoldilocksField>,
    pub key: [u8; 32],
    pub value: [u8; 32],
}

#[derive(Debug)]
pub struct SparseMerkleProof {
    pub siblings: Vec<HashOut<GoldilocksField>>,
    pub value: Vec<u8>,
    pub key_fragments: Vec<bool>,
}

#[derive(Debug)]
pub struct MerkleCircuit {
    pub root: HashOut<GoldilocksField>,
    nodes: HashMap<Vec<bool>, HashOut<GoldilocksField>>,
    height: usize,
    circuit_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
}

impl MerkleCircuit {
    pub fn new(height: usize) -> Result<Self, MerkleCircuitError> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Add circuit structure
        let circuit_data = Self::build_circuit(&mut builder)?;
        
        Ok(Self {
            root: HashOut::ZERO,
            nodes: HashMap::new(),
            height,
            circuit_data,
        })
    }

    fn build_circuit(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
    ) -> Result<CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>, MerkleCircuitError> {
        // Add public inputs
        let root = builder.add_virtual_hash();
        let key = builder.add_virtual_bytes();
        let value = builder.add_virtual_bytes();

        // Add constraints for Merkle path verification
        let computed_root = Self::add_merkle_constraints(builder, &key, &value)?;
        builder.connect_hashes(root, computed_root);

        // Build circuit
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        Ok(circuit_data)
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), MerkleCircuitError> {
        let key_bits = self.get_bits(key);
        let value_field = self.value_to_field(value)?;
        let mut current_hash = value_field;

        for i in (0..self.height).rev() {
            let sibling = self.nodes
                .get(&Self::sibling_path(&key_bits, i))
                .copied()
                .unwrap_or(HashOut::ZERO);

            current_hash = if key_bits[i] {
                PoseidonHash::two_to_one(sibling, current_hash)
            } else {
                PoseidonHash::two_to_one(current_hash, sibling)
            };

            self.nodes.insert(key_bits[..=i].to_vec(), current_hash);
        }

        self.root = current_hash;
        Ok(())
    }

    pub fn prove(&self, key: &[u8], value: &[u8]) -> Result<Vec<u8>, MerkleCircuitError> {
        // Generate Merkle proof
        let proof = self.generate_proof(key)?;
        
        // Create witness
        let mut pw = PartialWitness::new();
        
        // Set root
        pw.set_hash_target(
            self.circuit_data.prover_only.public_inputs[0],
            self.root,
        );
        
        // Set key and value
        pw.set_bytes_target(
            self.circuit_data.prover_only.public_inputs[1],
            key,
        );
        pw.set_bytes_target(
            self.circuit_data.prover_only.public_inputs[2],
            value,
        );

        // Set proof elements
        for (i, sibling) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(
                self.circuit_data.prover_only.public_inputs[3 + i],
                *sibling,
            );
        }

        // Generate proof
        let proof = self.circuit_data.prove(pw)
            .map_err(|e| MerkleCircuitError::ProofError(e.to_string()))?;

        bincode::serialize(&proof)
            .map_err(|e| MerkleCircuitError::SerializationError(e.to_string()))
    }

    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &MerklePublicInputs,
    ) -> Result<bool, MerkleCircuitError> {
        let proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2> = 
            bincode::deserialize(proof_bytes)
                .map_err(|e| MerkleCircuitError::SerializationError(e.to_string()))?;

        self.circuit_data.verify(proof)
            .map_err(|e| MerkleCircuitError::VerificationError(e.to_string()))?;

        Ok(true)
    }

    pub fn generate_proof(&self, key: &[u8]) -> Result<SparseMerkleProof, MerkleCircuitError> {
        let key_bits = self.get_bits(key);
        let mut siblings = Vec::with_capacity(self.height);

        for i in 0..self.height {
            let sibling = self.nodes
                .get(&Self::sibling_path(&key_bits, i))
                .copied()
                .unwrap_or(HashOut::ZERO);
            siblings.push(sibling);
        }

        Ok(SparseMerkleProof {
            siblings,
            value: self.get_value(key),
            key_fragments: key_bits,
        })
    }

    fn get_bits(&self, key: &[u8]) -> Vec<bool> {
        let mut bits = Vec::with_capacity(self.height);
        for byte in key {
            for i in (0..8).rev() {
                bits.push((*byte & (1 << i)) != 0);
                if bits.len() == self.height {
                    return bits;
                }
            }
        }
        while bits.len() < self.height {
            bits.push(false);
        }
        bits
    }

    fn sibling_path(key_bits: &[bool], level: usize) -> Vec<bool> {
        let mut path = key_bits[..level].to_vec();
        path.push(!key_bits[level]);
        path
    }

    fn value_to_field(&self, value: &[u8]) -> Result<HashOut<GoldilocksField>, MerkleCircuitError> {
        if value.len() != 32 {
            return Err(MerkleCircuitError::InvalidState("Invalid value length".into()));
        }

        let mut elements = [GoldilocksField::ZERO; 4];
        for (i, chunk) in value.chunks(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            elements[i] = GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes));
        }

        Ok(HashOut { elements })
    }

    fn get_value(&self, key: &[u8]) -> Vec<u8> {
        let key_bits = self.get_bits(key);
        self.nodes
            .get(&key_bits)
            .map_or_else(
                || vec![0u8; 32],
                |h| h.elements
                    .iter()
                    .flat_map(|e| e.to_canonical_u64().to_le_bytes())
                    .collect()
            )
    }

    fn add_merkle_constraints(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        key: &Target,
        value: &Target,
    ) -> Result<Target, MerkleCircuitError> {
        let value_hash = builder.hash_or_noop::<PoseidonHash>(*value, HashOut::ZERO);
        let key_bits = builder.split_le(*key, 256);
        
        let mut current = value_hash;
        for i in (0..256).rev() {
            let sibling = builder.add_virtual_hash();
            current = builder.select_hash(
                key_bits[i],
                builder.hash_or_noop::<PoseidonHash>(sibling, current),
                builder.hash_or_noop::<PoseidonHash>(current, sibling),
            );
        }

        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof() -> Result<(), MerkleCircuitError> {
        let mut circuit = MerkleCircuit::new(256)?;
        
        let key = [1u8; 32];
        let value = [42u8; 32];
        
        circuit.update(&key, &value)?;
        let proof = circuit.prove(&key, &value)?;
        
        let public_inputs = MerklePublicInputs {
            root: circuit.root,
            key,
            value,
        };
        
        assert!(circuit.verify(&proof, &public_inputs)?);
        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<(), MerkleCircuitError> {
        let mut circuit = MerkleCircuit::new(256)?;
        
        let key = [1u8; 32];
        let value = [42u8; 32];
        let wrong_value = [43u8; 32];
        
        circuit.update(&key, &value)?;
        let proof = circuit.prove(&key, &value)?;
        
        let public_inputs = MerklePublicInputs {
            root: circuit.root,
            key,
            value: wrong_value,
        };
        
        assert!(!circuit.verify(&proof, &public_inputs)?);
        Ok(())
    }
}