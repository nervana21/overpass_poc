// src/zkp/recursion.rs

use anyhow::{anyhow, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

use crate::zkp::state_transition::StateTransitionCircuit;

type C = PoseidonGoldilocksConfig;

/// Manages state transition proofs with recursion capabilities.
pub struct StateTransitionCircuitWithRecursion {
    recursive_proofs: Vec<ProofWithPublicInputs<GoldilocksField, C, 2>>,
    max_recursive_depth: usize,
    circuit: StateTransitionCircuit,
}

impl StateTransitionCircuitWithRecursion {
    /// Creates a new instance with default maximum recursive depth.
    pub fn new() -> Self {
        Self {
            recursive_proofs: Vec::new(),
            max_recursive_depth: 32,
            circuit: StateTransitionCircuit::new(),
        }
    }

    /// Generates a zero-knowledge proof for the state transition and manages recursion.
    ///
    /// # Arguments
    ///
    /// * `current_state` - A 32-byte array representing the current state.
    /// * `next_state` - A 32-byte array representing the next state.
    /// * `transition_data` - A 32-byte array representing the transition data.
    ///
    /// # Returns
    ///
    /// A `ProofWithPublicInputs` if proof generation is successful.
    pub fn generate_proof(
        &mut self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        // Check if we've reached the maximum recursive depth
        if self.recursive_proofs.len() >= self.max_recursive_depth {
            return Err(anyhow!("Maximum recursive depth reached"));
        }

        // Validate state transition before generating proof
        if !Self::validate_state_transition(&current_state, &next_state, &transition_data) {
            return Err(anyhow!("Invalid state transition"));
        }

        // Generate proof using the circuit
        let proof = self.circuit.generate_proof(current_state, next_state, transition_data)
            .map_err(|e| anyhow!("Proof generation failed: {}", e))?;
        self.recursive_proofs.push(proof.clone());
        Ok(proof)
    }

    /// Validates the state transition.
    ///
    /// # Arguments
    ///
    /// * `current` - Reference to the current state bytes.
    /// * `next` - Reference to the next state bytes.
    /// * `data` - Reference to the transition data bytes.
    ///
    /// # Returns
    ///
    /// `true` if the state transition is valid, otherwise `false`.
    fn validate_state_transition(current: &[u8; 32], next: &[u8; 32], data: &[u8; 32]) -> bool {
        // Verify that the current state is valid (non-zero)
        if current.iter().all(|&x| x == 0) {
            return false;
        }

        // Verify that the next state is valid (non-zero)
        if next.iter().all(|&x| x == 0) {
            return false;
        }

        // Verify that transition data is valid (non-zero)
        if data.iter().all(|&x| x == 0) {
            return false;
        }

        // Verify that states are different
        if current == next {
            return false;
        }
        
        true
    }

    /// Verifies a zero-knowledge proof and all recursive proofs.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// `true` if all proofs are valid, otherwise an error.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        // Verify the main proof
        self.circuit.verify_proof(proof.clone())?;
        
        // Verify all recursive proofs
        for recursive_proof in &self.recursive_proofs {
            self.circuit.verify_proof(recursive_proof.clone())?;
        }
        
        Ok(true)
    }

    /// Returns the current recursive depth.
    pub fn get_recursive_depth(&self) -> usize {
        self.recursive_proofs.len()
    }

    /// Returns the maximum allowed recursive depth.
    pub fn get_max_recursive_depth(&self) -> usize {
        self.max_recursive_depth
    }

    /// Sets a new maximum recursive depth.
    ///
    /// # Arguments
    ///
    /// * `depth` - The new maximum recursive depth.
    pub fn set_max_recursive_depth(&mut self, depth: usize) {
        self.max_recursive_depth = depth;
    }

    /// Clears all recursive proofs.
    pub fn clear_recursive_proofs(&mut self) {
        self.recursive_proofs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_recursive_proof_aggregation() -> Result<()> {
        let mut circuit = StateTransitionCircuitWithRecursion::new();
        
        // Define test states and transition data
        let initial_state = [1u8; 32];
        let next_state = [2u8; 32];
        let transition_data = [3u8; 32];
        
        // Generate proof
        let proof = circuit.generate_proof(
            initial_state,
            next_state,
            transition_data,
        )?;

        // Verify the generated proof
        assert!(circuit.verify_proof(proof.clone())?, "The proof should be valid");
        
        // Verify recursive depth
        assert_eq!(circuit.get_recursive_depth(), 1, "Should have one proof in the chain");

        Ok(())
    }
}
