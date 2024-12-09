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

pub struct StateTransitionCircuitWithRecursion {
    recursive_proofs: Vec<ProofWithPublicInputs<GoldilocksField, C, 2>>,
    max_recursive_depth: usize,
    circuit: StateTransitionCircuit,
}

impl StateTransitionCircuitWithRecursion {
    pub fn new() -> Self {
        Self {
            recursive_proofs: Vec::new(),
            max_recursive_depth: 32,
            circuit: StateTransitionCircuit::new(),
        }
    }

    pub fn generate_proof(
        &mut self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        if self.recursive_proofs.len() >= self.max_recursive_depth {
            return Err(anyhow!("Maximum recursive depth reached"));
        }

        if !Self::validate_state_transition(&current_state, &next_state, &transition_data) {
            return Err(anyhow!("Invalid state transition"));
        }

        let proof = self.circuit.generate_proof(current_state, next_state, transition_data)
            .map_err(|e| anyhow!("Proof generation failed: {}", e))?;
        
        self.recursive_proofs.push(proof.clone());
        Ok(proof)
    }

    fn validate_state_transition(current: &[u8; 32], next: &[u8; 32], data: &[u8; 32]) -> bool {
        if current.iter().all(|&x| x == 0) {
            return false;
        }

        if next.iter().all(|&x| x == 0) {
            return false;
        }

        if data.iter().all(|&x| x == 0) {
            return false;
        }

        if current == next {
            return false;
        }
        
        true
    }

    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        self.circuit.verify_proof(proof.clone())?;
        
        for recursive_proof in &self.recursive_proofs {
            self.circuit.verify_proof(recursive_proof.clone())?;
        }
        
        Ok(true)
    }

    pub fn get_recursive_depth(&self) -> usize {
        self.recursive_proofs.len()
    }

    pub fn get_max_recursive_depth(&self) -> usize {
        self.max_recursive_depth
    }

    pub fn set_max_recursive_depth(&mut self, depth: usize) {
        self.max_recursive_depth = depth;
    }

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
        
        // Simple test case with different states
        let initial_state = [1u8; 32];
        let next_state = [2u8; 32];
        let transition_data = [3u8; 32];
        
        let proof = circuit.generate_proof(
            initial_state,
            next_state,
            transition_data,
        )?;

        assert!(circuit.verify_proof(proof.clone())?, "The proof should be valid");
        assert_eq!(circuit.get_recursive_depth(), 1, "Should have one proof in the chain");

        Ok(())
    }

    #[test]
    fn test_recursive_depth_limit() -> Result<()> {
        let mut circuit = StateTransitionCircuitWithRecursion::new();
        circuit.set_max_recursive_depth(2);

        let state1 = [1u8; 32];
        let state2 = [2u8; 32];
        let state3 = [3u8; 32];
        let transition_data = [4u8; 32];

        // First proof
        let proof1 = circuit.generate_proof(state1, state2, transition_data)?;
        assert!(circuit.verify_proof(proof1)?, "First proof should be valid");

        // Second proof
        let proof2 = circuit.generate_proof(state2, state3, transition_data)?;
        assert!(circuit.verify_proof(proof2)?, "Second proof should be valid");

        // Third proof should fail due to depth limit
        assert!(circuit.generate_proof(state3, [4u8; 32], transition_data).is_err(),
            "Should not allow exceeding max recursive depth");

        Ok(())
    }
}