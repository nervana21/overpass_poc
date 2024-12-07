// src/zkp/state_transition.rs

use anyhow::{anyhow, ensure, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use plonky2_field::types::Field;

type C = PoseidonGoldilocksConfig;

/// Represents a state transition circuit using Plonky2.
pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, C, 2>,
    current_state: HashOutTarget,
    next_state: HashOutTarget,
    transition_data_target: HashOutTarget,
}

impl StateTransitionCircuit {
    /// Constructs a new state transition circuit.
    pub fn new() -> Self {
        // Define the circuit configuration
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Add virtual hashes for current state and next state
        let current_state = builder.add_virtual_hash();
        let next_state = builder.add_virtual_hash();

        // Register current_state and next_state as public inputs
        builder.register_public_inputs(&current_state.elements);
        builder.register_public_inputs(&next_state.elements);

        // Add a virtual hash for transition data
        let transition_data_target = builder.add_virtual_hash();

        // Compute next_state as the Poseidon hash of current_state and transition_data
        let computed_next_state = builder.hash_n_to_m_no_pad::<PoseidonHash>(
            vec![current_state.elements[0], transition_data_target.elements[0]],
            1,
        )[0];

        // Enforce that the computed_next_state matches the provided next_state
        builder.connect(computed_next_state, next_state.elements[0]);

        // Build the circuit data
        let circuit_data = builder.build::<C>();

        Self {
            circuit_data,
            current_state,
            next_state,
            transition_data_target,
        }
    }

    /// Converts a `[u8; 32]` array to a `HashOut<GoldilocksField>`.
    fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>> {
        data.chunks(8)
            .map(|chunk| {
                let bytes = chunk
                    .try_into()
                    .context("Chunk size mismatch while converting to u64")?;
                Ok(GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes)))
            })
            .collect::<Result<Vec<_>>>()
            .map(|fields| HashOut::from_partial(&fields))
    }

    /// Generates a zero-knowledge proof for the state transition.
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
        &self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        // Validate input lengths
        ensure!(
            current_state.len() == 32 && next_state.len() == 32 && transition_data.len() == 32,
            "All inputs must be exactly 32 bytes"
        );

        let mut pw = PartialWitness::<GoldilocksField>::new();

        // Assign the current state, next state, and transition data to the circuit
        pw.set_hash_target(self.current_state, Self::to_hash_out(current_state)?)?;
        pw.set_hash_target(self.next_state, Self::to_hash_out(next_state)?)?;
        pw.set_hash_target(self.transition_data_target, Self::to_hash_out(transition_data)?)?;

        // Attempt to generate the proof
        let proof = self
            .circuit_data
            .prove(pw)
            .map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

        Ok(proof)
    }

    /// Verifies a zero-knowledge proof for the state transition.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, otherwise an error.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        self.circuit_data
            .verify(proof)
            .context("Proof verification failed")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::Hasher;
    use plonky2_field::types::PrimeField64;
use super::*;
    use anyhow::Result;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::hash::hash_types::HashOut;
    use rand::Rng;

    impl StateTransitionCircuit {
        /// Computes the Poseidon hash for testing purposes.
        fn compute_poseidon_hash(
            current_state: &HashOut<GoldilocksField>,
            transition_data: &HashOut<GoldilocksField>,
        ) -> HashOut<GoldilocksField> {
            let mut input = Vec::new();
            input.extend_from_slice(&current_state.elements);
            input.extend_from_slice(&transition_data.elements);
            PoseidonHash::hash_no_pad(&input)
        }

        /// Converts a `HashOut<GoldilocksField>` back to a `[u8; 32]` array.
        fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            for (i, field_elem) in hash.elements.iter().enumerate() {
                bytes[i * 8..(i + 1) * 8]
                    .copy_from_slice(&field_elem.to_canonical_u64().to_le_bytes());
            }
            bytes
        }
    }

    /// Tests the state transition circuit with valid random inputs.
    #[test]
    fn test_state_transition_circuit() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        // Generate random current state and transition data
        let mut rng = rand::thread_rng();
        let current_state_bytes: [u8; 32] = rng.gen();
        let transition_data_bytes: [u8; 32] = rng.gen();

        // Convert byte arrays to HashOut
        let current_state = StateTransitionCircuit::to_hash_out(current_state_bytes)
            .context("Failed to convert current_state bytes to HashOut")?;
        let transition_data = StateTransitionCircuit::to_hash_out(transition_data_bytes)
            .context("Failed to convert transition_data bytes to HashOut")?;

        // Compute the expected next state using Poseidon hash
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state, &transition_data);

        // Convert the computed next state back to bytes
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        // Generate the proof
        let proof = circuit
            .generate_proof(current_state_bytes, next_state_bytes, transition_data_bytes)
            .context("Proof generation failed")?;

        // Verify the proof
        let is_valid = circuit
            .verify_proof(proof)
            .context("Proof verification failed")?;
        assert!(is_valid, "The proof should be valid");

        Ok(())
    }

    /// Tests the circuit's behavior with invalid input lengths.
    #[test]
    fn test_invalid_inputs() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        // Define valid inputs
        let valid_current_state = [0u8; 32];
        let valid_next_state = [0u8; 32];
        let valid_transition_data = [0u8; 32];

        // Test with valid input lengths
        let result = circuit.generate_proof(
            valid_current_state,
            valid_next_state,
            valid_transition_data,
        );
        assert!(
            result.is_ok(),
            "Proof generation should succeed with valid input lengths"
        );

        // Define an invalid input (31 bytes instead of 32)
        let mut invalid_current_state = [0u8; 32];
        invalid_current_state[..31].copy_from_slice(&[1u8; 31]);

        // Test with invalid input lengths
        let result = circuit.generate_proof(
            invalid_current_state,
            valid_next_state,
            valid_transition_data,
        );
        assert!(
            result.is_err(),
            "Proof generation should fail with invalid input lengths"
        );

        Ok(())
    }

    /// Tests the circuit with zeroed states to ensure it handles edge cases correctly.
    #[test]
    fn test_edge_case_zeroed_states() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        let zero_state_bytes = [0u8; 32];
        let transition_data_bytes = [0u8; 32];

        let current_state = StateTransitionCircuit::to_hash_out(zero_state_bytes)
            .context("Failed to convert zeroed current_state bytes to HashOut")?;
        let transition_data = StateTransitionCircuit::to_hash_out(transition_data_bytes)
            .context("Failed to convert zeroed transition_data bytes to HashOut")?;

        // Compute the expected next state using Poseidon hash
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state, &transition_data);

        // Convert the computed next state back to bytes
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        // Generate the proof
        let proof = circuit
            .generate_proof(zero_state_bytes, next_state_bytes, transition_data_bytes)
            .expect("Proof generation should succeed for zeroed states");

        // Verify the proof
        let is_valid = circuit
            .verify_proof(proof)
            .expect("Proof verification failed for zeroed states");
        assert!(is_valid, "The proof for zeroed states should be valid");

        Ok(())
    }

    /// Tests the circuit's response to an invalid proof.
    #[test]
    fn test_invalid_proof() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        // Generate random current state and transition data
        let mut rng = rand::thread_rng();
        let current_state_bytes: [u8; 32] = rng.gen();
        let transition_data_bytes: [u8; 32] = rng.gen();

        // Convert byte arrays to HashOut
        let current_state = StateTransitionCircuit::to_hash_out(current_state_bytes)
            .context("Failed to convert current_state bytes to HashOut")?;
        let transition_data = StateTransitionCircuit::to_hash_out(transition_data_bytes)
            .context("Failed to convert transition_data bytes to HashOut")?;

        // Compute the expected next state using Poseidon hash
        let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(&current_state, &transition_data);

        // Convert the computed next state back to bytes
        let next_state_bytes = StateTransitionCircuit::hash_out_to_bytes(&computed_next_state);

        // Generate a valid proof
        let proof = circuit
            .generate_proof(current_state_bytes, next_state_bytes, transition_data_bytes)
            .context("Proof generation failed")?;

        // Modify the proof's public inputs to invalidate it
        let mut invalid_proof = proof.clone();
        // Here, we assume that `public_inputs` is a Vec<GoldilocksField>.
        if let Some(first_public_input) = invalid_proof.public_inputs.first_mut() {
            *first_public_input = GoldilocksField::ZERO;
        }

        // Attempt to verify the invalid proof
        let is_valid = circuit.verify_proof(invalid_proof).unwrap_or(false);
        assert!(
            !is_valid,
            "The modified proof should be invalid and verification should fail"
        );

        Ok(())
    }}