use anyhow::anyhow;
use plonky2::hash::hash_types::HashOut;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::HashOutTarget,
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
use anyhow::{Context, Result};
use plonky2_field::types::Field;

type C = PoseidonGoldilocksConfig;

pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, C, 2>,
    current_state: HashOutTarget,
    next_state: HashOutTarget,
    transition_data_target: HashOutTarget,
}

impl StateTransitionCircuit {
    /// Creates a new state transition circuit.
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let current_state = builder.add_virtual_hash();
        let next_state = builder.add_virtual_hash();
        builder.register_public_inputs(&current_state.elements);
        builder.register_public_inputs(&next_state.elements);

        let transition_data_target = builder.add_virtual_hash();
        let computed_next_state = builder.hash_n_to_m_no_pad::<PoseidonHash>(
            vec![current_state.elements[0], transition_data_target.elements[0]],
            1,
        )[0];

        builder.connect(computed_next_state, next_state.elements[0]);

        let circuit_data = builder.build::<C>();
        Self {
            circuit_data,
            current_state,
            next_state,
            transition_data_target,
        }
    }

    /// Generates a proof for the state transition.
    pub fn generate_proof(
        &self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        let mut pw = PartialWitness::<GoldilocksField>::new();
    
        // Convert inputs to field elements and create `HashOut` instances
        let current_state_hash = HashOut::from_partial(
            &current_state
                .chunks(8)
                .map(|chunk| GoldilocksField::from_canonical_u64(
                    u64::from_le_bytes(chunk.try_into().expect("Invalid chunk size"))
                ))
                .collect::<Vec<_>>(),
        );
    
        let next_state_hash = HashOut::from_partial(
            &next_state
                .chunks(8)
                .map(|chunk| GoldilocksField::from_canonical_u64(
                    u64::from_le_bytes(chunk.try_into().expect("Invalid chunk size"))
                ))
                .collect::<Vec<_>>(),
        );
    
        let transition_data_hash = HashOut::from_partial(
            &transition_data
                .chunks(8)
                .map(|chunk| GoldilocksField::from_canonical_u64(
                    u64::from_le_bytes(chunk.try_into().expect("Invalid chunk size"))
                ))
                .collect::<Vec<_>>(),
        );
    
        // Assign witnesses
        pw.set_hash_target(self.current_state, current_state_hash)?;
        pw.set_hash_target(self.next_state, next_state_hash)?;
        pw.set_hash_target(self.transition_data_target, transition_data_hash)?;
    
        // Generate proof
        let proof = self
            .circuit_data
            .prove(pw)
            .map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;
    
        Ok(proof)
    }
    /// Verifies the proof for a state transition.
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
    use super::*;
    use rand::Rng;

    #[test]
    fn test_state_transition_circuit() {
        let circuit = StateTransitionCircuit::new();

        // Generate random inputs
        let mut rng = rand::thread_rng();
        let current_state = rng.gen::<[u8; 32]>();
        let next_state = rng.gen::<[u8; 32]>();
        let transition_data = rng.gen::<[u8; 32]>();

        // Generate and verify proof
        let proof = circuit
            .generate_proof(current_state, next_state, transition_data)
            .expect("Proof generation failed");

        let is_valid = circuit.verify_proof(proof).expect("Proof verification failed");
        assert!(is_valid, "The proof should be valid");
    }
}