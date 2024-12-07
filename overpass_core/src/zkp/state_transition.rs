use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        proof::ProofWithPublicInputs,
    },
    iop::{witness::PartialWitness, target::Target},
};
use anyhow::Result;

type C = PoseidonGoldilocksConfig;

/// Configuration for the state transition circuit.
pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, C, 2>,
}

impl StateTransitionCircuit {
    /// Build the circuit for state transitions.
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Define public inputs: current state hash and next state hash
        let current_state = builder.add_virtual_hash();
        let next_state = builder.add_virtual_hash();
        builder.register_public_inputs(&current_state.elements);
        builder.register_public_inputs(&next_state.elements);

        // Witness for transition data
        let transition_data = builder.add_virtual_hash();

        // Compute next state hash using Poseidon
        let computed_next_state = builder.hash_n_to_m_no_pad::<PoseidonGoldilocksConfig>(
            &[current_state.elements[0], transition_data.elements[0]],
            1,
        )[0];

        // Enforce computed_next_state consistency
        builder.connect(computed_next_state, next_state.elements[0]);

        let circuit_data = builder.build::<C>();

        Self { circuit_data }
    }

    /// Generate a proof for a state transition.
    pub fn generate_proof(
        &self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        let mut pw = PartialWitness::<GoldilocksField>::new();

        // Set public inputs for current and next states
        for i in 0..4 {
            let chunk = |state: &[u8; 32], index| {
                GoldilocksField::from_canonical_u64(u64::from_be_bytes(
                    state[index * 8..(index + 1) * 8].try_into().unwrap(),
                ))
            };

            let current_chunk = chunk(&current_state, i);
            let next_chunk = chunk(&next_state, i);

            pw.set_target(self.circuit_data.prover_only.public_inputs[i], current_chunk);
            pw.set_target(self.circuit_data.prover_only.public_inputs[i + 4], next_chunk);
        }

        // Set witness for transition data
        for i in 0..4 {
            let chunk = GoldilocksField::from_canonical_u64(u64::from_be_bytes(
                transition_data[i * 8..(i + 1) * 8].try_into().unwrap(),
            ));
            pw.set_target(self.circuit_data.prover_only.wire_inputs[i + 8], chunk);
        }

        let proof = self.circuit_data.prove(pw)?;
        Ok(proof)
    }

    /// Verify a proof for a state transition.
    pub fn verify_proof(&self, proof: ProofWithPublicInputs<GoldilocksField, C, 2>) -> Result<bool> {
        self.circuit_data.verify(proof)?;
        Ok(true)
    }
}