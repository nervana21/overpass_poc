use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::WitnessWrite;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
};
use plonky2_field::types::Field;
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

        // Compute next state hash
        let computed_next_state = builder.add_virtual_hash();
        builder.connect_hashes(computed_next_state, current_state);
        builder.connect_hashes(computed_next_state, transition_data);   
        
        // Enforce consistency
        builder.connect_hashes(computed_next_state, next_state);

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

        // Set public inputs and witness values
        for i in 0..4 {
            let current_state_target = self.circuit_data.prover_only.public_inputs[i];
            let next_state_target = self.circuit_data.prover_only.public_inputs[i + 4];
            pw.set_target(current_state_target, GoldilocksField::from_canonical_u64(u64::from_be_bytes(current_state[i*8..(i+1)*8].try_into().unwrap())));
            pw.set_target(next_state_target, GoldilocksField::from_canonical_u64(u64::from_be_bytes(next_state[i*8..(i+1)*8].try_into().unwrap())));
        }

        // Set transition data
        let transition_target = self.circuit_data.prover_only.public_inputs[8];
        pw.set_target(transition_target, GoldilocksField::from_canonical_u64(u64::from_be_bytes(transition_data[..8].try_into().unwrap())));

        let proof = self.circuit_data.prove(pw)?;
        Ok(proof)
    }

    /// Verify a proof for a state transition.
    pub fn verify_proof(&self, proof: ProofWithPublicInputs<GoldilocksField, C, 2>) -> Result<bool> {
        self.circuit_data.verify(proof)?;
        Ok(true)
    }
}