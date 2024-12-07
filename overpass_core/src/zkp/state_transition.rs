use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    }, iop::witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs
    }
};
use anyhow::Result;
use plonky2_field::types::Field;

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
        let transition_data_target = builder.add_virtual_hash();

        // Compute next state hash
        let computed_next_state = builder.hash_n_to_m_no_pad::<PoseidonHash>(
            vec![
                current_state.elements[0],
                transition_data_target.elements[0],
            ],
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

        // Convert inputs to GoldilocksField and set public inputs
        let current_state_hash = HashOut::<GoldilocksField>::from_vec(current_state.iter().map(|&x| GoldilocksField::from_canonical_u8(x)).collect());
        let next_state_hash = HashOut::<GoldilocksField>::from_vec(next_state.iter().map(|&x| GoldilocksField::from_canonical_u8(x)).collect());
        let transition_data_hash = HashOut::<GoldilocksField>::from_vec(transition_data.iter().map(|&x| GoldilocksField::from_canonical_u8(x)).collect());

        let _ = pw.set_hash_target(
            HashOutTarget::from_vec(vec![self.circuit_data.prover_only.public_inputs[0].clone()]),
            current_state_hash,
        );
        let _ = pw.set_hash_target(
            HashOutTarget::from_vec(vec![self.circuit_data.prover_only.public_inputs[1].clone()]),
            next_state_hash,
        );
        let _ = pw.set_hash_target(
            HashOutTarget::from_vec(vec![self.circuit_data.prover_only.public_inputs[2].clone()]),
            transition_data_hash,
        );
        let proof = self.circuit_data.prove(pw)?;
        Ok(proof)
    }

    /// Verify a proof for a state transition.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        self.circuit_data.verify(proof)?;
        Ok(true)
    }
}