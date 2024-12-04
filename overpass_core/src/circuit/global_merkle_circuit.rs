use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use anyhow::Result;

/// Custom error type for Global Merkle Circuit operations.
#[derive(Error, Debug)]
pub enum GlobalMerkleCircuitError {
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Structure for public inputs required by the Merkle Circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleCircuitPublicInputs {
    pub old_root: HashOut<GoldilocksField>,
    pub new_root: HashOut<GoldilocksField>,
    pub old_balance: u64,
    pub new_balance: u64,
    pub old_nonce: u64,
    pub new_nonce: u64,
}

/// Main structure for the Global Merkle Circuit.
pub struct GlobalMerkleCircuit {
    pub circuit_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
}

impl GlobalMerkleCircuit {
    /// Creates a new GlobalMerkleCircuit with the specified tree height.
    pub fn new() -> Result<Self, GlobalMerkleCircuitError> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Add virtual targets for public inputs
        let old_root = builder.add_virtual_hash();
        let new_root = builder.add_virtual_hash();
        let old_balance = builder.add_virtual_target();
        let new_balance = builder.add_virtual_target();
        let old_nonce = builder.add_virtual_target();
        let new_nonce = builder.add_virtual_target();

        // Add constraints for the circuit
        let balance_diff = builder.sub(old_balance, new_balance);
        builder.assert_zero(balance_diff); // Adjusted logic to enforce balance difference check

        let one = builder.one();
        let expected_new_nonce = builder.add(old_nonce, one);
        builder.connect(new_nonce, expected_new_nonce);

        // Build the circuit
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();

        Ok(Self { circuit_data })
    }

    /// Generates a proof for the given public inputs.
    pub fn prove(
        &self,
        inputs: MerkleCircuitPublicInputs,
    ) -> Result<Vec<u8>, GlobalMerkleCircuitError> {
        let mut pw = PartialWitness::<GoldilocksField>::new();

        pw.set_target(self.circuit_data.prover_only.public_inputs[0], GoldilocksField::from_canonical_u64(inputs.old_balance));
        pw.set_target(self.circuit_data.prover_only.public_inputs[1], GoldilocksField::from_canonical_u64(inputs.new_balance));
        pw.set_target(self.circuit_data.prover_only.public_inputs[2], GoldilocksField::from_canonical_u64(inputs.old_nonce));
        pw.set_target(self.circuit_data.prover_only.public_inputs[3], GoldilocksField::from_canonical_u64(inputs.new_nonce));

        for (i, elem) in inputs.old_root.elements.iter().enumerate() {
            pw.set_target(self.circuit_data.prover_only.public_inputs[4 + i], *elem);
        }
        for (i, elem) in inputs.new_root.elements.iter().enumerate() {
            pw.set_target(self.circuit_data.prover_only.public_inputs[36 + i], *elem);
        }

        let proof = self
            .circuit_data
            .prove(pw)
            .map_err(|e| GlobalMerkleCircuitError::ProofError(format!("{:?}", e)))?;

        Ok(proof.to_bytes())
    }
    /// Verifies a proof with the given public inputs.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        inputs: MerkleCircuitPublicInputs,
    ) -> Result<bool, GlobalMerkleCircuitError> {
        let proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2> =
            ProofWithPublicInputs::from_bytes(proof_bytes.to_vec(), &self.circuit_data.common)
                .map_err(|e| GlobalMerkleCircuitError::VerificationError(format!("{:?}", e)))?;

        let mut public_inputs = Vec::new();
        public_inputs.push(GoldilocksField::from_canonical_u64(inputs.old_balance));
        public_inputs.push(GoldilocksField::from_canonical_u64(inputs.new_balance));
        public_inputs.push(GoldilocksField::from_canonical_u64(inputs.old_nonce));
        public_inputs.push(GoldilocksField::from_canonical_u64(inputs.new_nonce));

        for elem in inputs.old_root.elements.iter() {
            public_inputs.push(*elem);
        }
        for elem in inputs.new_root.elements.iter() {
            public_inputs.push(*elem);
        }

        self.circuit_data
            .verify(proof)
            .map(|_| true)
            .map_err(|e| GlobalMerkleCircuitError::VerificationError(format!("{:?}", e)))
    }}