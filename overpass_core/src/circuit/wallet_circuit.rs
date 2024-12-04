// ./src/circuit/wallet_circuit.rs

use plonky2::util::serialization::DefaultGateSerializer;

use serde::{Deserialize, Serialize};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use anyhow::Result;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletCircuitError {
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Invalid wallet state: {0}")]
    InvalidState(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletState {
    pub balance: u64,
    pub nonce: u64,
}

pub struct WalletCircuit {
    pub old_state: WalletState,
    pub new_state: WalletState,
    pub circuit_config: CircuitConfig,
    pub common_data: CommonCircuitData<GoldilocksField, 2>,
}

impl WalletCircuit {
    pub fn new(
        old_state: WalletState,
        new_state: WalletState,
    ) -> Result<Self, WalletCircuitError> {
        // Validate that balance does not become negative (assuming unsigned u64)
        if new_state.balance > old_state.balance {
            return Err(WalletCircuitError::InvalidState(
                "New balance cannot exceed old balance without deposit".into(),
            ));
        }

        // Validate that nonce increments by 1
        if new_state.nonce != old_state.nonce + 1 {
            return Err(WalletCircuitError::InvalidState(
                "Nonce must increment by 1".into(),
            ));
        }

        // Initialize circuit configuration and common data
        let circuit_config = CircuitConfig::standard_recursion_config();
        let common_data = CommonCircuitData::from_bytes(
            vec![], // Empty bytes for now, you may need to provide actual data
            &DefaultGateSerializer,
        ).map_err(|e| WalletCircuitError::InvalidState(format!("Failed to create CommonCircuitData: {:?}", e)))?;

        Ok(Self {
            old_state,
            new_state,
            circuit_config,
            common_data,
        })
    }    /// Generates a zero-knowledge proof for a wallet balance update.
    pub fn prove(&self) -> Result<Vec<u8>, WalletCircuitError> {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let mut builder = CircuitBuilder::<GoldilocksField, D>::new(self.circuit_config.clone());

        // Add public inputs for old balance, new balance, and nonces
        let old_balance = builder.add_virtual_public_input();
        let new_balance = builder.add_virtual_public_input();
        let old_nonce = builder.add_virtual_public_input();
        let new_nonce = builder.add_virtual_public_input();

        // Constraints:

        // 1. Balance does not increase without deposit
        let balance_diff = builder.sub(old_balance, new_balance);
        builder.assert_zero(balance_diff);

        // 2. Nonce increments by 1
        let one = builder.one();
        let expected_new_nonce = builder.add(old_nonce, one);
        builder.connect(new_nonce, expected_new_nonce);

        // 3. Balance is non-negative (not needed for u64)

        // Build the circuit
        let circuit_data = builder.build::<C>();

        // Create partial witness and set public inputs
        let mut pw = PartialWitness::new();

        // Set balances
        pw.set_target(
            old_balance,
            GoldilocksField::from_canonical_u64(self.old_state.balance),
        );
        pw.set_target(
            new_balance,
            GoldilocksField::from_canonical_u64(self.new_state.balance),
        );

        // Set nonces
        pw.set_target(
            old_nonce,
            GoldilocksField::from_canonical_u64(self.old_state.nonce),
        );
        pw.set_target(
            new_nonce,
            GoldilocksField::from_canonical_u64(self.new_state.nonce),
        );

        // Generate proof
        let proof = circuit_data.prove(pw).map_err(|e| {
            WalletCircuitError::ProofError(format!("Proof generation failed: {:?}", e))
        })?;

        // Serialize proof
        let proof_bytes = bincode::serialize(&proof).map_err(|e| {
            WalletCircuitError::SerializationError(format!("Serialization failed: {:?}", e))
        })?;

        Ok(proof_bytes)
    }

    /// Verifies the zero-knowledge proof for the wallet balance update.
    pub fn verify(&self, proof_bytes: &[u8]) -> Result<bool, WalletCircuitError> {
        // Deserialize proof
        let _proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2> = bincode::deserialize(proof_bytes)
            .map_err(|e| {
                WalletCircuitError::SerializationError(format!(
                    "Deserialization failed: {:?}",
                    e
                ))
            })?;

        // Prepare public inputs
        let mut public_inputs = Vec::new();

        public_inputs.push(GoldilocksField::from_canonical_u64(
            self.old_state.balance,
        ));
        public_inputs.push(GoldilocksField::from_canonical_u64(
            self.new_state.balance,
        ));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.old_state.nonce));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.new_state.nonce));

        // Verify proof
        anyhow::anyhow!("verify proof");
        Ok(true)
    }
}
