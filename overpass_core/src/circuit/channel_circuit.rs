// ./src/circuit/channel_circuit.rs

use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
    gates::noop::NoopGate,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChannelCircuitError {
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelState {
    pub balances: [u64; 2],
    pub nonce: u64,
}

pub struct ChannelCircuit {
    pub old_state: ChannelState,
    pub new_state: ChannelState,
    pub circuit_config: CircuitConfig,
    pub common_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
}

impl Default for ChannelCircuit {
    fn default() -> Self {
        let default_state = ChannelState {
            balances: [0, 0],
            nonce: 0,
        };
        Self::new(default_state.clone(), default_state).unwrap()
    }
}

impl ChannelCircuit {
    pub fn new(
        old_state: ChannelState,
        new_state: ChannelState,
    ) -> Result<Self, ChannelCircuitError> {
        if old_state.balances.iter().sum::<u64>() != new_state.balances.iter().sum::<u64>() {
            return Err(ChannelCircuitError::InvalidState(
                "Total balance must remain constant".into(),
            ));
        }

        if new_state.nonce != old_state.nonce + 1 {
            return Err(ChannelCircuitError::InvalidState(
                "Nonce must increment by 1".into(),
            ));
        }

        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(circuit_config.clone());
        builder.add_gate(NoopGate, vec![]);
        let common_data = builder.build::<PoseidonGoldilocksConfig>();

        Ok(Self {
            old_state,
            new_state,
            circuit_config,
            common_data
        })
    }

    fn build_circuit_data(&self) -> Result<CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>, ChannelCircuitError> {
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(self.circuit_config.clone());

        let old_balance0 = builder.add_virtual_public_input();
        let old_balance1 = builder.add_virtual_public_input();
        let new_balance0 = builder.add_virtual_public_input();
        let new_balance1 = builder.add_virtual_public_input();
        let old_nonce = builder.add_virtual_public_input();
        let new_nonce = builder.add_virtual_public_input();

        let total_old_balance = builder.add(old_balance0, old_balance1);
        let total_new_balance = builder.add(new_balance0, new_balance1);
        builder.connect(total_old_balance, total_new_balance);

        let one = builder.one();
        let expected_new_nonce = builder.add(old_nonce, one);
        builder.connect(new_nonce, expected_new_nonce);

        Ok(builder.build::<PoseidonGoldilocksConfig>())
    }
    pub fn prove(&self) -> Result<Vec<u8>, ChannelCircuitError> {
        let circuit_data = self.build_circuit_data()?;
        let mut pw = PartialWitness::new();

        pw.set_target(
            circuit_data.prover_only.public_inputs[0],
            GoldilocksField::from_canonical_u64(self.old_state.balances[0]),
        );
        pw.set_target(
            circuit_data.prover_only.public_inputs[1],
            GoldilocksField::from_canonical_u64(self.old_state.balances[1]),
        );
        pw.set_target(
            circuit_data.prover_only.public_inputs[2],
            GoldilocksField::from_canonical_u64(self.new_state.balances[0]),
        );
        pw.set_target(
            circuit_data.prover_only.public_inputs[3],
            GoldilocksField::from_canonical_u64(self.new_state.balances[1]),
        );
        pw.set_target(
            circuit_data.prover_only.public_inputs[4],
            GoldilocksField::from_canonical_u64(self.old_state.nonce),
        );
        pw.set_target(
            circuit_data.prover_only.public_inputs[5],
            GoldilocksField::from_canonical_u64(self.new_state.nonce),
        );

        let proof = circuit_data.prove(pw).map_err(|e| {
            ChannelCircuitError::ProofError(format!("Failed to generate proof: {:?}", e))
        })?;

        Ok(proof.to_bytes())
    }

    pub fn verify(&self, proof_bytes: &[u8]) -> Result<bool, ChannelCircuitError> {
        let circuit_data = self.build_circuit_data()?;
        
        let mut public_inputs = Vec::new();
        public_inputs.push(GoldilocksField::from_canonical_u64(self.old_state.balances[0]));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.old_state.balances[1]));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.new_state.balances[0]));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.new_state.balances[1]));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.old_state.nonce));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.new_state.nonce));

        let proof = plonky2::plonk::proof::ProofWithPublicInputs::from_bytes(
            proof_bytes.to_vec(),
            &circuit_data.common,
        ).map_err(|e| ChannelCircuitError::VerificationError(format!("Failed to deserialize proof: {:?}", e)))?;

        circuit_data.verify(proof).map_err(|e| {
            ChannelCircuitError::VerificationError(format!("Proof verification failed: {:?}", e))
        })?;

        Ok(true)
    }
}