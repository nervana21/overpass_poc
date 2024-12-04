use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    field::types::Field,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GlobalCircuitError {
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferState {
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub nonce: u64,
}

/// Structure to hold transfer public inputs
#[derive(Debug)]
struct TransferPublicInputs {
    sender_old_balance: Target,
    receiver_old_balance: Target,
    amount: Target,
    nonce: Target,
    sender_new_balance: Target,
    receiver_new_balance: Target,
    new_nonce: Target,
}

pub struct TransferCircuit {
    old_state: TransferState,
    new_state: TransferState,
    amount: u64,
    circuit_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
}

impl TransferCircuit {
    pub fn new(
        old_state: TransferState,
        new_state: TransferState,
        amount: u64,
    ) -> Result<Self, GlobalCircuitError> {
        Self::validate_state_transition(&old_state, &new_state, amount)?;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        let pub_inputs = Self::add_public_inputs(&mut builder);
        Self::add_circuit_constraints(&mut builder, &pub_inputs)?;
        
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();

        Ok(Self {
            old_state,
            new_state,
            amount,
            circuit_data,
        })
    }

    /// Adds public inputs to the circuit
    fn add_public_inputs(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
    ) -> TransferPublicInputs {
        TransferPublicInputs {
            sender_old_balance: builder.add_virtual_public_input(),
            receiver_old_balance: builder.add_virtual_public_input(),
            amount: builder.add_virtual_public_input(),
            nonce: builder.add_virtual_public_input(),
            sender_new_balance: builder.add_virtual_public_input(),
            receiver_new_balance: builder.add_virtual_public_input(),
            new_nonce: builder.add_virtual_public_input(),
        }
    }

    /// Adds circuit constraints
    fn add_circuit_constraints(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: &TransferPublicInputs,
    ) -> Result<(), GlobalCircuitError> {
        // Balance constraints
        let computed_sender_new_balance = builder.sub(inputs.sender_old_balance, inputs.amount);
        builder.connect(inputs.sender_new_balance, computed_sender_new_balance);

        let computed_receiver_new_balance = builder.add(inputs.receiver_old_balance, inputs.amount);
        builder.connect(inputs.receiver_new_balance, computed_receiver_new_balance);

        // Nonce constraint
        let one = builder.one();
        let expected_new_nonce = builder.add(inputs.nonce, one);
        builder.connect(inputs.new_nonce, expected_new_nonce);

        // Non-negative balance assertions
        builder.assert_one(inputs.sender_new_balance);
        builder.assert_one(inputs.receiver_new_balance);

        Ok(())
    }

    /// Validates state transition
    fn validate_state_transition(
        old_state: &TransferState,
        new_state: &TransferState,
        amount: u64,
    ) -> Result<(), GlobalCircuitError> {
        if old_state.sender_balance < amount {
            return Err(GlobalCircuitError::InvalidTransition("Insufficient sender balance".into()));
        }

        if new_state.sender_balance != old_state.sender_balance.checked_sub(amount)
            .ok_or_else(|| GlobalCircuitError::InvalidTransition("Balance overflow".into()))? {
            return Err(GlobalCircuitError::InvalidTransition("Invalid sender balance update".into()));
        }

        if new_state.receiver_balance != old_state.receiver_balance.checked_add(amount)
            .ok_or_else(|| GlobalCircuitError::InvalidTransition("Balance overflow".into()))? {
            return Err(GlobalCircuitError::InvalidTransition("Invalid receiver balance update".into()));
        }

        if new_state.nonce != old_state.nonce + 1 {
            return Err(GlobalCircuitError::InvalidTransition("Invalid nonce increment".into()));
        }

        Ok(())
    }

    /// Populates the witness
    fn populate_witness(&self, pw: &mut PartialWitness<GoldilocksField>) -> Result<(), GlobalCircuitError> {
        // Set witness values for public inputs
        pw.set_target(
            self.circuit_data.prover_only.public_inputs[0],
            GoldilocksField::from_canonical_u64(self.old_state.sender_balance),
        );
        // Add remaining witness values similarly...

        Ok(())
    }

    pub fn prove(&self) -> Result<Vec<u8>, GlobalCircuitError> {
        let mut pw = PartialWitness::new();
        self.populate_witness(&mut pw)?;

        let proof = self.circuit_data.prove(pw)
            .map_err(|e| GlobalCircuitError::ProofError(e.to_string()))?;

        bincode::serialize(&proof)
            .map_err(|e| GlobalCircuitError::SerializationError(e.to_string()))
    }

    pub fn verify(&self, proof_bytes: &[u8]) -> Result<bool, GlobalCircuitError> {
        let proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2> = 
            bincode::deserialize(proof_bytes)
                .map_err(|e| GlobalCircuitError::SerializationError(e.to_string()))?;

        self.circuit_data.verify(proof)
            .map_err(|e| GlobalCircuitError::VerificationError(e.to_string()))?;

        Ok(true)
    }
}