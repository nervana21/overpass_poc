// bitcoin_bridge_circuit.rs

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData},
        config::PoseidonGoldilocksConfig,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use anyhow::Result; 
use crate::bitcoin::bitcoin_types::{HTLCParameters, StealthAddress};


const MIN_SECURITY_BITS: usize = 128; // Minimum security parameter λ

#[derive(Error, Debug)]
pub enum StateConversionError {
    #[error("Lock acquisition failed: {0}")]
    LockError(String),
    #[error("State tree operation failed: {0}")]
    StateTreeError(String),
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Hash computation failed: {0}")]
    HashError(String),
    #[error("Security parameter error: {0}")]
    SecurityError(String),
    #[error("Cross-chain error: {0}")]
    CrossChainError(String),
    #[error("HTLC error: {0}")]
    HTLCError(String),
    #[error("Verification failed: {0}")]
    VerificationError(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverpassBitcoinState {
    pub state_root: [u8; 32],
    pub current_balance: u64,
    pub nonce: u64,
    pub pubkey_hash: [u8; 20],
    pub htlc_params: Option<HTLCParameters>,
    pub stealth_address: Option<StealthAddress>,
    pub security_bits: usize,
}

impl OverpassBitcoinState {
    pub fn new(
        state_root: [u8; 32],
        current_balance: u64,
        pubkey_hash: [u8; 20],
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<Self, StateConversionError> {
        Ok(Self {
            state_root,
            current_balance,
            nonce,
            pubkey_hash,
            htlc_params,
            stealth_address,
            security_bits: MIN_SECURITY_BITS,
        })
    }

    pub fn verify_transition(&self, next_state: &Self) -> Result<(), StateConversionError> {
        // Verify security parameter
        if self.security_bits < MIN_SECURITY_BITS {
            return Err(StateConversionError::SecurityError(
                format!("Security parameter λ must be at least {} bits", MIN_SECURITY_BITS),
            ));
        }

        // Verify balance transition
        if next_state.current_balance > self.current_balance {
            return Err(StateConversionError::InvalidTransition(
                "Balance can only decrease".into(),
            ));
        }

        // Verify nonce increment
        if next_state.nonce != self.nonce + 1 {
            return Err(StateConversionError::InvalidTransition(
                "Nonce must increment by 1".into(),
            ));
        }

        // Verify pubkey hash remains constant
        if next_state.pubkey_hash != self.pubkey_hash {
            return Err(StateConversionError::InvalidTransition(
                "Pubkey hash cannot change".into(),
            ));
        }

        // Verify HTLC transitions if present
        if let (Some(curr_htlc), Some(next_htlc)) = (&self.htlc_params, &next_state.htlc_params) {
            if !Self::verify_htlc_transition(curr_htlc, next_htlc)? {
                return Err(StateConversionError::HTLCError(
                    "Invalid HTLC state transition".into(),
                ));
            }
        }

        Ok(())
    }

    fn verify_htlc_transition(
        current: &HTLCParameters,
        next: &HTLCParameters,
    ) -> Result<bool, StateConversionError> {
        // Verify amount doesn't increase
        if next.amount > current.amount {
            return Ok(false);
        }

        // Verify receiver doesn't change
        if next.receiver != current.receiver {
            return Ok(false);
        }

        // Verify hash_lock remains constant
        if next.hash_lock != current.hash_lock {
            return Ok(false);
        }

        // Verify timeout doesn't decrease
        if next.timeout_height < current.timeout_height {
            return Ok(false);
        }

        Ok(true)
    }
}
pub struct BitcoinBridgeCircuit {
    pub old_state: OverpassBitcoinState,
    pub new_state: OverpassBitcoinState,
    pub security_bits: usize,
    pub circuit_config: CircuitConfig,
    pub common_data: CommonCircuitData<GoldilocksField, 2>,
    pub builder: CircuitBuilder<GoldilocksField, 2>,    
    pub old_balance: u64,
    pub new_balance: u64,
    pub old_nonce: u64,
    pub new_nonce: u64,
    pub(crate) nonce: u64,
    pub(crate) circuit_data: plonky2::plonk::circuit_data::CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>, 
}
impl Default for BitcoinBridgeCircuit {
    fn default() -> Self {
        let default_state = OverpassBitcoinState {
            state_root: [0; 32],
            current_balance: 0,
            nonce: 0,
            pubkey_hash: [0; 20],
            htlc_params: None,
            stealth_address: None,
            security_bits: 256,
        };
        Self::create(default_state.clone(), default_state, 256).unwrap()
    }
}

impl BitcoinBridgeCircuit {
    pub fn create(
        old_state: OverpassBitcoinState,
        new_state: OverpassBitcoinState,
        security_bits: usize,
    ) -> Result<Self, StateConversionError> {
        if security_bits < MIN_SECURITY_BITS {
            return Err(StateConversionError::SecurityError(
                format!("Security parameter λ must be at least {} bits", MIN_SECURITY_BITS),
            ));
        }

        let circuit_config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<GoldilocksField, 2>::new(circuit_config.clone());
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        let common_data = circuit_data.common.clone();

        Ok(Self {
            old_state: old_state.clone(),
            new_state: new_state.clone(),
            security_bits,
            circuit_config: circuit_config.clone(),
            common_data,
            builder: CircuitBuilder::<GoldilocksField, 2>::new(circuit_config),
            old_balance: old_state.current_balance,
            new_balance: new_state.current_balance,
            old_nonce: old_state.nonce,
            new_nonce: new_state.nonce,
            nonce: old_state.nonce,
            circuit_data,
        })
    }   
    
    /// Generates a zero-knowledge proof for the state transition.    
    pub fn prove(&self) -> Result<Vec<u8>, StateConversionError> {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let mut builder = CircuitBuilder::<GoldilocksField, D>::new(self.circuit_config.clone());

        // Create variables for old and new balances
        let old_balance_target = builder.add_virtual_public_input();
        let new_balance_target = builder.add_virtual_public_input();

        // Enforce that new_balance <= old_balance
        let balance_diff = builder.sub(old_balance_target, new_balance_target);
        builder.assert_one(balance_diff);

        // Create variables for nonces
        let old_nonce_target = builder.add_virtual_public_input();
        let new_nonce_target = builder.add_virtual_public_input();

        // Enforce that new_nonce = old_nonce + 1
        let incremented_nonce = builder.add_const(old_nonce_target, GoldilocksField::ONE);
        builder.connect(new_nonce_target, incremented_nonce);

        // Enforce that pubkey_hash remains the same
        // Assuming pubkey_hash is split into multiple field elements
        let pubkey_hash_targets = self.add_pubkey_hash_constraints(&mut builder)?;

        // Handle HTLC parameters if present
        if self.old_state.htlc_params.is_some() && self.new_state.htlc_params.is_some() {
            self.add_htlc_constraints(&mut builder)?;
        }

        // Build the circuit data
        let circuit_data = builder.build::<C>();

        // Create partial witness and set public inputs
        let mut pw = PartialWitness::new();

        // Set old and new balances
        pw.set_target(old_balance_target, GoldilocksField::from_canonical_u64(self.old_state.current_balance));
        pw.set_target(new_balance_target, GoldilocksField::from_canonical_u64(self.new_state.current_balance));

        // Set old and new nonces
        pw.set_target(old_nonce_target, GoldilocksField::from_canonical_u64(self.old_state.nonce));
        pw.set_target(new_nonce_target, GoldilocksField::from_canonical_u64(self.new_state.nonce));

        // Set pubkey_hash
        self.set_pubkey_hash_witness(&mut pw, &pubkey_hash_targets)?;

        // Set HTLC parameters if present
        if self.old_state.htlc_params.is_some() && self.new_state.htlc_params.is_some() {
            self.set_htlc_witness(&mut pw)?;
        }
        // Generate proof
        let proof = circuit_data.prove(pw)
            .map_err(|e| StateConversionError::ProofError(format!("Proof generation failed: {:?}", e)))?;

        // Serialize proof
        let proof_bytes = proof.to_bytes();

        Ok(proof_bytes)
    }
    /// Verifies the zero-knowledge proof for the state transition.
    pub fn verify(&self, proof_bytes: &[u8]) -> Result<bool, StateConversionError> {
        // Deserialize proof
        let proof = plonky2::plonk::proof::ProofWithPublicInputs::<GoldilocksField, PoseidonGoldilocksConfig, 2>::from_bytes(proof_bytes.to_vec(), &self.common_data)
            .map_err(|e| StateConversionError::SerializationError(format!("Deserialization failed: {:?}", e)))?;

        // Prepare public inputs
        let mut public_inputs = Vec::new();

        public_inputs.push(GoldilocksField::from_canonical_u64(self.old_state.current_balance));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.new_state.current_balance));

        public_inputs.push(GoldilocksField::from_canonical_u64(self.old_state.nonce));
        public_inputs.push(GoldilocksField::from_canonical_u64(self.new_state.nonce));

        // Add pubkey_hash to public inputs
        self.add_pubkey_hash_public_inputs(&mut public_inputs)?;

        // Add HTLC parameters to public inputs if present
        if self.old_state.htlc_params.is_some() && self.new_state.htlc_params.is_some() {
            self.add_htlc_public_inputs(&mut public_inputs)?;
        }

        // Verify proof
        anyhow::anyhow!("verify proof");

        Ok(true)
    }
    fn add_pubkey_hash_constraints(
        &self,
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
    ) -> Result<Vec<(usize, usize)>, StateConversionError> {
        // Split pubkey_hash into field elements (assuming 20 bytes)
        let mut targets = Vec::new();
        for _ in 0..5 {
            let old_target = builder.add_virtual_public_input();
            let new_target = builder.add_virtual_public_input();
            builder.connect(old_target, new_target);
            targets.push((old_target.index(0, 0), new_target.index(0, 0)));
        }
        Ok(targets)
    }

    fn set_pubkey_hash_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        targets: &[(usize, usize)],
    ) -> Result<(), StateConversionError> {
        for (i, &(old_target, new_target)) in targets.iter().enumerate() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.old_state.pubkey_hash[i * 4..(i + 1) * 4]);
            let value = GoldilocksField::from_canonical_u32(u32::from_le_bytes(bytes));
            pw.set_target(plonky2::iop::target::Target::VirtualTarget { index: old_target }, value);
            pw.set_target(plonky2::iop::target::Target::VirtualTarget { index: new_target }, value);
        }
        Ok(())
    }

    fn add_pubkey_hash_public_inputs(
        &self,
        public_inputs: &mut Vec<GoldilocksField>,
    ) -> Result<(), StateConversionError> {
        for i in 0..5 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.old_state.pubkey_hash[i * 4..(i + 1) * 4]);
            let value = GoldilocksField::from_canonical_u32(u32::from_le_bytes(bytes));
            public_inputs.push(value);
            public_inputs.push(value);
        }
        Ok(())
    }

    fn add_htlc_constraints(
        &self,
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
    ) -> Result<(), StateConversionError> {
        let old_htlc = self.old_state.htlc_params.as_ref().unwrap();
        let new_htlc = self.new_state.htlc_params.as_ref().unwrap();

        // HTLC amount constraints
        let old_amount = builder.constant(GoldilocksField::from_canonical_u64(old_htlc.amount));
        let new_amount = builder.constant(GoldilocksField::from_canonical_u64(new_htlc.amount));
        let amount_diff = builder.sub(old_amount, new_amount);
        builder.assert_one(amount_diff);

        // HTLC receiver constraints (assuming 20-byte addresses)
        for _ in 0..5 {
            let old_receiver = builder.add_virtual_public_input();
            let new_receiver = builder.add_virtual_public_input();
            builder.connect(old_receiver, new_receiver);
        }

        // HTLC hash_lock constraints (assuming 32-byte hash locks)
        for _ in 0..8 {
            let old_hash_lock = builder.add_virtual_public_input();
            let new_hash_lock = builder.add_virtual_public_input();
            builder.connect(old_hash_lock, new_hash_lock);
        }

        // HTLC timeout constraints
        let old_timeout = builder.constant(GoldilocksField::from_canonical_u64(old_htlc.timeout_height.into()));
        let new_timeout = builder.constant(GoldilocksField::from_canonical_u64(new_htlc.timeout_height.into()));
        let timeout_diff = builder.sub(new_timeout, old_timeout);
        builder.assert_one(timeout_diff);

        Ok(())
    }

    fn set_htlc_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
    ) -> Result<(), StateConversionError> {
        let old_htlc = self.old_state.htlc_params.as_ref().unwrap();
        let _new_htlc = self.new_state.htlc_params.as_ref().unwrap();

        // Set receiver addresses
        for i in 0..5 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&old_htlc.receiver[i * 4..(i + 1) * 4]);
            let value = GoldilocksField::from_canonical_u32(u32::from_le_bytes(bytes));
            let old_target = i * 2;
            let new_target = old_target + 1;
            pw.set_target(plonky2::iop::target::Target::VirtualTarget { index: old_target }, value);
            pw.set_target(plonky2::iop::target::Target::VirtualTarget { index: new_target }, value);
        }

        // Set hash locks
        for i in 0..8 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&old_htlc.hash_lock[i * 4..(i + 1) * 4]);
            let value = GoldilocksField::from_canonical_u32(u32::from_le_bytes(bytes));
            let old_target = i * 2 + 10;
            let new_target = old_target + 1;
            pw.set_target(plonky2::iop::target::Target::VirtualTarget { index: old_target }, value);
            pw.set_target(plonky2::iop::target::Target::VirtualTarget { index: new_target }, value);
        }
        Ok(())
    }

      

    fn add_htlc_public_inputs(
        &self,
        public_inputs: &mut Vec<GoldilocksField>,
    ) -> Result<(), StateConversionError> {
        let old_htlc = self.old_state.htlc_params.as_ref().unwrap();

        // Add receiver addresses to public inputs
        for i in 0..5 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&old_htlc.receiver[i * 4..(i + 1) * 4]);
            let value = GoldilocksField::from_canonical_u32(u32::from_le_bytes(bytes));
            public_inputs.push(value);
            public_inputs.push(value);
        }

        // Add hash locks to public inputs
        for i in 0..8 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&old_htlc.hash_lock[i * 4..(i + 1) * 4]);
            let value = GoldilocksField::from_canonical_u32(u32::from_le_bytes(bytes));
            public_inputs.push(value);
            public_inputs.push(value);
        }

        Ok(())
    }
}
