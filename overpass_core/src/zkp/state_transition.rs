// src/zkp/state_transition.rs

use crate::zkp::channel::ChannelState;
use crate::zkp::tree::{MerkleProof, MerkleTree};
use anyhow::{anyhow, Context, Result};
use plonky2::plonk::config::Hasher;
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
use plonky2_field::types::{Field, PrimeField64};
use std::collections::HashMap;

use super::helpers::{compute_channel_root, hash_state};

/// Type alias for Poseidon configuration
type PoseidonConfig = PoseidonGoldilocksConfig;

/// Represents the state transition circuit using Plonky2.
pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, PoseidonConfig, 2>,
    current_state_target: HashOutTarget,
    next_state_target: HashOutTarget,
    transition_data_target: HashOutTarget,
    channel_roots: HashMap<[u8; 32], [u8; 32]>, // Changed to [u8; 32]
    merkle_tree: MerkleTree,
}

impl StateTransitionCircuit {
    /// Initializes a new state transition circuit.
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Define virtual hash targets for current state, transition data, and next state.
        let current_state_target = builder.add_virtual_hash();
        let transition_data_target = builder.add_virtual_hash();
        let next_state_target = builder.add_virtual_hash();

        // Register current and next states as public inputs.
        builder.register_public_inputs(&current_state_target.elements);
        builder.register_public_inputs(&next_state_target.elements);

        // Prepare inputs for Poseidon hash: interleaving current state and transition data.
        let inputs = current_state_target
            .elements
            .iter()
            .zip(transition_data_target.elements.iter())
            .flat_map(|(&c, &t)| vec![c, t])
            .collect::<Vec<_>>();

        // Compute the next state hash using Poseidon without padding.
        let computed_next_state = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        // Enforce that the computed hash matches the declared next state.
        for i in 0..4 {
            builder.connect(
                computed_next_state.elements[i],
                next_state_target.elements[i],
            );
        }

        // Finalize the circuit.
        let circuit_data = builder.build::<PoseidonConfig>();

        Self {
            circuit_data,
            current_state_target,
            next_state_target,
            transition_data_target,
            channel_roots: HashMap::new(),
            merkle_tree: MerkleTree::new(),
        }
    }

    /// Generates a zero-knowledge proof for a state transition.
    pub fn generate_zkp(
        &self,
        channel_id: [u8; 32],
        initial_state: &ChannelState,
        transition_data: &[u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, PoseidonConfig, 2>> {
        let mut pw = PartialWitness::new();

        let next_state = apply_transition(channel_id, initial_state, transition_data)
            .context("Failed to apply transition to initial state")?;

        // Serialize and hash the initial and next states
        let initial_state_bytes =
            hash_state(initial_state).context("Failed to hash initial state")?;
        let next_state_bytes = hash_state(&next_state).context("Failed to hash next state")?;

        // Convert byte arrays to HashOut targets.
        let initial_hash =
            Self::to_hash_out(initial_state_bytes).context("Failed to convert initial hash")?;
        let transition_hash = Self::to_hash_out(*transition_data)
            .context("Failed to convert transition data hash")?;
        let next_hash =
            Self::to_hash_out(next_state_bytes).context("Failed to convert next hash")?;

        // Assign hashes to their respective targets.
        pw.set_hash_target(self.current_state_target, initial_hash)
            .context("Failed to set initial state hash")?;
        pw.set_hash_target(self.transition_data_target, transition_hash)
            .context("Failed to set transition data hash")?;
        pw.set_hash_target(self.next_state_target, next_hash)
            .context("Failed to set next state hash")?;

        // Generate and return the proof.
        self.circuit_data
            .prove(pw)
            .context("Proof generation failed")
    }

    /// Verifies a zero-knowledge proof for a state transition.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, PoseidonConfig, 2>,
    ) -> Result<bool> {
        self.circuit_data
            .verify(proof)
            .map(|_| true)
            .context("Proof verification failed")
    }

    /// Converts a byte array to a Poseidon HashOut.
    fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>, anyhow::Error> {
        let elements = data
            .chunks(8)
            .map(|chunk| {
                let bytes: [u8; 8] = chunk
                    .try_into()
                    .map_err(|_| anyhow!("Invalid byte length for field element"))?;
                Ok(GoldilocksField::from_canonical_u64(u64::from_le_bytes(
                    bytes,
                )))
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        Ok(HashOut::from_partial(&elements))
    }

    /// Converts a Poseidon HashOut back to a byte array.
    fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        for (i, &element) in hash.elements.iter().enumerate() {
            let elem_u64 = element.to_noncanonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Computes the Poseidon hash for the next state based on current state and transition data.
    fn compute_poseidon_hash(
        current_hash: &HashOut<GoldilocksField>,
        transition_hash: &HashOut<GoldilocksField>,
    ) -> HashOut<GoldilocksField> {
        let inputs = vec![
            current_hash.elements[0],
            transition_hash.elements[0],
            current_hash.elements[1],
            transition_hash.elements[1],
            current_hash.elements[2],
            transition_hash.elements[2],
            current_hash.elements[3],
            transition_hash.elements[3],
        ];
        PoseidonHash::hash_no_pad(&inputs)
    }

    /// Computes the next state based on current state and transition data.
    pub fn compute_next_state(
        &self,
        current_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<[u8; 32]> {
        let current_hash =
            Self::to_hash_out(current_state).context("Failed to convert current state hash")?;
        let transition_hash =
            Self::to_hash_out(transition_data).context("Failed to convert transition data hash")?;
        let next_hash = Self::compute_poseidon_hash(&current_hash, &transition_hash);
        Self::hash_out_to_bytes(&next_hash).context("Failed to convert next hash to bytes")
    }

    /// Generates a Merkle proof for a channel's transaction history.
    pub fn generate_merkle_proof(&self, channel_id: [u8; 32]) -> Option<MerkleProof> {
        self.channel_roots.get(&channel_id).and_then(|root| {
            self.merkle_tree
                .get_proof(root)
                .map(|proof| MerkleProof { path: proof })
        })
    }

    /// Verifies a Merkle proof for a channel's transaction history.
    pub fn verify_merkle_proof(&self, channel_id: [u8; 32], proof: &MerkleProof) -> bool {
        if let Some(root) = self.channel_roots.get(&channel_id) {
            self.merkle_tree.verify_proof(root, &proof.path, root)
        } else {
            false
        }
    }
}

impl Default for StateTransitionCircuit {
    fn default() -> Self {
        Self::new()
    }
}

/// Applies transition data to the initial state to produce the next state.
pub fn apply_transition(
    channel_id: [u8; 32],
    initial_state: &ChannelState,
    transition_data: &[u8; 32],
) -> Result<ChannelState> {
    let delta_balance_0 = i32::from_le_bytes(
        transition_data[0..4]
            .try_into()
            .context("Failed to parse delta_balance_0")?,
    );
    let delta_balance_1 = i32::from_le_bytes(
        transition_data[4..8]
            .try_into()
            .context("Failed to parse delta_balance_1")?,
    );

    let initial_balance_0 = initial_state
        .balances
        .get(0)
        .copied()
        .ok_or_else(|| anyhow!("Missing balance 0"))? as i64;

    let initial_balance_1 = initial_state
        .balances
        .get(1)
        .copied()
        .ok_or_else(|| anyhow!("Missing balance 1"))? as i64;

    let new_balance_0 = initial_balance_0
        .checked_add(delta_balance_0 as i64)
        .ok_or_else(|| anyhow!("Balance overflow for balance 0"))?;

    let new_balance_1 = initial_balance_1
        .checked_add(delta_balance_1 as i64)
        .ok_or_else(|| anyhow!("Balance overflow for balance 1"))?;

    // Ensure non-negative balances
    if new_balance_0 < 0 || new_balance_1 < 0 {
        anyhow::bail!("Negative balance is not allowed");
    }

    // Increment nonce strictly by +1
    let new_nonce = initial_state
        .nonce
        .checked_add(1)
        .ok_or_else(|| anyhow!("Nonce overflow"))?;

    let mut new_state = ChannelState {
        balances: vec![
            new_balance_0
                .try_into()
                .context("Failed to convert balance 0")?,
            new_balance_1
                .try_into()
                .context("Failed to convert balance 1")?,
        ],
        nonce: new_nonce,
        metadata: initial_state.metadata.clone(),
        merkle_root: [0u8; 32],
        proof: None,
    };

    new_state.merkle_root = compute_channel_root(
        channel_id,
        hash_state(&new_state)?, // Commitment hash based on updated state
        new_nonce,
    );

    Ok(new_state)
}
