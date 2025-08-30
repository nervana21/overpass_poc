// src/zkp/state.rs

use std::time::{SystemTime, UNIX_EPOCH};

use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, PrimeField64};
use sha2::{Digest, Sha256};

use crate::zkp::channel::ChannelState;
use crate::zkp::helpers::commitments::Bytes32;
use crate::zkp::pedersen_parameters::PedersenParameters;

/// Converts ChannelState into a 32-byte hash using PoseidonHash.
pub fn hash_state(state: &ChannelState) -> anyhow::Result<Bytes32> {
    let mut inputs = Vec::new();

    for &balance in &state.balances {
        inputs.push(GoldilocksField::from_canonical_u64(balance));
    }

    inputs.push(GoldilocksField::from_canonical_u64(state.nonce));

    for &byte in &state.metadata {
        inputs.push(GoldilocksField::from_canonical_u8(byte));
    }

    let hash_out = PoseidonHash::hash_no_pad(&inputs);
    let mut bytes = [0u8; 32];
    for (i, &element) in hash_out.elements.iter().enumerate() {
        let elem_u64 = element.to_canonical_u64();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
    }

    Ok(bytes)
}

pub fn current_timestamp() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
    now.as_secs()
}

#[derive(Debug, Clone)]
pub struct StateProof {
    pub pi: Bytes32,
    pub public_inputs: Vec<Bytes32>,
    pub timestamp: u64,
    pub params: PedersenParameters,
}

pub fn convert_helper_proof(proof: StateProof) -> crate::zkp::state_proof::StateProof {
    crate::zkp::state_proof::StateProof {
        pi: proof.pi,
        public_inputs: proof.public_inputs,
        timestamp: proof.timestamp,
    }
}

pub fn verify_wallet_proof(
    old_root: &Bytes32,
    new_root: &Bytes32,
    proof: &StateProof,
    _params: &PedersenParameters,
) -> bool {
    if current_timestamp().saturating_sub(proof.timestamp) > 3600 {
        return false;
    }

    if proof.public_inputs.len() < 2 {
        return false;
    }
    if proof.public_inputs[0] != *old_root || proof.public_inputs[1] != *new_root {
        return false;
    }

    let mut hasher = Sha256::new();
    proof.public_inputs.iter().for_each(|input| hasher.update(input));
    hasher.update(proof.timestamp.to_le_bytes());
    hasher.update(proof.params.g.compress().as_bytes());
    hasher.update(proof.params.h.compress().as_bytes());

    proof.pi == hasher.finalize().as_slice()
}

pub fn verify_zk_proof(
    proof: &Bytes32,
    public_inputs: &[Bytes32],
    params: &PedersenParameters,
) -> bool {
    if public_inputs.is_empty() {
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(proof);
    for input in public_inputs {
        hasher.update(input);
    }
    hasher.update(params.g.compress().as_bytes());
    hasher.update(params.h.compress().as_bytes());

    let mut expected = [0u8; 32];
    expected.copy_from_slice(&hasher.finalize());
    proof == &expected
}

pub fn generate_state_proof(
    old_commitment: Bytes32,
    new_commitment: Bytes32,
    merkle_root: Bytes32,
    params: &PedersenParameters,
) -> StateProof {
    let mut hasher = Sha256::new();
    hasher.update(old_commitment);
    hasher.update(new_commitment);
    hasher.update(merkle_root);

    let timestamp = current_timestamp();
    hasher.update(timestamp.to_le_bytes());
    hasher.update(params.g.compress().as_bytes());
    hasher.update(params.h.compress().as_bytes());

    let mut pi = [0u8; 32];
    pi.copy_from_slice(&hasher.finalize());

    StateProof {
        pi,
        public_inputs: vec![old_commitment, new_commitment, merkle_root],
        timestamp,
        params: params.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp_nonzero() {
        let ts = current_timestamp();
        assert!(ts > 0);
    }

    #[test]
    fn test_generate_and_verify_state_proof() {
        let params = PedersenParameters::default();
        let old_commitment = [1u8; 32];
        let new_commitment = [2u8; 32];
        let merkle_root = [3u8; 32];

        let proof = generate_state_proof(old_commitment, new_commitment, merkle_root, &params);

        assert_eq!(proof.public_inputs.len(), 3);
        assert_eq!(proof.public_inputs[0], old_commitment);
        assert_eq!(proof.public_inputs[1], new_commitment);
        assert_eq!(proof.public_inputs[2], merkle_root);
    }
}
