// src/zkp/helpers.rs

use anyhow::{anyhow, Result};
use corepc_node::{tempfile::tempdir, Conf, Node};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use miniscript::bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    script::Builder,
    transaction::{Transaction, TxIn, TxOut, Version},
    Address, Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness,
};
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::zkp::channel::ChannelState;
use crate::zkp::pedersen_parameters::PedersenParameters;
use plonky2_field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};

/// Type alias for bytes32.
pub type Bytes32 = [u8; 32];

/// Represents a Point on the elliptic curve.
pub type Point = RistrettoPoint;

/// Generates a random blinding factor.
pub fn generate_random_blinding() -> Bytes32 {
    let mut rng = OsRng;
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    blinding
}

/// Computes Pedersen commitment.
pub fn pedersen_commit(
    value: Vec<u64>,
    blinding: Bytes32,
    hparams: &PedersenParameters,
) -> Bytes32 {
    let total: u64 = value.iter().sum();
    let value_scalar = Scalar::from(total);
    let blinding_scalar = Scalar::from_bytes_mod_order(blinding);
    let commitment = hparams.g * value_scalar + hparams.h * blinding_scalar;
    hash_point(commitment)
}

/// Hashes a RistrettoPoint to bytes32 using SHA256.
pub fn hash_point(point: Point) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(point.compress().as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Computes the Merkle root from wallet roots.
pub fn compute_global_root(wallet_roots: &HashMap<Bytes32, Bytes32>) -> Result<Bytes32, String> {
    let leaves: Vec<Bytes32> = wallet_roots.values().cloned().collect();
    Ok(compute_merkle_root(leaves))
}

/// Computes the Merkle root from channel state.
pub fn compute_channel_root(channel_id: Bytes32, commitment: Bytes32, nonce: u64) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(channel_id);
    hasher.update(commitment);
    hasher.update(nonce.to_le_bytes());
    let result = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&result);
    root
}

/// Computes Merkle root from a list of leaves.
pub fn compute_merkle_root(leaves: Vec<Bytes32>) -> Bytes32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut current_level: Vec<Bytes32> = leaves;
    while current_level.len() > 1 {
        // If odd number of nodes, duplicate the last one.
        if current_level.len() % 2 != 0 {
            current_level.push(*current_level.last().unwrap());
        }
        current_level = current_level
            .chunks(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect::<Vec<Bytes32>>();
    }
    current_level[0]
}

/// Computes the global Merkle root from a sorted slice of leaves.
/// If the slice is empty, returns the default zeroed root.
pub fn compute_global_root_from_sorted(sorted_hashes: &[Bytes32]) -> Bytes32 {
    if sorted_hashes.is_empty() {
        return [0u8; 32];
    }
    let mut current_level = sorted_hashes.to_vec();
    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            current_level.push(*current_level.last().unwrap());
        }
        current_level = current_level
            .chunks(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    current_level[0]
}

/// Hashes two bytes32 together to form parent node.
pub fn hash_pair(left: Bytes32, right: Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&result);
    parent
}

/// Converts the ChannelState into a 32-byte hash using PoseidonHash.
pub fn hash_state(state: &ChannelState) -> Result<Bytes32> {
    let mut inputs = Vec::new();

    // Serialize balances
    for &balance in &state.balances {
        let field_element = GoldilocksField::from_canonical_u64(balance);
        inputs.push(field_element);
    }

    // Serialize nonce
    let nonce_element = GoldilocksField::from_canonical_u64(state.nonce);
    inputs.push(nonce_element);

    // Serialize metadata
    for &byte in &state.metadata {
        let metadata_element = GoldilocksField::from_canonical_u8(byte);
        inputs.push(metadata_element);
    }

    // Compute Poseidon hash
    let hash_out = PoseidonHash::hash_no_pad(&inputs);

    // Convert to bytes
    let mut bytes = [0u8; 32];
    for (i, &element) in hash_out.elements.iter().enumerate() {
        let elem_u64 = element.to_canonical_u64();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
    }

    Ok(bytes)
}

/// Current Unix timestamp.
pub fn current_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    now.as_secs()
}

/// Represents a state proof for wallet updates.
#[derive(Debug, Clone)]
pub struct StateProof {
    pub pi: Bytes32,
    pub public_inputs: Vec<Bytes32>,
    pub timestamp: u64,
    pub params: PedersenParameters,
}

/// Convert between StateProof types
pub fn convert_helper_proof(proof: StateProof) -> crate::zkp::state_proof::StateProof {
    crate::zkp::state_proof::StateProof {
        pi: proof.pi,
        public_inputs: proof.public_inputs,
        timestamp: proof.timestamp,
    }
}

/// Verify a wallet proof.
pub fn verify_wallet_proof(
    old_root: &Bytes32,
    new_root: &Bytes32,
    proof: &StateProof,
    params: &PedersenParameters,
) -> bool {
    // Verify timestamp is recent enough (within last hour)
    let current_time = current_timestamp();
    if current_time - proof.timestamp > 3600 {
        return false;
    }

    // Verify public inputs contain the old and new roots
    if proof.public_inputs.len() < 2 {
        return false;
    }
    if proof.public_inputs[0] != *old_root || proof.public_inputs[1] != *new_root {
        return false;
    }

    // compute the hash
    let mut hasher = Sha256::new();
    proof
        .public_inputs
        .iter()
        .for_each(|input| hasher.update(input));
    hasher.update(proof.timestamp.to_le_bytes()); // timestamp
    hasher.update(params.g.compress().as_bytes()); // Pedersen parameter `g`
    hasher.update(params.h.compress().as_bytes()); // Pedersen parameter `h`

    let expected = hasher.finalize();

    proof.pi == *expected
}
/// Verifies a zero-knowledge proof using Pedersen commitments.
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

    let result = hasher.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&result);

    proof == &expected
}

/// Generates a zero-knowledge proof of state transition.
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

    let result = hasher.finalize();
    let mut pi = [0u8; 32];
    pi.copy_from_slice(&result);

    StateProof {
        pi,
        public_inputs: vec![old_commitment, new_commitment, merkle_root],
        timestamp,
        params: params.clone(),
    }
}

/// Builds an OP_RETURN transaction embedding the provided data.
pub fn build_op_return_transaction(
    node: &Node,
    address: &Address,
    data: [u8; 32],
) -> Result<Transaction> {
    // Step 1: Get the first available UTXO for the given address
    let utxos: Vec<Value> = node.client.call("listunspent", &[])?;
    let utxo = utxos
        .into_iter()
        .find(|u| u.get("address") == Some(&Value::String(address.to_string())))
        .ok_or_else(|| anyhow!("No UTXO found for address {}", address))?;

    let txid_str = utxo
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing txid"))?;
    let txid: Txid = txid_str.parse()?;

    let vout = utxo
        .get("vout")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Missing vout"))? as u32;

    let amount_btc = utxo
        .get("amount")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow!("Missing amount"))?;
    let input_value = (amount_btc * 100_000_000.0) as u64; // Convert BTC to satoshis

    // Step 2: Construct the OP_RETURN output.
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&data)
        .into_script();
    let op_return_output = TxOut {
        value: Amount::from_sat(0), // OP_RETURN outputs have zero value.
        script_pubkey: op_return_script,
    };

    let fee = 1000; // e.g., 1000 satoshis fee.
    if input_value <= fee {
        return Err(anyhow!("Insufficient funds to cover fee"));
    }
    let change_value = input_value - fee;
    let change_address = node.client.new_address()?;
    // Use the script_pubkey directly from the change address.
    let change_script = change_address.script_pubkey();
    let change_output = TxOut {
        value: Amount::from_sat(change_value),
        script_pubkey: change_script,
    };

    // Step 4: Construct the transaction.
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(0)?,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![op_return_output, change_output],
    };

    Ok(tx)
}

/// Builds a P2TR transaction with n = 21 outputs of 546 sats each
/// to model a relatively simple transaction that might be used
/// for a single utxo funding multiple other UTXOs
pub fn build_p2tr_transaction(node: &Node, funding_address: &Address) -> Result<Transaction> {
    use miniscript::bitcoin::AddressType as BtcAddressType;

    let utxos: Vec<Value> = node.client.call("listunspent", &[])?;
    let utxo = utxos
        .into_iter()
        .find(|u| u.get("address") == Some(&Value::String(funding_address.to_string())))
        .ok_or_else(|| anyhow!("No UTXO found for address {}", funding_address))?;

    let txid: Txid = utxo
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing txid"))?
        .parse()?;

    let vout = utxo
        .get("vout")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Missing vout"))? as u32;

    let input_value = (utxo
        .get("amount")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow!("Missing amount"))?
        * 100_000_000.0) as u64;

    let dust_limit = 546;
    let num_outputs = 21;

    let mut outputs = Vec::with_capacity(num_outputs + 1); // 21 + change
    let mut total_output_value = 0;

    for _ in 0..num_outputs {
        let addr = node
            .client
            .new_address_with_type(corepc_node::AddressType::Bech32m)?;
        if addr.address_type() != Some(BtcAddressType::P2tr) {
            return Err(anyhow!("Expected Taproot address, got: {}", addr));
        }

        outputs.push(TxOut {
            value: Amount::from_sat(dust_limit),
            script_pubkey: addr.script_pubkey(),
        });
        total_output_value += dust_limit;
    }

    // Estimate fee
    let fee_per_vb = 2;
    let est_vbytes = 10 + 41 + (31 * outputs.len()); // base + 1 input + N outputs
    let est_fee = fee_per_vb * est_vbytes;

    // Add change output
    let change_value = input_value.saturating_sub(total_output_value + est_fee as u64);
    let change_address = node.client.new_address()?;
    outputs.push(TxOut {
        value: Amount::from_sat(change_value),
        script_pubkey: change_address.script_pubkey(),
    });

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs,
    };

    Ok(tx)
}

pub fn initialize_funded_node(bitcoind_path: &str) -> anyhow::Result<(Node, Address)> {
    let tmpdir = tempdir()?;

    let mut conf = Conf::default();
    conf.args = vec!["-regtest", "-fallbackfee=0.0001"];
    conf.wallet = None;
    conf.tmpdir = Some(tmpdir.path().to_path_buf());

    let node = Node::with_conf(bitcoind_path, &conf)?;

    let wallet_name = "test_wallet";
    let _ = node.client.create_wallet(wallet_name);

    let address = node.client.new_address()?;
    println!("Generated Address: {:?}", &address);

    node.client.generate_to_address(101, &address)?;
    println!("Generated 101 blocks");

    Ok((node, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash = hash_pair(left, right);

        // Hash should be deterministic
        let hash2 = hash_pair(left, right);
        assert_eq!(hash, hash2);

        // Different inputs should produce different hashes
        let different = hash_pair(right, left);
        assert_ne!(hash, different);
    }

    #[test]
    fn test_compute_merkle_root() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let root = compute_merkle_root(leaves.clone());

        // Root should be deterministic
        let root2 = compute_merkle_root(leaves);
        assert_eq!(root, root2);

        // Empty leaves should produce zero root
        assert_eq!(compute_merkle_root(vec![]), [0u8; 32]);
    }

    #[test]
    fn test_pedersen_commit() {
        let params = PedersenParameters::default();
        let value = vec![100, 0];
        let blinding = generate_random_blinding();

        let commitment = pedersen_commit(value.clone(), blinding, &params);
        assert_eq!(commitment.len(), 32);

        // Same inputs should produce same commitment
        let commitment2 = pedersen_commit(value, blinding, &params);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_verify_wallet_proof() {
        let params = PedersenParameters::default();
        let old_root = [1u8; 32];
        let new_root = [2u8; 32];

        let proof = generate_state_proof(old_root, new_root, [3u8; 32], &params);

        assert!(verify_wallet_proof(&old_root, &new_root, &proof, &params));

        // Wrong roots should fail verification
        assert!(!verify_wallet_proof(&[4u8; 32], &new_root, &proof, &params));
    }

    #[test]
    fn test_generate_state_proof() {
        let params = PedersenParameters::default();

        // Define known inputs for the proof
        let old_commitment = [1u8; 32];
        let new_commitment = [2u8; 32];
        let merkle_root = [3u8; 32];

        // Generate the state proof
        let proof = generate_state_proof(old_commitment, new_commitment, merkle_root, &params);

        // Check that the proof has a valid length and expected public inputs
        assert_eq!(proof.pi.len(), 32);
        assert_eq!(
            proof.public_inputs,
            vec![old_commitment, new_commitment, merkle_root]
        );
        assert!(proof.timestamp > 0);

        // Verify that the wallet proof passes using the given parameters
        let is_valid = verify_wallet_proof(&old_commitment, &new_commitment, &proof, &params);
        assert!(is_valid, "The generated state proof should be valid.");
    }

    #[test]
    fn test_compute_channel_root_deterministic() {
        let channel_id = [1u8; 32];
        let commitment = [2u8; 32];
        let nonce = 21;

        let root1 = compute_channel_root(channel_id, commitment, nonce);
        let root2 = compute_channel_root(channel_id, commitment, nonce);

        // Identical inputs must yield identical roots
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_channel_root_different_channel_id() {
        let channel_id1 = [1u8; 32];
        let channel_id2 = [2u8; 32];
        let commitment = [3u8; 32];
        let nonce = 21;

        let root1 = compute_channel_root(channel_id1, commitment, nonce);
        let root2 = compute_channel_root(channel_id2, commitment, nonce);

        // Changing the channel_id should produce a different root
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_channel_root_different_commitment() {
        let channel_id = [1u8; 32];
        let commitment1 = [2u8; 32];
        let commitment2 = [3u8; 32];
        let nonce = 21;

        let root1 = compute_channel_root(channel_id, commitment1, nonce);
        let root2 = compute_channel_root(channel_id, commitment2, nonce);

        // Changing the commitment should produce a different root
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_channel_root_different_nonce() {
        let channel_id = [1u8; 32];
        let commitment = [2u8; 32];
        let nonce1 = 21;
        let nonce2 = 999;

        let root1 = compute_channel_root(channel_id, commitment, nonce1);
        let root2 = compute_channel_root(channel_id, commitment, nonce2);

        // Changing the nonce should produce a different root
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_channel_root_zero_values() {
        let channel_id = [0u8; 32];
        let commitment = [0u8; 32];
        let nonce = 0;

        // Call the function; if it doesn't panic, the test passes.
        let _ = compute_channel_root(channel_id, commitment, nonce);
    }

    #[test]
    fn test_hash_state_deterministic() {
        // A ChannelState with some simple values
        let state = ChannelState {
            balances: vec![100, 200],
            nonce: 21,
            metadata: vec![1, 2, 3],
            merkle_root: [0u8; 32],
            proof: None,
        };

        // Hash it twice; the outputs must match
        let hash1 = hash_state(&state).expect("hash_state should succeed");
        let hash2 = hash_state(&state).expect("hash_state should succeed");
        assert_eq!(hash1, hash2, "Identical state must produce identical hash");
    }

    #[test]
    fn test_hash_state_diff_balance() {
        // Start with a base state
        let mut state = ChannelState {
            balances: vec![100, 200],
            nonce: 21,
            metadata: vec![1, 2, 3],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let base_hash = hash_state(&state).unwrap();

        // Change one of the balances
        state.balances[1] = 300;
        let changed_hash = hash_state(&state).unwrap();

        assert_ne!(
            base_hash, changed_hash,
            "Changing balances should produce a different hash"
        );
    }

    #[test]
    fn test_hash_state_diff_nonce() {
        // Base state
        let mut state = ChannelState {
            balances: vec![100, 200],
            nonce: 21,
            metadata: vec![1, 2, 3],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let base_hash = hash_state(&state).unwrap();

        // Change the nonce
        state.nonce = 999;
        let changed_hash = hash_state(&state).unwrap();

        assert_ne!(
            base_hash, changed_hash,
            "Changing the nonce should produce a different hash"
        );
    }

    #[test]
    fn test_hash_state_diff_metadata() {
        // Base state
        let mut state = ChannelState {
            balances: vec![100, 200],
            nonce: 21,
            metadata: vec![1, 2, 3],
            merkle_root: [0u8; 32],
            proof: None,
        };
        let base_hash = hash_state(&state).unwrap();

        // Change metadata
        state.metadata = vec![9, 9, 9, 9];
        let changed_hash = hash_state(&state).unwrap();

        assert_ne!(
            base_hash, changed_hash,
            "Changing metadata should produce a different hash"
        );
    }

    #[test]
    fn test_hash_state_zero_values() {
        // All-zero balances, nonce, and empty metadata
        let state = ChannelState {
            balances: vec![0, 0],
            nonce: 0,
            metadata: vec![],
            merkle_root: [0u8; 32],
            proof: None,
        };

        // Just ensure it doesn't panic and yields some hash
        let _ = hash_state(&state).expect("hash_state should not fail");
    }
}
