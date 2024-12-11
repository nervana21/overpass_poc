use anyhow::{anyhow, Context, Result};
use bitcoin::Network;
use plonky2_field::types::{Field, PrimeField64};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::Hasher;
use overpass_core::zkp::{
    bitcoin_ephemeral_state::BitcoinClient,
    tree::MerkleTree,
    channel::ChannelState,
};

/// Converts a ChannelState into a 32-byte hash using PoseidonHash.
fn hash_state(state: &ChannelState) -> Result<[u8; 32]> {
    use plonky2::hash::poseidon::PoseidonHash;

    // Convert ChannelState fields to field elements
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

/// Applies transition data to the initial state to produce the next state.
fn apply_transition(initial_state: &ChannelState, transition_data: &[u8; 32]) -> Result<ChannelState> {
    // Extract delta_balance_0, delta_balance_1, delta_nonce from transition_data
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
    let delta_nonce = i32::from_le_bytes(
        transition_data[8..12]
            .try_into()
            .context("Failed to parse delta_nonce")?,
    );

    // Apply deltas to balances and nonce
    let new_balance_0 = initial_state
        .balances
        .get(0)
        .ok_or_else(|| anyhow!("Missing balance 0"))?
        .checked_add_signed(delta_balance_0 as i64)
        .ok_or_else(|| anyhow!("Balance overflow for balance 0"))?;
    let new_balance_1 = initial_state
        .balances
        .get(1)
        .ok_or_else(|| anyhow!("Missing balance 1"))?
        .checked_add_signed(delta_balance_1 as i64)
        .ok_or_else(|| anyhow!("Balance overflow for balance 1"))?;
    let new_nonce = initial_state
        .nonce
        .checked_add(delta_nonce as u64)
        .ok_or_else(|| anyhow!("Nonce overflow"))?;

    // Create the new state
    let mut new_state = ChannelState {
        balances: vec![new_balance_0 as u64, new_balance_1 as u64],
        nonce: new_nonce,
        metadata: initial_state.metadata.clone(),
        merkle_root: [0u8; 32], // Placeholder, will be updated after hashing
        proof: None,
    };

    // Compute the new merkle_root based on the updated state
    new_state.merkle_root = hash_state(&new_state)?;

    Ok(new_state)
}

/// Builds an OP_RETURN transaction embedding the provided data.
fn build_op_return_transaction(client: &mut BitcoinClient, data: [u8; 32]) -> Result<String> {
    let amount = 100_000;
    let (outpoint, utxo) = client.get_spendable_utxo(amount)?;
    let op_return_script = bitcoin::blockdata::script::Builder::new()
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
        .push_slice(&data)
        .into_script();

    let tx_in = bitcoin::TxIn {
        previous_output: outpoint,
        script_sig: bitcoin::ScriptBuf::default(),
        sequence: bitcoin::Sequence(0xffffffff),
        witness: bitcoin::Witness::default(),
    };

    let tx_out_opreturn = bitcoin::TxOut {
        value: 0,
        script_pubkey: op_return_script,
    };

    let tx_out_change = bitcoin::TxOut {
        value: amount - 1_000,
        script_pubkey: utxo.script_pubkey,
    };

    let tx = bitcoin::Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out_opreturn, tx_out_change],
    };

    let raw_tx_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
    let signed_tx_hex = client
        .sign_raw_transaction(&raw_tx_hex)
        .map_err(|e| anyhow!("Transaction signing failed: {}", e))?;

    Ok(signed_tx_hex)
}

#[test]
fn test_e2e_integration() -> Result<()> {
    let mut client = BitcoinClient::new(
        "http://127.0.0.1:18443",
        "rpcuser",
        "rpcpassword",
        Network::Regtest,
    )?;

    let addr = client.get_new_address()?;
    client.generate_blocks(101, &addr.to_string())?;
    let balance = client.get_balance()?;
    assert!(balance > 0, "Wallet balance should be greater than zero");

    let initial_state = ChannelState {
        balances: vec![100, 50],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-3i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&3i32.to_le_bytes());
    transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());

    let next_state = apply_transition(&initial_state, &transition_data)?;
    let initial_state_bytes = hash_state(&initial_state)?;
    let next_state_bytes = hash_state(&next_state)?;

    let mut smt = MerkleTree::new();
    smt.insert(initial_state_bytes)?;
    smt.insert(next_state_bytes)?;

    let merkle_proof = smt
        .get_proof(&next_state_bytes)
        .ok_or(anyhow!("Failed to generate Merkle proof"))?;
    if !smt.verify_proof(&next_state_bytes, &merkle_proof, &smt.root) {
        return Err(anyhow!("Merkle proof verification failed"));
    }

    let raw_tx_hex = build_op_return_transaction(&mut client, next_state_bytes)?;
    let txid = client.send_raw_transaction_hex(&raw_tx_hex)?;
    client.generate_blocks(1, &addr.to_string())?;

    Ok(())
}