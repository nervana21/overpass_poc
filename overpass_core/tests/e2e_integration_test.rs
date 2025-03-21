// overpass_core/tests/e2e_integration_test.rs

use anyhow::{anyhow, Context, Result}; // Ensure Context is imported
use bitcoin::Network;
use overpass_core::zkp::helpers::hash_state;
use overpass_core::zkp::{
    bitcoin_ephemeral_state::BitcoinClient, channel::ChannelState, tree::MerkleTree,
};

/// Applies transition data to the initial state to produce the next state.
fn apply_transition(
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
        .ok_or_else(|| anyhow!("Missing balance 0"))?
        .to_owned() as i64;
    let initial_balance_1 = initial_state
        .balances
        .get(1)
        .ok_or_else(|| anyhow!("Missing balance 1"))?
        .to_owned() as i64;

    let new_balance_0 = initial_balance_0
        .checked_add(delta_balance_0 as i64)
        .ok_or_else(|| anyhow!("Balance overflow for balance 0"))?;
    let new_balance_1 = initial_balance_1
        .checked_add(delta_balance_1 as i64)
        .ok_or_else(|| anyhow!("Balance overflow for balance 1"))?;

    if new_balance_0 < 0 || new_balance_1 < 0 {
        anyhow::bail!("Negative balance is not allowed");
    }

    // nonce increases by 1
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

    new_state.merkle_root = hash_state(&new_state)?;

    Ok(new_state)
}

#[test]
fn test_e2e_integration() -> Result<()> {
    println!("\n=== Starting E2E Integration Test ===\n");

    // Initialize Bitcoin client
    let mut client = BitcoinClient::new(
        "http://127.0.0.1:18443",
        "rpcuser",
        "rpcpassword",
        Network::Regtest,
    )?;

    println!("Bitcoin client initialized");

    // Fund the wallet
    let addr = client.get_new_address()?;
    println!("Generated address: {}", addr);

    client.generate_blocks(101, &addr.to_string())?;
    println!("Generated 101 blocks");

    let balance = client.get_balance()?;
    println!("Wallet balance: {}", balance);
    assert!(balance > 0, "Wallet balance should be greater than zero");

    // Define channel states
    println!("\n=== Creating Channel States ===\n");
    let initial_state = ChannelState {
        balances: vec![100, 50],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };
    println!("Initial state created: {:?}", initial_state);

    // Generate transition data
    println!("\n=== Generating Transition Data ===\n");
    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-3i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&3i32.to_le_bytes());
    transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());

    println!("Transition data: {:?}", transition_data);
    println!(
        "Delta balance 0: {}",
        i32::from_le_bytes(transition_data[0..4].try_into().unwrap())
    );
    println!(
        "Delta balance 1: {}",
        i32::from_le_bytes(transition_data[4..8].try_into().unwrap())
    );
    println!(
        "Nonce: {}",
        i32::from_le_bytes(transition_data[8..12].try_into().unwrap())
    );

    // Apply transition to get the next state
    println!("\n=== Applying Transition ===");
    let next_state = apply_transition(&initial_state, &transition_data)?;
    println!("Next state created: {:?}", next_state);

    // Compute state hashes
    println!("\n=== Computing State Hashes ===");
    let initial_state_bytes = hash_state(&initial_state)?;
    println!("Initial state hash bytes: {:?}", initial_state_bytes);

    let next_state_bytes = hash_state(&next_state)?;
    println!("Next state hash bytes: {:?}", next_state_bytes);

    // Initialize Merkle tree and update with states
    println!("\n=== Updating Merkle Tree ===");
    let mut smt = MerkleTree::new();

    smt.insert(initial_state_bytes)?;
    println!("Initial state added to Merkle tree");

    smt.insert(next_state_bytes)?;
    println!("Next state added to Merkle tree");

    // Generate and verify Merkle proof for the next state
    println!("\n=== Generating and Verifying Merkle Proof ===");
    let merkle_proof = smt
        .get_proof(&next_state_bytes)
        .ok_or(anyhow!("Failed to generate Merkle proof"))?;
    println!("Merkle proof generated successfully");

    println!("Merkle proof verification started");
    println!("Root: {:?}", smt.root);

    if !smt.verify_proof(&next_state_bytes, &merkle_proof, &smt.root) {
        return Err(anyhow!("Merkle proof verification failed"));
    }
    println!("Merkle proof verified successfully");

    // Build and send OP_RETURN transaction
    println!("\n=== Building and Sending OP_RETURN Transaction ===");
    let raw_tx_hex = build_op_return_transaction(&mut client, next_state_bytes)?;
    let txid = client.send_raw_transaction_hex(&raw_tx_hex)?;
    println!("Transaction sent with ID: {}", txid);

    client.generate_blocks(1, &addr.to_string())?;
    println!("Block generated to confirm transaction");

    println!("\n=== Test Completed Successfully ===\n");
    Ok(())
}

fn build_op_return_transaction(client: &mut BitcoinClient, data: [u8; 32]) -> Result<String> {
    let amount = 100_000;
    let (outpoint, utxo) = client.get_spendable_utxo(amount)?;
    println!("UTXO fetched");
    println!("UTXO: {:?}", utxo);
    println!("Outpoint: {}", outpoint);

    println!("Amount: {}", amount);
    println!("Data: {:?}", data);

    let op_return_script = bitcoin::blockdata::script::Builder::new()
        .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
        .push_slice(&data)
        .into_script();

    println!("OP_RETURN script built");

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
        value: utxo.value - 1_000,
        script_pubkey: utxo.script_pubkey,
    };

    let tx = bitcoin::Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out_opreturn, tx_out_change],
    };

    println!("Transaction built");

    let raw_tx_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
    println!("Transaction serialized");

    let signed_tx_hex = client
        .sign_raw_transaction(&raw_tx_hex)
        .map_err(|e| anyhow!("Transaction signing failed: {}", e))?;

    println!("Transaction signed");
    Ok(signed_tx_hex)
}

#[test]
fn test_valid_transition() -> Result<()> {
    let initial_state = ChannelState {
        balances: vec![100, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-10i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&(10i32).to_le_bytes());
    transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());

    let result = apply_transition(&initial_state, &transition_data)?;
    assert_eq!(result.balances[0], 90);
    assert_eq!(result.balances[1], 10);
    assert_eq!(result.nonce, 1);

    Ok(())
}

#[test]
fn test_insufficient_funds() -> Result<()> {
    let initial_state = ChannelState {
        balances: vec![10, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-20i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&(20i32).to_le_bytes());

    let result = apply_transition(&initial_state, &transition_data);
    assert!(result.is_err());
    assert_eq!(
        format!("{}", result.unwrap_err()),
        "Negative balance is not allowed"
    );

    Ok(())
}

#[test]
fn test_nonce_overflow() -> Result<()> {
    let initial_state = ChannelState {
        balances: vec![100, 0],
        nonce: u64::MAX,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };

    let mut transition_data = [0u8; 32];
    transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());

    let result = apply_transition(&initial_state, &transition_data);
    assert!(result.is_err());
    assert_eq!(format!("{}", result.unwrap_err()), "Nonce overflow");
    Ok(())
}

#[test]
fn test_negative_balance() -> Result<()> {
    let initial_state = ChannelState {
        balances: vec![10, 10],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-20i32).to_le_bytes());

    let result = apply_transition(&initial_state, &transition_data);
    assert!(result.is_err());
    assert_eq!(
        format!("{}", result.unwrap_err()),
        "Negative balance is not allowed"
    );

    Ok(())
}
