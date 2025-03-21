// overpass_core/tests/e2e_integration_test.rs

use anyhow::{anyhow, Result};
use bitcoin::Network;
use overpass_core::zkp::helpers::{build_op_return_transaction, compute_channel_root, hash_state};
use overpass_core::zkp::state_transition::apply_transition;
use overpass_core::zkp::{
    bitcoin_ephemeral_state::BitcoinClient, channel::ChannelState, tree::MerkleTree,
};

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
        balances: vec![balance as u64, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };
    let channel_id = [1u8; 32];

    let computed_merkle_root =
        compute_channel_root(channel_id, hash_state(&initial_state)?, initial_state.nonce);

    let initial_state = ChannelState {
        balances: vec![balance as u64, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: computed_merkle_root,
        proof: None,
    };

    println!("Initial state created: {:?}", initial_state);
    // Generate transition data
    println!("\n=== Generating Transition Data ===\n");
    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-3i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&3i32.to_le_bytes());

    println!("Transition data: {:?}", transition_data);
    println!(
        "Delta balance 0: {}",
        i32::from_le_bytes(transition_data[0..4].try_into().unwrap())
    );
    println!(
        "Delta balance 1: {}",
        i32::from_le_bytes(transition_data[4..8].try_into().unwrap())
    );

    // Apply transition to get the next state
    println!("\n=== Applying Transition ===");
    let next_state = apply_transition(channel_id, &initial_state, &transition_data)?;
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

#[test]
fn test_valid_transition() -> Result<()> {
    let initial_state = ChannelState {
        balances: vec![100, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };

    let channel_id = [1u8; 32];

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-10i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&(10i32).to_le_bytes());

    let result = apply_transition(channel_id, &initial_state, &transition_data)?;
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

    let channel_id = [1u8; 32];

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-20i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&(20i32).to_le_bytes());

    let result = apply_transition(channel_id, &initial_state, &transition_data);
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

    let channel_id = [1u8; 32];

    let mut transition_data = [0u8; 32];
    transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());

    let result = apply_transition(channel_id, &initial_state, &transition_data);
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

    let channel_id = [1u8; 32];

    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-20i32).to_le_bytes());

    let result = apply_transition(channel_id, &initial_state, &transition_data);
    assert!(result.is_err());
    assert_eq!(
        format!("{}", result.unwrap_err()),
        "Negative balance is not allowed"
    );

    Ok(())
}
