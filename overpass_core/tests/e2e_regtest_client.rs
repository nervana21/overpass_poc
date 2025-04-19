// overpass_core/tests/e2e_regtest_client.rs

use anyhow::{anyhow, Result};
use bitcoin_rpc_codegen::{RegtestClient, RpcApi};
use miniscript::bitcoin::{Amount, Network};
use overpass_core::zkp::channel::ChannelState;
use overpass_core::zkp::helpers::{build_codegen_transaction, compute_channel_root, hash_state};
use overpass_core::zkp::state_transition::apply_transition;
use overpass_core::zkp::tree::MerkleTree;
use serde_json::json;

/// Replace these with your actual URL/creds when running locally
const RPC_URL: &str = "http://127.0.0.1:18443";
const RPC_USER: &str = "rpcuser";
const RPC_PASS: &str = "rpcpassword";
const WALLET: &str = "test";

#[test]
fn e2e_regtest_client_test() -> Result<()> {
    println!("\n=== Starting E2E Regtest Client Codegen Test ===");

    // Spawn bitcoind (if needed), wait for RPC, and load/create wallet
    let mut rt = RegtestClient::new_auto(RPC_URL, RPC_USER, RPC_PASS, WALLET)?;
    let client = &rt.client;

    let blockchain_info = client.get_blockchain_info()?;
    assert_eq!(blockchain_info.chain, Network::Regtest);

    let fund_addr = client.get_new_address(None, None)?.require_network(Network::Regtest)?;
    let fund_addr_str = fund_addr.to_string();
    client.generate_to_address(101, &fund_addr)?;
    println!("Generated 101 blocks to {}", fund_addr_str);

    // --- Check balance ---
    let balance_sats = client.get_balance(None, None)?.to_sat();
    println!("Wallet balance: {}", balance_sats);
    assert!(balance_sats > 0);

    // fund a fresh address with 5000 sats and confirm
    client.call_json("settxfee", &[json!(0.00001)])?;
    let fund_addr = client.get_new_address(None, None)?.require_network(Network::Regtest)?;
    let fund_addr_str = fund_addr.to_string();
    client.send_to_address(
        &fund_addr,
        Amount::from_sat(100_000),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    client.generate_to_address(1, &fund_addr)?;
    println!("Sent 100000 sats to {} and mined 1 block", fund_addr_str);

    let utxos = client.list_unspent(Some(1), None, Some(&[&fund_addr]), None, None)?;
    assert!(!utxos.is_empty(), "No UTXO at funding address");

    let utxos = client.list_unspent(Some(1), None, Some(&[&fund_addr]), None, None)?;
    assert!(!utxos.is_empty(), "No UTXO at funding address");

    // channel-state, transition, Merkle proof
    println!("\n=== Creating Channel States ===");
    let mut st0 = ChannelState {
        balances: [balance_sats, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0; 32],
        proof: None,
    };
    st0.merkle_root = compute_channel_root([1; 32], hash_state(&st0)?, st0.nonce);
    println!("Initial state created: {:?}", st0);

    println!("\n=== Generating Transition Data ===");
    let mut data = [0u8; 32];
    data[0..4].copy_from_slice(&(-3i32).to_le_bytes());
    data[4..8].copy_from_slice(&3i32.to_le_bytes());
    println!("Transition data: {:?}", data);
    println!("Delta balance 0: {}", i32::from_le_bytes(data[0..4].try_into().unwrap()));
    println!("Delta balance 1: {}", i32::from_le_bytes(data[4..8].try_into().unwrap()));

    println!("\n=== Applying Transition ===");
    let st1 = apply_transition([1; 32], &st0, &data)?;
    println!("Next state created: {:?}", st1);

    println!("\n=== Computing State Hashes ===");
    let h0 = hash_state(&st0)?;
    let h1 = hash_state(&st1)?;
    println!("Initial state hash bytes: {:?}", h0);
    println!("Next state hash bytes: {:?}", h1);

    println!("\n=== Updating Merkle Tree ===");
    let mut smt = MerkleTree::new();
    smt.insert(h0)?;
    println!("Initial state added to Merkle tree");
    smt.insert(h1)?;
    println!("Next state added to Merkle tree");

    println!("\n=== Generating and Verifying Merkle Proof ===");
    let proof = smt.get_proof(&h1).ok_or(anyhow!("Failed to generate Merkle proof"))?;
    println!("Merkle proof generated successfully");
    println!("Merkle proof verification started");
    println!("Root: {:?}", smt.root);
    assert!(smt.verify_proof(&h1, &proof, &smt.root), "Merkle proof verification failed");
    println!("Merkle proof verified successfully");

    // build, sign & broadcast the P2TR tx
    println!("\n=== Building and Sending Codegen P2TR Transaction ===");
    let tx = build_codegen_transaction(&client, &fund_addr_str, data)?;

    let signed = client.sign_raw_transaction_with_wallet(&tx, None, None)?;
    println!("Raw P2TR transaction hex: {}", hex::encode(&signed.hex));

    let txid = client.send_raw_transaction(&signed.hex)?;
    println!("Broadcasted transaction: {}", txid);

    client.generate_to_address(1, &fund_addr)?;
    println!("Block generated to confirm transaction");

    // --- Tear down regtest node ---
    rt.teardown()?;

    println!("\n=== E2E Regtest Client Test Completed Successfully ===");
    Ok(())
}
