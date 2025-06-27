use anyhow::{anyhow, Ok, Result};
use midas::*;
use overpass_core::zkp::channel::ChannelState;
use overpass_core::zkp::helpers::{compute_channel_root, hash_state};
use overpass_core::zkp::state_transition::apply_transition;
use overpass_core::zkp::tree::MerkleTree;
use serde_json::json;

#[tokio::test]
async fn test_midas() -> Result<()> {
    println!("\n=== Starting E2E Midas Test ===");

    println!("\n=== Creating Channel States ===");
    let initial_balance = 100u64;
    let mut initial_state = ChannelState {
        balances: [initial_balance, 0],
        nonce: 0,
        metadata: vec![],
        merkle_root: [0u8; 32],
        proof: None,
    };
    let channel_id = [1u8; 32];

    // Compute and update the initial Merkle root
    initial_state.merkle_root =
        compute_channel_root(channel_id, hash_state(&initial_state)?, initial_state.nonce);

    println!("Initial state created: {:?}", initial_state);

    println!("\n=== Generating Transition Data ===");
    let mut transition_data = [0u8; 32];
    transition_data[0..4].copy_from_slice(&(-3i32).to_le_bytes());
    transition_data[4..8].copy_from_slice(&3i32.to_le_bytes());

    println!("Transition data: {:?}", transition_data);
    println!("Delta balance 0: {}", i32::from_le_bytes(transition_data[0..4].try_into().unwrap()));
    println!("Delta balance 1: {}", i32::from_le_bytes(transition_data[4..8].try_into().unwrap()));

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

    println!("\n=== Generating and Verifying Merkle Proof ===");
    let merkle_proof =
        smt.get_proof(&next_state_bytes).ok_or(anyhow!("Failed to generate Merkle proof"))?;
    println!("Merkle proof generated successfully");

    println!("Merkle proof verification started");
    println!("Root: {:?}", smt.root);

    if !smt.verify_proof(&next_state_bytes, merkle_proof.as_slice(), &smt.root) {
        return Err(anyhow!("Merkle proof verification failed"));
    }
    println!("Merkle proof verified successfully");

    println!("\n=== Building and Sending P2TR Midas Transaction ===");

    // Start with a fresh test-node client
    let mut client = BitcoinTestClient::new().await?;

    // Ensure a wallet exists before using wallet functionality
    let _wallet_name = client.ensure_default_wallet("test_wallet").await?;

    // Check initial chain state
    let info = client.getblockchaininfo().await?;
    println!("Initial blockchain state:\n{:#?}\n", info);

    // Batch RPC operations for network info
    let results = client
        .batch()
        .getblockcount() // u64
        .getnetworkinfo() // NetworkInfo
        .getdifficulty() // f64
        .getconnectioncount() // u64
        .execute()
        .await?;

    // Extract each field (they're Option<_> since our static BatchResults has every RPC)
    let block_count = results.getblockcount.expect("getblockcount was in the batch");
    let net_info = results.getnetworkinfo.expect("getnetworkinfo was in the batch");
    let difficulty = results.getdifficulty.expect("getdifficulty was in the batch");
    let conn_count = results.getconnectioncount.expect("getconnectioncount was in the batch");

    println!("block_count: {:#?}", block_count);
    println!("network_info: {:#?}", net_info);
    println!("difficulty: {:#?}", difficulty);
    println!("connection_count: {:#?}", conn_count);

    // Generate a P2TR address
    let address_resp = client.getnewaddress("".to_string(), "bech32m".to_string()).await?;
    let address = address_resp.0;
    println!("Generated P2TR address: {}\n", address);

    // Mine 101 blocks to our new address so the coinbase UTXOs actually belong to it
    client.generatetoaddress(101, address.clone(), 2000).await?;

    // Check the balance of the new address
    let balance_amount = client.getreceivedbyaddress(address.clone(), 0, false).await?.0;
    println!("Initial wallet balance: {}\n", balance_amount);

    // Create & fund a PSBT
    let amount = 5_500u64;
    println!("Preparing to send: {} satoshis\n", amount);

    let psbt_options = json!({
        "changePosition": 1,
        "feeRate":     0.0001,        // BTC per vbyte
        "includeWatching": true,
        "lockUnspents":    true,
        "replaceable":     false
    });

    let outputs = vec![json!({ address.clone(): amount as f64 / 100_000_000.0 })];

    let psbt_obj = client
        .walletcreatefundedpsbt(
            vec![],       // auto-select UTXOs
            outputs,      // outputs in BTC
            0,            // locktime
            psbt_options, // now correctly recognized
            false,        // bip32derivs
        )
        .await?;
    println!("Created PSBT: {}\n", psbt_obj.psbt);

    // Sign the PSBT
    let signed_obj = client
        .walletprocesspsbt(
            psbt_obj.psbt.clone(),
            true,              // sign
            "ALL".to_string(), // sighash_type
            true,              // bip32derivs
            true,              // finalize
        )
        .await?;
    println!("Signed PSBT: {}\n", signed_obj.psbt);

    // Finalize the PSBT
    let finalized_obj = client.finalizepsbt(signed_obj.psbt, true).await?;
    let hex = finalized_obj.hex.ok_or_else(|| anyhow!("Failed to get hex from finalized PSBT"))?;
    println!("Finalized transaction hex: {}\n", hex);

    // Broadcast the transaction
    let resp = client.sendrawtransaction(hex, 0.0, 0.0).await?;
    let txid: String = resp.0;
    println!("Broadcasted transaction! TXID: {}\n", txid);

    // Mine one more block to confirm (also to our test address)
    client.generatetoaddress(1, address.clone(), 2000).await?;
    println!("Block mined to confirm transaction");

    // Check final balance on the same address
    let final_balance = client.getreceivedbyaddress(address.clone(), 0, false).await?.0;
    println!("Balance: {:.8} BTC", final_balance);

    println!("=== Test Completed Successfully ===\n");
    Ok(())
}
