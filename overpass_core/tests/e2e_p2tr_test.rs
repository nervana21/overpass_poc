// overpass_core/tests/e2e_integration_test.rs

use anyhow::{anyhow, Ok};
use miniscript::bitcoin::{consensus::deserialize, consensus::encode::serialize_hex, Transaction};

use overpass_core::zkp::{
    channel::ChannelState,
    helpers::{build_p2tr_transaction, compute_channel_root, hash_state, initialize_funded_node},
    state_transition::apply_transition,
    tree::MerkleTree,
};

#[test]
fn test_e2e_pt2r() -> anyhow::Result<()> {
    println!("\n=== Starting E2E P2TR Test ===");
    let (node, address) = initialize_funded_node("/Users/bitnode/bitcoin/build/src/bitcoind")?;

    let balance = node.client.get_balance()?.balance()?.to_sat();
    println!("Wallet balance: {}", balance);
    assert!(balance > 0, "Wallet balance should be greater than zero");

    println!("\n=== Creating Channel States ===");
    let mut initial_state = ChannelState {
        balances: vec![balance, 0],
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

    println!("\n=== Generating and Verifying Merkle Proof ===");
    let merkle_proof = smt
        .get_proof(&next_state_bytes)
        .ok_or(anyhow!("Failed to generate Merkle proof"))?;
    println!("Merkle proof generated successfully");

    println!("Merkle proof verification started");
    println!("Root: {:?}", smt.root);

    if !smt.verify_proof(&next_state_bytes, merkle_proof.as_slice(), &smt.root) {
        return Err(anyhow!("Merkle proof verification failed"));
    }
    println!("Merkle proof verified successfully");

    // Build and send P2TR transaction
    println!("\n=== Building and Sending P2TR Transaction ===");

    let tx = build_p2tr_transaction(&node, &address)?;

    let tx_hex = serialize_hex(&tx);
    let signed: serde_json::Value = node
        .client
        .call("signrawtransactionwithwallet", &[tx_hex.clone().into()])?;

    let signed_hex = signed["hex"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing hex from signed transaction"))?;

    // Convert the signed hex back into a Transaction
    let tx: Transaction = deserialize(&hex::decode(signed_hex)?)?;

    // Send the signed transaction
    let _ = node.client.send_raw_transaction(&tx)?;
    println!("Broadcasted transaction: {}", signed_hex);

    node.client.generate_to_address(1, &address)?;
    println!("\nBlock generated to confirm transaction");

    println!("=== Test Completed Successfully ===\n");

    Ok(())
}
