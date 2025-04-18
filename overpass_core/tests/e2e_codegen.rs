// overpass_core/tests/e2e_codegen.rs

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bitcoin_rpc_codegen::{Client, RpcApi};
use miniscript::bitcoin::{Amount, Network};
use overpass_core::zkp::channel::ChannelState;
use overpass_core::zkp::helpers::{build_codegen_transaction, compute_channel_root, hash_state};
use overpass_core::zkp::state_transition::apply_transition;
use overpass_core::zkp::tree::MerkleTree;
use serde_json::json;

static WALLET_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn e2e_codegen_test() -> Result<()> {
    // pick a free RPC port and start bitcoind
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let rpc_port = listener.local_addr()?.port();
    drop(listener);

    let rpc_user = "rpcuser";
    let rpc_pass = "rpcpassword";
    let base_rpc_url = format!("http://127.0.0.1:{}", rpc_port);

    let datadir = PathBuf::from("target/bitcoind-test");
    let _ = fs::remove_dir_all(&datadir);
    fs::create_dir_all(&datadir)?;

    let mut child: Child = Command::new("bitcoind")
        .arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcuser={}", rpc_user))
        .arg(format!("-rpcpassword={}", rpc_pass))
        .arg(format!("-rpcport={}", rpc_port))
        .arg("-listen=0")
        .arg("-fallbackfee=0.0002")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(15) {
            return Err(anyhow!("bitcoind RPC never came up"));
        }
        if let Ok(c) = Client::new_auto(&base_rpc_url, rpc_user, rpc_pass) {
            if c.get_network_info().is_ok() {
                break;
            }
        }
        sleep(Duration::from_millis(200));
    }

    // test begins
    println!("\n=== Starting E2E Codegen Test ===");

    let node_client = Client::new_auto(&base_rpc_url, rpc_user, rpc_pass)?;
    let suffix = WALLET_COUNTER.fetch_add(1, Ordering::SeqCst);
    let wallet_name = format!("test_wallet_e2e_{}", suffix);

    // create a fresh wallet
    let wallet_dir = datadir.join("regtest").join("wallets").join(&wallet_name);
    if wallet_dir.exists() {
        fs::remove_dir_all(&wallet_dir)?;
    }
    node_client.create_wallet(&wallet_name, None, None, None, None)?;

    let wallet_rpc_url = format!("{}/wallet/{}", base_rpc_url, wallet_name);
    let client = Client::new_auto(&wallet_rpc_url, rpc_user, rpc_pass)?;

    let network_info = client.get_network_info()?;
    let network = if network_info.network_active {
        client.get_blockchain_info()?.chain
    } else {
        Network::Regtest
    };

    // mine 110 blocks, check balance
    let addr = client.get_new_address(None, None)?.require_network(network)?;
    let addr_str = addr.to_string();
    client.generate_to_address(101, &addr)?;
    println!("Generated 101 blocks to {}", addr_str);

    let balance_sats = client.get_balance(None, None)?.to_sat();
    println!("Wallet balance: {}", balance_sats);
    assert!(balance_sats > 0);

    // fund a fresh address with 5000 sats and confirm
    client.call_json("settxfee", &[json!(0.00001)])?;
    let fund_addr = client.get_new_address(None, None)?.require_network(network)?;
    let fund_addr_str = fund_addr.to_string();
    client.send_to_address(
        &fund_addr,
        Amount::from_sat(5000),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    client.generate_to_address(1, &addr)?;
    // println!("Sent 5000 sats to {} and mined 1 block", fund_addr_str);

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

    client.generate_to_address(1, &addr)?;
    println!("Block generated to confirm transaction");

    // tear down
    let _ = node_client.stop();
    let _ = child.wait();

    println!("\n=== Test Completed Successfully ===");
    Ok(())
}
