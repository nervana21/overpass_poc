use anyhow::Result;
use rand::Rng;

use overpass_core::zkp::tree::SparseMerkleTree;
use overpass_core::zkp::state_transition::StateTransitionCircuit;
use overpass_core::zkp::recursion::StateTransitionCircuitWithRecursion;
use overpass_core::zkp::bitcoin_ephemeral_state::BitcoinClient;
use bitcoin::{
    absolute::LockTime,
    TxIn, TxOut, Witness,
    blockdata::opcodes::all::OP_RETURN,
    blockdata::transaction::Transaction,
    consensus::encode,
    Sequence, Script,
};
use bitcoin::blockdata::script::Builder;

#[derive(Clone)]
struct ChannelState {
    balances: Vec<u64>,
    nonce: u64,
    metadata: Vec<u8>,
}

fn hash_state(state: &ChannelState) -> Result<[u8; 32]> {
    use bitcoin::hashes::{sha256d, Hash, HashEngine};
    let mut engine = sha256d::Hash::engine();
    for &b in &state.balances {
        engine.input(&b.to_le_bytes());
    }
    engine.input(&state.nonce.to_le_bytes());
    engine.input(&state.metadata);
    let hash = sha256d::Hash::from_engine(engine).to_byte_array();
    Ok(hash)
}

fn build_op_return_transaction(client: &BitcoinClient, data: [u8; 32]) -> Result<String> {
    let amount = 100_000;
    let (outpoint, _script_pubkey) = client.get_spendable_utxo(amount)?;

    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&data)
        .into_script();

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: Script::builder()
            .push_slice(&[0x00; 32])
            .into_script(),
        sequence: Sequence(0xffffffff),
        witness: Witness::default(),
    };

    let op_return_value = 0;
    let return_address = client.get_new_address()?;
    let change_value = amount - 1000;
    let tx_out_opreturn = TxOut {
        value: op_return_value,
        script_pubkey: op_return_script,
    };
    let tx_out_change = TxOut {
        value: change_value,
        script_pubkey: return_address.script_pubkey(),
    };

    let raw_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out_opreturn, tx_out_change],
    };

    let hex_str = hex::encode(encode::serialize(&raw_tx));
    let signed_hex = client.sign_raw_transaction(&hex_str)?;
    Ok(signed_hex)
}
#[test]
fn test_e2e_integration() -> Result<()> {
    let client = BitcoinClient::new(
        "http://127.0.0.1:18443",
        "rpcuser",
        "rpcpassword"
    )?;

    // Fund the wallet
    let addr = client.get_new_address()?;
    client.generate_blocks(101, &addr.to_string())?;
    let balance = client.get_balance()?;
    assert!(balance > 0, "Should have nonzero balance");

    let initial_state = ChannelState {
        balances: vec![100, 50],
        nonce: 0,
        metadata: vec![],
    };
    let next_state = ChannelState {
        balances: vec![97, 53],
        nonce: 1,
        metadata: vec![],
    };

    let initial_state_bytes = hash_state(&initial_state)?;
    let next_state_bytes = hash_state(&next_state)?;
    let transition_data = hash_state(&initial_state)?; // Match circuit expectations

    let circuit = StateTransitionCircuit::new();
    let proof = circuit.generate_proof(initial_state_bytes, next_state_bytes, transition_data)?;
    assert!(StateTransitionCircuit::verify_proof(&circuit, proof.clone())?);

    let channel_key = [9u8; 32];
    let mut smt = SparseMerkleTree::new(32);
    smt.update(channel_key, initial_state_bytes)?;
    smt.update(channel_key, next_state_bytes)?;

    let next_proof = smt.generate_proof(channel_key, next_state_bytes)?;
    assert!(SparseMerkleTree::verify_proof(smt.root, &next_proof, channel_key)?);

    let raw_tx_hex = build_op_return_transaction(&client, smt.root)?;
    let txid = client.send_raw_transaction_hex(&raw_tx_hex)?;
    client.generate_blocks(1, &client.get_new_address()?.to_string())?;
    println!("Anchored SMT root in TX {}", txid);

    Ok(())
}