use plonky2::plonk::config::GenericHashOut;
use anyhow::Result;
use bitcoin::blockdata::script::ScriptBuf;
use overpass_core::zkp::tree::SparseMerkleTree;
use overpass_core::zkp::state_transition::StateTransitionCircuit;
use overpass_core::zkp::bitcoin_ephemeral_state::BitcoinClient;
use bitcoin::{
    absolute::LockTime,
    TxIn, TxOut, Witness,
    blockdata::opcodes::all::OP_RETURN,
    blockdata::transaction::Transaction,
    consensus::encode,
    Sequence
};
use bitcoin::blockdata::script::Builder;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::HashOut;

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
    let (outpoint, script_pubkey) = client.get_spendable_utxo(amount)?;

    // Create OP_RETURN script
    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&data)
        .into_script();

    // Create input without segwit
    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence(0xffffffff),
        witness: Witness::default(),
    };

    // Create outputs
    let op_return_value = 0;
    let _return_address = client.get_new_address()?;
    let change_value = amount - 1000; // Fee
    
    let tx_out_opreturn = TxOut {
        value: op_return_value,
        script_pubkey: op_return_script,
    };
    let tx_out_change = TxOut {
        value: change_value,
        script_pubkey: script_pubkey.into(),
    };

    // Build transaction
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out_opreturn, tx_out_change],
    };

    // Serialize and sign
    let raw_tx_hex = hex::encode(encode::serialize(&tx));
    let signed_hex = client.sign_raw_transaction(&raw_tx_hex)?;
    
    Ok(signed_hex)
}#[test]
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

    // Hash states
    let initial_state_bytes = hash_state(&initial_state)?;
    let next_state_bytes = hash_state(&next_state)?;

    // Generate transition data
    let mut transition_data = [0u8; 32];
    transition_data[0] = 1;
    for i in 0..4 {
        transition_data[i * 8] = i as u8;
    }

    // Generate and verify state transition proof
    let circuit = StateTransitionCircuit::new();
    let computed_next_state = StateTransitionCircuit::compute_poseidon_hash(
        &HashOut::<GoldilocksField>::from_bytes(&initial_state_bytes),
        &HashOut::<GoldilocksField>::from_bytes(&transition_data),
    );
    assert_eq!(&next_state_bytes[..], computed_next_state.to_bytes());

    let proof = circuit.generate_proof(
        initial_state_bytes.try_into().unwrap(),
        computed_next_state.to_bytes().try_into().unwrap(),
        transition_data
    )?;
    assert!(circuit.verify_proof(proof.clone())?);

    // Update Merkle tree
    let channel_key = [9u8; 32];
    let mut smt = SparseMerkleTree::new(32);
    smt.update(channel_key, initial_state_bytes)?;
    smt.update(channel_key, next_state_bytes)?;

    let merkle_proof = smt.generate_proof(channel_key, next_state_bytes)?;
    assert!(SparseMerkleTree::verify_proof(smt.root, &merkle_proof, channel_key)?);

    // Submit to Bitcoin
    let raw_tx_hex = build_op_return_transaction(&client, smt.root)?;
    let txid = client.send_raw_transaction_hex(&raw_tx_hex)?;
    client.generate_blocks(1, &client.get_new_address()?.to_string())?;
    println!("Anchored SMT root in TX {}", txid);

    Ok(())
}