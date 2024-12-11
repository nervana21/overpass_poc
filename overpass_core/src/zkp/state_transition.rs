// src/zkp/state_transition.rs

use crate::zkp::tree::{MerkleProof, MerkleTree};
use plonky2::plonk::config::Hasher;
use anyhow::{anyhow, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};
use crate::zkp::channel::ChannelState;
use plonky2_field::types::{Field, PrimeField64};
use std::collections::HashMap;


/// Type alias for Poseidon configuration
type PoseidonConfig = PoseidonGoldilocksConfig;

/// Represents the state transition circuit using Plonky2.
pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, PoseidonConfig, 2>,
    current_state_target: HashOutTarget,
    next_state_target: HashOutTarget,
    transition_data_target: HashOutTarget,
    channel_roots: HashMap<[u8; 32], [u8; 32]>, // Changed to [u8; 32]
    merkle_tree: MerkleTree,
}

impl StateTransitionCircuit {
    /// Initializes a new state transition circuit.
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Define virtual hash targets for current state, transition data, and next state.
        let current_state_target = builder.add_virtual_hash();
        let transition_data_target = builder.add_virtual_hash();
        let next_state_target = builder.add_virtual_hash();

        // Register current and next states as public inputs.
        builder.register_public_inputs(&current_state_target.elements);
        builder.register_public_inputs(&next_state_target.elements);

        // Prepare inputs for Poseidon hash: interleaving current state and transition data.
        let inputs = current_state_target
            .elements
            .iter()
            .zip(transition_data_target.elements.iter())
            .flat_map(|(&c, &t)| vec![c, t])
            .collect::<Vec<_>>();

        // Compute the next state hash using Poseidon without padding.
        let computed_next_state = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        // Enforce that the computed hash matches the declared next state.
        for i in 0..4 {
            builder.connect(computed_next_state.elements[i], next_state_target.elements[i]);
        }

        // Finalize the circuit.
        let circuit_data = builder.build::<PoseidonConfig>();

        Self {
            circuit_data,
            current_state_target,
            next_state_target,
            transition_data_target,
            channel_roots: HashMap::new(),
            merkle_tree: MerkleTree::new(),
        }
    }

    /// Generates a zero-knowledge proof for a state transition.
    pub fn generate_zkp(
        &self,
        initial_state: &ChannelState,
        transition_data: &[u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, PoseidonConfig, 2>> {
        let mut pw = PartialWitness::new();
        // Compute next state by applying transition data to initial state
        let next_state = apply_transition(initial_state, transition_data)
            .context("Failed to apply transition to initial state")?;

        // Serialize and hash the initial and next states
        let initial_state_bytes = hash_state(&initial_state)
            .context("Failed to hash initial state")?;
        let next_state_bytes = hash_state(&next_state)
            .context("Failed to hash next state")?;

        // Convert byte arrays to HashOut targets.
        let initial_hash = Self::to_hash_out(initial_state_bytes)
            .context("Failed to convert initial hash")?;
        let transition_hash = Self::to_hash_out(*transition_data)
            .context("Failed to convert transition data hash")?;
        let next_hash = Self::to_hash_out(next_state_bytes)
            .context("Failed to convert next hash")?;

        // Assign hashes to their respective targets.
        pw.set_hash_target(self.current_state_target, initial_hash)
            .context("Failed to set initial state hash")?;
        pw.set_hash_target(self.transition_data_target, transition_hash)
            .context("Failed to set transition data hash")?;
        pw.set_hash_target(self.next_state_target, next_hash)
            .context("Failed to set next state hash")?;

        // Generate and return the proof.
        self.circuit_data.prove(pw).context("Proof generation failed")
    }

    /// Verifies a zero-knowledge proof for a state transition.
    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, PoseidonConfig, 2>,
    ) -> Result<bool> {
        self.circuit_data
            .verify(proof)
            .map(|_| true)
            .context("Proof verification failed")
    }

    /// Converts a byte array to a Poseidon HashOut.
    fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>, anyhow::Error> {
        let elements = data
            .chunks(8)
            .map(|chunk| {
                let bytes: [u8; 8] = chunk
                    .try_into()
                    .map_err(|_| anyhow!("Invalid byte length for field element"))?;
                Ok(GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes)))
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        Ok(HashOut::from_partial(&elements))
    }

    /// Converts a Poseidon HashOut back to a byte array.
    fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        for (i, &element) in hash.elements.iter().enumerate() {
            let elem_u64 = element.to_noncanonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Computes the Poseidon hash for the next state based on current state and transition data.
    fn compute_poseidon_hash(
        current_hash: &HashOut<GoldilocksField>,
        transition_hash: &HashOut<GoldilocksField>,
    ) -> HashOut<GoldilocksField> {
        let inputs = vec![
            current_hash.elements[0],
            transition_hash.elements[0],
            current_hash.elements[1],
            transition_hash.elements[1],
            current_hash.elements[2],
            transition_hash.elements[2],
            current_hash.elements[3],
            transition_hash.elements[3],
        ];
        PoseidonHash::hash_no_pad(&inputs)
    }

    /// Computes the next state based on current state and transition data.
    pub fn compute_next_state(
        &self,
        current_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<[u8; 32]> {
        let current_hash = Self::to_hash_out(current_state)
            .context("Failed to convert current state hash")?;
        let transition_hash = Self::to_hash_out(transition_data)
            .context("Failed to convert transition data hash")?;
        let next_hash = Self::compute_poseidon_hash(&current_hash, &transition_hash);
        Self::hash_out_to_bytes(&next_hash).context("Failed to convert next hash to bytes")
    }

    /// Generates a Merkle proof for a channel's transaction history.
    pub fn generate_merkle_proof(&self, channel_id: [u8; 32]) -> Option<MerkleProof> {
        self.channel_roots.get(&channel_id).and_then(|root| {
            self.merkle_tree.get_proof(root).map(|proof| MerkleProof { path: proof })
        })
    }

    /// Verifies a Merkle proof for a channel's transaction history.
    pub fn verify_merkle_proof(&self, channel_id: [u8; 32], proof: &MerkleProof) -> bool {
        if let Some(root) = self.channel_roots.get(&channel_id) {
            self.merkle_tree.verify_proof(root, &proof.path, root)
        } else {
            false
        }
    }
}

/// Converts ChannelState to a 32-byte hash using PoseidonHash.
fn hash_state(state: &ChannelState) -> Result<[u8; 32]> {
    use plonky2::hash::poseidon::PoseidonHash;

    println!("Hashing state:");
    println!("  Balances: {:?}", state.balances);
    println!("  Nonce: {}", state.nonce);
    println!("  Metadata length: {}", state.metadata.len());
    println!("  Merkle Root: {:?}", state.merkle_root);

    // Convert ChannelState fields to field elements
    let mut inputs = Vec::new();

    // Serialize balances
    for &balance in &state.balances {
        let field_element = GoldilocksField::from_canonical_u64(balance);
        println!("  Balance field element: {:?}", field_element);
        inputs.push(field_element);
    }

    // Serialize nonce
    let nonce_element = GoldilocksField::from_canonical_u64(state.nonce);
    println!("  Nonce field element: {:?}", nonce_element);
    inputs.push(nonce_element);

    // Serialize metadata
    for &byte in &state.metadata {
        let metadata_element = GoldilocksField::from_canonical_u8(byte);
        println!("  Metadata field element: {:?}", metadata_element);
        inputs.push(metadata_element);
    }

    // Serialize merkle_root
    for &byte in &state.merkle_root {
        let merkle_element = GoldilocksField::from_canonical_u8(byte);
        println!("  Merkle Root field element: {:?}", merkle_element);
        inputs.push(merkle_element);
    }

    println!("Total input elements: {}", inputs.len());

    // Compute Poseidon hash
    let hash_out = PoseidonHash::hash_no_pad(&inputs);
    println!("Hash elements: {:?}", hash_out.elements);

    // Convert to bytes
    let mut bytes = [0u8; 32];
    for (i, &element) in hash_out.elements.iter().enumerate() {
        let elem_u64 = element.to_canonical_u64();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_u64.to_le_bytes());
    }

    println!("Final hash bytes: {:?}", bytes);
    Ok(bytes)
}

/// Applies transition data to the initial state to produce the next state.
fn apply_transition(initial_state: &ChannelState, transition_data: &[u8; 32]) -> Result<ChannelState> {
    // Example transition logic:
    // - Update balances
    // - Increment nonce
    // - Update metadata if necessary

    // For demonstration, we'll assume transition_data encodes:
    // - delta_balance_0: i32 (4 bytes)
    // - delta_balance_1: i32 (4 bytes)
    // - delta_nonce: i32 (4 bytes)
    // The rest of the bytes are unused.

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
    let new_nonce = if delta_nonce >= 0 {
        initial_state
            .nonce
            .checked_add(delta_nonce as u64)
            .ok_or_else(|| anyhow!("Nonce overflow"))?
    } else {
        initial_state
            .nonce
            .checked_sub((-delta_nonce) as u64)
            .ok_or_else(|| anyhow!("Nonce underflow"))?
    };

 
    // Create the new state
    let mut new_state = ChannelState {
        balances: vec![new_balance_0 as u64, new_balance_1 as u64],
        nonce: new_nonce,
        metadata: initial_state.metadata.clone(),
        merkle_root: [0u8; 32], // Placeholder, will be updated after hashing
        proof: initial_state.proof.clone(),
    };

    // Compute the new merkle_root based on the updated state
    new_state.merkle_root = hash_state(&new_state)
        .context("Failed to compute new merkle_root")?;

    Ok(new_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use bitcoin::Network;

    #[test]
    fn test_e2e_integration() -> Result<()> {
        println!("\n=== Starting E2E Integration Test ===\n");

        // Initialize Bitcoin client
        let client = Client::new(
            "http://localhost:18332",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        ).context("Failed to create Bitcoin client")?;

        println!("Bitcoin client initialized");

        // Fund the wallet
        let addr = client
            .get_new_address(None, None)
            .context("Failed to generate new address")?;
        println!("Generated address: {:?}", addr);

        // Generate blocks to confirm the address has funds
        client
            .generate_to_address(101, &addr.clone().require_network(Network::Testnet)?)
            .context("Failed to generate blocks")?;
        println!("Generated 101 blocks");

        // Check wallet balance
        let balance = client
            .get_balance(None, None)
            .context("Failed to get wallet balance")?;
        println!("Wallet balance: {}", balance);
        assert!(balance.to_sat() > 0, "Wallet balance should be greater than zero");

        // Define channel states
        println!("\n=== Creating Channel States ===\n");

        let initial_state = ChannelState {
            balances: vec![100, 50],  // Initial balances
            nonce: 0,                 // Initial nonce
            metadata: Vec::<u8>::new(),
            merkle_root: [0u8; 32],   // Placeholder value
            proof: None,
        };
        println!("Initial state created: {:?}", initial_state);

        // Generate transition data
        println!("\n=== Generating Transition Data ===\n");

        let mut transition_data = [0u8; 32];
        transition_data[0..4].copy_from_slice(&(-3i32).to_le_bytes());  // delta_balance_0 = -3
        transition_data[4..8].copy_from_slice(&3i32.to_le_bytes());     // delta_balance_1 = +3
        transition_data[8..12].copy_from_slice(&1i32.to_le_bytes());    // delta_nonce = +1

        println!("Transition data: {:?}", transition_data);
        println!("Delta balance 0: {}", i32::from_le_bytes(transition_data[0..4].try_into().unwrap()));
        println!("Delta balance 1: {}", i32::from_le_bytes(transition_data[4..8].try_into().unwrap()));
        println!("Delta nonce: {}", i32::from_le_bytes(transition_data[8..12].try_into().unwrap()));

        // Apply transition to get the next state
        println!("\n=== Applying Transition ===\n");
        let next_state = apply_transition(&initial_state, &transition_data)?;
        println!("Next state created: {:?}", next_state);

        // Compute state hashes
        println!("\n=== Computing State Hashes ===\n");

        let initial_state_bytes = hash_state(&initial_state)
            .context("Failed to hash initial state")?;
        let next_state_bytes = hash_state(&next_state)
            .context("Failed to hash next state")?;

        println!("Initial State Hash: {:?}", initial_state_bytes);
        println!("Next State Hash: {:?}", next_state_bytes);

        // Initialize Merkle tree and update with states
        println!("\n=== Updating Merkle Tree ===\n");

        let _channel_key = [9u8; 32]; // Handled unused variable by prefixing with _
        let mut smt = MerkleTree::new();

        smt.insert(initial_state_bytes)?;
        println!("Initial state added to Merkle tree");

        smt.insert(next_state_bytes)?;
        println!("Next state added to Merkle tree");

        // Generate and verify Merkle proof for the next state
        println!("\n=== Generating and Verifying Merkle Proof ===\n");
        let merkle_proof = smt.get_proof(&next_state_bytes)
            .ok_or(anyhow!("Failed to generate Merkle proof"))?;
        println!("Merkle proof generated successfully");

        // Verify Merkle proof
        println!("Merkle proof verification started");
        println!("Root: {:?}", smt.root);

        if !smt.verify_proof(&next_state_bytes, &merkle_proof, &smt.root) {
            return Err(anyhow!("Merkle proof verification failed"));
        }
        println!("Merkle proof verified successfully");

        // Build and send OP_RETURN transaction
        println!("\n=== Building and Sending OP_RETURN Transaction ===\n");
        let raw_tx_hex = build_op_return_transaction(&client, next_state_bytes)?;
        let txid = client.send_raw_transaction(raw_tx_hex.as_str())?;
        println!("Transaction sent with ID: {}", txid);

        // Generate a block to confirm the transaction
        client.generate_to_address(1, &addr.require_network(Network::Testnet)?)?;
        println!("Block generated to confirm transaction");

        println!("\n=== Test Completed Successfully ===\n");
        Ok(())
    }

    /// Builds an OP_RETURN transaction embedding the provided data.
    fn build_op_return_transaction(client: &Client, data: [u8; 32]) -> Result<String> {  
        // Define a reasonable fee (e.g., 1,000 satoshis)
        let fee = 1_000;

        // List unspent outputs
        let utxos = client.list_unspent(None, None, None, None, None)
            .context("Failed to list unspent outputs")?;
        
        // Select a UTXO that can cover the fee
        let utxo = utxos.iter()
            .find(|utxo| utxo.amount.to_sat() >= fee)
            .ok_or_else(|| anyhow!("No suitable UTXO found"))?;
            
        let outpoint = bitcoin::OutPoint::new(utxo.txid, utxo.vout);
        
        println!("UTXO fetched");
        println!("UTXO: {:?}", utxo);
        println!("Outpoint: {}", outpoint);
        
        println!("Fee: {}", fee);
        println!("Data: {:?}", data);

        // Construct the OP_RETURN script
        let op_return_script = bitcoin::blockdata::script::Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
            .push_slice(&data)
            .into_script();

        println!("OP_RETURN script built");

        // Create the transaction input
        let tx_in = bitcoin::TxIn {
            previous_output: outpoint,
            script_sig: bitcoin::ScriptBuf::default(),
            sequence: bitcoin::Sequence(0xffffffff),
            witness: bitcoin::Witness::default(),
        };

        // Create the OP_RETURN output
        let tx_out_opreturn = bitcoin::TxOut {
            value: 0,
            script_pubkey: op_return_script,
        };

        // Calculate the change amount
        let change_value = utxo.amount.to_sat() - fee;

        // Create the change output
        let tx_out_change = bitcoin::TxOut {
            value: change_value,
            script_pubkey: utxo.script_pub_key.clone(),
        };

        // Build the transaction
        let tx = bitcoin::Transaction {
            version: 2,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![tx_in],
            output: vec![tx_out_opreturn, tx_out_change],
        };

        println!("Transaction built");

        // Serialize the transaction to hex
        let raw_tx_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
        println!("Transaction serialized");

        // Sign the transaction
        let signed_tx_result = client
            .sign_raw_transaction_with_wallet(raw_tx_hex.as_str(), None, None)
            .context("Transaction signing failed")?;

        // Convert Vec<u8> to hex string
        let signed_tx_hex = hex::encode(signed_tx_result.hex);
        
        println!("Transaction signed");
        
        // Send the raw transaction
        let txid = client.send_raw_transaction(signed_tx_hex.as_str())?;
        println!("Transaction sent with ID: {}", txid);

        println!("\n=== OP_RETURN Transaction Sent Successfully ===\n");
        Ok(signed_tx_hex)
    }
}