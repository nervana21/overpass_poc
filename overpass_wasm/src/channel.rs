// overpass_wasm/src/channel.rs

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use wasm_bindgen::prelude::*;
use crate::storage::ClientStorage;

/// A serializable channel structure.
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Channel {
    #[serde(skip)]
    storage: ClientStorage,
    current_state: ChannelState,
    pending_transactions: Vec<Transaction>,
    merkle_tree: MerkleTree,
}

/// A serializable transaction structure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    pub amount: u64,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl Transaction {
    pub fn new(amount: u64, data: Vec<u8>, nonce: u64) -> Self {
        let timestamp = js_sys::Date::now() as u64;
        // In production, this would use proper key signing
        let signature = Vec::new();
        Self {
            amount,
            data,
            nonce,
            timestamp,
            signature,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}

/// A serializable transaction structure for external use.
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableTransaction {
    id: String,
    amount: u64,
    sender: String,
    recipient: String,
    timestamp: u64,
    signature: Vec<u8>,
    nonce: u64,
}

impl From<&Transaction> for SerializableTransaction {
    fn from(transaction: &Transaction) -> Self {
        SerializableTransaction {
            id: format!("{:x}", Sha256::digest(&transaction.signature)), // Using SHA256 hash of signature as a unique identifier
            amount: transaction.amount,
            sender: "sender_address".to_string(), // Replace with actual sender
            recipient: "recipient_address".to_string(), // Replace with actual recipient
            timestamp: transaction.timestamp,
            signature: transaction.signature.clone(),
            nonce: transaction.nonce,
        }
    }
}

/// Error type for channel-specific errors.
#[derive(Debug, Clone)]
pub enum ChannelError {
    InvalidNonce,
    InvalidProof,
    InvalidAmount,
    StorageError,
    StateError,
    NetworkError,
}

impl From<ChannelError> for JsValue {
    fn from(error: ChannelError) -> Self {
        JsValue::from_str(&format!("Channel error: {:?}", error))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateUpdate {
    pub nonce: u64,
    pub balance: u64,
    pub merkle_root: Vec<u8>,
    pub cell_hash: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelState {
    pub nonce: u64,
    pub balance: u64,
    pub merkle_root: Vec<u8>,
    pub cell_hash: Vec<u8>,
    pub last_update: u64,
    pub is_finalized: bool,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            merkle_root: Vec::new(),
            cell_hash: Vec::new(),
            last_update: 0,
            is_finalized: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MerkleTree {
    nodes: HashMap<usize, Vec<u8>>,
    depth: usize,
}

impl MerkleTree {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            depth: 32, // Sufficient depth for most use cases
        }
    }

    fn add_transaction(&mut self, transaction: &Transaction) -> Vec<u8> {
        let leaf = self.hash_transaction(transaction);
        let index = self.nodes.len();
        self.nodes.insert(index, leaf.clone());
        self.compute_root(index)
    }

    fn hash_transaction(&self, transaction: &Transaction) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&transaction.serialize());
        hasher.finalize().to_vec()
    }

    fn compute_root(&self, index: usize) -> Vec<u8> {
        let mut current_hash = self.nodes.get(&index).expect("Node must exist").clone();

        let mut current_index = index;
        for _ in 0..self.depth {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if let Some(sibling) = self.nodes.get(&sibling_index) {
                let mut hasher = Sha256::new();
                if current_index % 2 == 0 {
                    hasher.update(&current_hash);
                    hasher.update(sibling);
                } else {
                    hasher.update(sibling);
                    hasher.update(&current_hash);
                }
                current_hash = hasher.finalize().to_vec();
            }

            current_index /= 2;
        }

        current_hash
    }

    #[allow(dead_code)]
    fn verify_proof(&self, proof: &[Vec<u8>], leaf_hash: &[u8], root: &[u8]) -> bool {
        let mut current_hash = leaf_hash.to_vec();

        for (i, sibling) in proof.iter().enumerate() {
            let mut hasher = Sha256::new();
            if i % 2 == 0 {
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            current_hash = hasher.finalize().to_vec();
        }

        &current_hash == root
    }
}

#[wasm_bindgen]
impl Channel {
    /// Creates a new Channel instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Channel, JsValue> {
        let storage = ClientStorage::new().map_err(|_| ChannelError::StorageError.into())?;
        let current_state = match storage.load_state("channel-1").map_err(|_| ChannelError::StorageError.into())? {
            Some(state) => state,
            None => ChannelState::default(),
        };

        Ok(Self {
            storage,
            current_state,
            pending_transactions: Vec::new(),
            merkle_tree: MerkleTree::new(),
        })
    }

    /// Converts a JsValue to a Channel instance.
    #[wasm_bindgen(js_name = fromJsValue)]
    pub fn from_js_value(value: &JsValue) -> Result<Channel, JsValue> {
        serde_wasm_bindgen::from_value(value.clone()).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Converts the Channel instance to a JsValue.
    #[wasm_bindgen(js_name = toJsValue)]
    pub fn to_js_value(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Adds a transaction to the channel.
    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.pending_transactions.push(transaction.clone());
        let merkle_root = self.merkle_tree.add_transaction(&transaction);
        self.current_state.merkle_root = merkle_root;
        // Update other state fields as necessary
    }

    /// Retrieves a transaction by ID.
    pub fn get_transaction(&self, id: &str) -> Option<SerializableTransaction> {
        self.pending_transactions.iter().find_map(|tx| {
            let tx_serializable: SerializableTransaction = tx.into();
            if tx_serializable.id == id {
                Some(tx_serializable)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};

    #[test]
    fn test_create_htlc_parameters() {
        let client = BitcoinClient::new();
        let htlc = client.create_htlc_parameters(
            1_000_000,
            [1u8; 20],
            sha256::Hash::hash(&[0u8; 32]).to_byte_array(),
            144,
        );

        assert_eq!(htlc.amount, 1_000_000);
        assert_eq!(htlc.timeout_height, 144);
        assert_eq!(htlc.receiver, [1u8; 20]);
    }

    #[test]
    fn test_create_op_return_script() {
        let client = BitcoinClient::new();
        let metadata = OpReturnMetadata {
            channel_id: [0u8; 32],
            rebalancing_flags: 1,
            hash_lock: sha256::Hash::hash(&[0u8; 32]).to_byte_array(),
            data: vec![1, 2, 3],
            stealth_address: None,
            version: 1,
            nonce: [0u8; 32],
        };

        let script_result = client.create_op_return_script(&metadata);
        assert!(script_result.is_ok());
    }

    #[test]
    fn test_create_transaction() {
        let client = BitcoinClient::new();
        let prev_script = ScriptBuf::new();
        let pubkey_hash = [0u8; 20];
        let tx_result = client.create_transaction(&prev_script, 1_000_000, pubkey_hash);
        assert!(tx_result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_htlc() {
        let client = BitcoinClient::new();
        let preimage = [0u8; 32];
        let hash_lock = sha256::Hash::hash(&preimage).to_byte_array();

        let state = client
            .create_lock_state(
                1_000_000,
                [0u8; 32],
                100,
                [1u8; 20],
                0,
                0,
                Some(HTLCParameters {
                    amount: 1_000_000,
                    receiver: [1u8; 20],
                    hash_lock,
                    timeout_height: 144,
                }),
                None,
            )
            .unwrap();

        let valid = client.verify_htlc(&state, &preimage).await;
        assert!(valid.is_ok());
    }

    #[tokio::test]
    async fn test_state_caching() {
        let client = BitcoinClient::new();
        let test_hash = [1u8; 32];
        let test_data = vec![1, 2, 3, 4];

        client
            .cache_state(test_hash, test_data.clone())
            .await
            .unwrap();
        let cached = client.get_cached_state(test_hash).await;

        assert_eq!(cached, Some(test_data));
    }
}

/// Represents a Bitcoin client managing state and operations.
#[derive(Debug, Clone)]
pub struct BitcoinClient {
    state_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl BitcoinClient {
    /// Creates a new Bitcoin client with an empty state cache.
    pub fn new() -> Self {
        Self {
            state_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates HTLC parameters for locking channels.
    pub fn create_htlc_parameters(
        &self,
        amount: u64,
        receiver: [u8; 20],
        hash_lock: [u8; 32],
        timeout_height: u32,
    ) -> HTLCParameters {
        HTLCParameters {
            amount,
            receiver,
            hash_lock,
            timeout_height,
        }
    }

    /// Creates an OP_RETURN script with encoded metadata.
    pub fn create_op_return_script(
        &self,
        metadata: &OpReturnMetadata,
    ) -> Result<ScriptBuf, String> {
        let encoded = metadata
            .encode()
            .map_err(|e| format!("Failed to encode metadata: {}", e))?;

        Ok(Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&encoded)
            .into_script())
    }

    /// Creates a new Bitcoin transaction.
    pub fn create_transaction(
        &self,
        prev_script: &ScriptBuf,
        value: u64,
        pubkey_hash: [u8; 20],
    ) -> Result<Transaction, String> {
        let tx_in = TxIn {
            previous_output: OutPoint::default(),
            script_sig: prev_script.clone(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .push_opcode(bitcoin::opcodes::all::OP_HASH160)
            .push_slice(&pubkey_hash)
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();

        let tx_out = TxOut {
            value,
            script_pubkey,
        };

        let tx = Transaction {
            version: 2,
            lock_time: locktime::absolute::LockTime::ZERO,
            input: vec![tx_in],
            output: vec![tx_out],
        };

        Ok(tx)
    }

    /// Verifies HTLC parameters against a preimage.
    pub async fn verify_htlc(
        &self,
        state: &BitcoinLockState,
        preimage: &[u8],
    ) -> Result<bool, String> {
        match &state.htlc_params {
            Some(params) => params
                .verify_hashlock(preimage)
                .map_err(|e| format!("Failed to verify hashlock: {}", e)),
            None => Err("HTLC parameters not found".to_string()),
        }
    }

    /// Creates a new BitcoinLockState.
    pub fn create_lock_state(
        &self,
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<BitcoinLockState, String> {
        BitcoinLockState::new(
            lock_amount,
            lock_script_hash,
            lock_height,
            pubkey_hash,
            sequence,
            nonce,
            htlc_params,
            stealth_address,
        )
        .map_err(|e| format!("Failed to create lock state: {}", e))
    }

    /// Adds a state to the cache.
    pub async fn cache_state(
        &self,
        state_hash: [u8; 32],
        state_data: Vec<u8>,
    ) -> Result<(), String> {
        let mut cache = self.state_cache.write().await;
        cache.insert(state_hash, state_data);
        Ok(())
    }

    /// Retrieves a state from the cache.
    pub async fn get_cached_state(&self, state_hash: [u8; 32]) -> Option<Vec<u8>> {
        let cache = self.state_cache.read().await;
        cache.get(&state_hash).cloned()
    }
}