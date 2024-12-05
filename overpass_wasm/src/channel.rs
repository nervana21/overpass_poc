// overpass_wasm/src/channel.rs

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use serde_wasm_bindgen::to_value;
use web_sys::{Storage, Window};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use wasm_bindgen_futures::future_to_promise;
use wasm_bindgen_futures::JsFuture;

// Error type for channel-specific errors
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

#[derive(Debug, Clone)]
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

#[derive(Clone, Debug)]
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
        let mut current_hash = self.nodes.get(&index)
            .expect("Node must exist")
            .clone();
        
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
    }}

#[wasm_bindgen]
pub struct Channel {
    storage: ClientStorage,
    current_state: ChannelState,
    pending_transactions: Vec<Transaction>,
    merkle_tree: MerkleTree,
}

#[wasm_bindgen]
#[derive(Serialize)]
struct SerializableTransaction {
    id: String,
    amount: u64,
    sender: String,
    recipient: String,
    timestamp: u64,
    signature: Vec<u8>,
    nonce: u64
}

impl From<&Transaction> for SerializableTransaction {
    fn from(transaction: &Transaction) -> Self {
        SerializableTransaction {
            id: format!("{:x}", sha2::Sha256::digest(&transaction.signature)), // Using SHA256 hash of signature as a unique identifier
            amount: transaction.amount,
            sender: "sender_address".to_string(), // Replace with actual sender
            recipient: "recipient_address".to_string(), // Replace with actual recipient
            timestamp: transaction.timestamp,
            signature: transaction.signature.clone(),
            nonce: transaction.nonce,
        }
    }
}

#[wasm_bindgen]
impl Channel {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Channel, JsValue> {
        let storage = ClientStorage::new()?;
        let current_state = match storage.load_state("channel-1")? {
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

    pub fn process_transaction(&mut self, amount: u64, data: Vec<u8>) -> js_sys::Promise {
        let current_state = self.current_state.clone();
        let merkle_tree = self.merkle_tree.clone();
        let storage = self.storage.clone();
        let pending_transactions = self.pending_transactions.clone();

        let future = async move {
            // Validate transaction
            if amount == 0 {
                return Err(ChannelError::InvalidAmount.into());
            }

            if current_state.balance + amount < current_state.balance {
                // Overflow check
                return Err(ChannelError::InvalidAmount.into());
            }

            // Create and validate transaction
            let transaction = Transaction::new(
                amount,
                data,
                current_state.nonce + 1,
            );

            // Generate and verify proof
            let proof = Channel::generate_proof(&transaction)?;
            if !Channel::verify_transaction_proof(&proof, &transaction) {
                return Err(ChannelError::InvalidProof.into());
            }

            // Update merkle tree and compute new state
            let mut tree = merkle_tree;
            let merkle_root = tree.add_transaction(&transaction);
            let cell_hash = Channel::compute_cell_hash(&transaction);

            let update = StateUpdate {
                nonce: transaction.nonce,
                balance: current_state.balance + amount,
                merkle_root,
                cell_hash,
                timestamp: transaction.timestamp,
                signature: transaction.signature.clone(),
            };

            // Broadcast update to network
            Channel::broadcast_update(&update).await?;

            // Update local state
            let mut new_transactions = pending_transactions;
            new_transactions.push(transaction);

            let mut new_state = current_state;
            new_state.nonce = update.nonce;
            new_state.balance = update.balance;
            new_state.last_update = update.timestamp;

            // Persist state
            storage.save_state("channel-1", &new_state)?;

            Ok(to_value(&update).unwrap())
        };

        future_to_promise(future)
    }

    fn generate_proof(transaction: &Transaction) -> Result<Vec<u8>, JsValue> {
        let mut hasher = Sha256::new();
        hasher.update(&transaction.serialize());
        Ok(hasher.finalize().to_vec())
    }

    fn verify_transaction_proof(proof: &[u8], transaction: &Transaction) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&transaction.serialize());
        let transaction_hash = hasher.finalize();
        proof == transaction_hash.as_slice()
    }

    async fn broadcast_update(_update: &StateUpdate) -> Result<(), JsValue> {
        // In production, this would send the update to a network
        let window = web_sys::window()
            .ok_or_else(|| JsValue::from_str("No window found"))?;
        
        let performance = window
            .performance()
            .ok_or_else(|| JsValue::from_str("Performance API not available"))?;
        
        // Simulate network latency
        let start = performance.now();
        while performance.now() - start < 100.0 {
            // Simulate processing
            JsFuture::from(js_sys::Promise::new(&mut |resolve, _| {
                resolve.call0(&JsValue::NULL).unwrap();
            })).await?;
        }
        
        Ok(())
    }

    fn compute_cell_hash(transaction: &Transaction) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&transaction.serialize());
        hasher.finalize().to_vec()
    }

    pub fn get_state(&self) -> Result<JsValue, JsValue> {
        Ok(to_value(&self.current_state)?)
    }

    pub fn get_pending_transactions(&self) -> Result<JsValue, JsValue> {
        let serializable_transactions: Vec<SerializableTransaction> = self.pending_transactions
            .iter()
            .map(|t| SerializableTransaction::from(t))
            .collect();
        Ok(to_value(&serializable_transactions)?)
    }

    pub fn finalize(&mut self) -> Result<JsValue, JsValue> {
        self.current_state.is_finalized = true;
        self.storage.save_state("channel-1", &self.current_state)?;
        Ok(to_value(&self.current_state)?)
    }
}

#[derive(Clone)]
pub struct ClientStorage {
    storage: Storage,
}

impl ClientStorage {
    pub fn new() -> Result<Self, JsValue> {
        let window: Window = web_sys::window()
            .ok_or_else(|| JsValue::from_str("No window found"))?;
            
        let storage = window
            .local_storage()?
            .ok_or_else(|| JsValue::from_str("No local storage found"))?;
        
        Ok(Self { storage })
    }

    pub fn save_state(&self, key: &str, state: &ChannelState) -> Result<(), JsValue> {
        let serialized = serde_json::to_string(state)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        self.storage.set_item(key, &serialized)?;
        Ok(())
    }

    pub fn load_state(&self, key: &str) -> Result<Option<ChannelState>, JsValue> {
        match self.storage.get_item(key)? {
            Some(stored) => {
                serde_json::from_str(&stored)
                    .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))
                    .map(Some)
            }
            None => Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_channel_creation() {
        let channel = Channel::new().unwrap();
        let state = channel.get_state().unwrap();
        let state: ChannelState = serde_wasm_bindgen::from_value(state).unwrap();
        assert_eq!(state.nonce, 0);
        assert_eq!(state.balance, 0);
    }

    #[wasm_bindgen_test]
    async fn test_transaction_processing() {
        let mut channel = Channel::new().unwrap();
        let amount = 100;
        let data = vec![1, 2, 3];
        
        let promise = channel.process_transaction(amount, data);
        let result = JsFuture::from(promise).await.unwrap();
        
        let update: StateUpdate = serde_wasm_bindgen::from_value(result).unwrap();
        assert_eq!(update.balance, amount);
        assert_eq!(update.nonce, 1);
    }

    #[wasm_bindgen_test]
    async fn test_multiple_transactions() {
        let mut channel = Channel::new().unwrap();
        
        for i in 1..=3 {
            let promise = channel.process_transaction(100 * i as u64, vec![i as u8]);
            let result = JsFuture::from(promise).await.unwrap();
            
            let update: StateUpdate = serde_wasm_bindgen::from_value(result).unwrap();
            assert_eq!(update.nonce, i as u64);
        }
    }
}
