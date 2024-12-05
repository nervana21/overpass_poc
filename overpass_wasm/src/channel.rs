// overpass_wasm/src/channel.rs

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use wasm_bindgen::convert::RefFromWasmAbi;
use std::mem::ManuallyDrop;
use crate::storage::ClientStorage;

#[derive(Serialize, Deserialize)]
pub struct SerializableChannel {
    current_state: ChannelState,
    pending_transactions: Vec<SerializableTransaction>,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableTransaction {
    // Add fields for SerializableTransaction here
}

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
    }}
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
    nonce: u64,
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
        let storage = crate::storage::ClientStorage::new()?;
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

    #[wasm_bindgen(js_name = fromJsValue)]
    pub fn from_js_value(value: &JsValue) -> Result<Channel, JsValue> {
        serde_wasm_bindgen::from_value(value.clone()).map_err(|e| e.into())
    }
}
#[wasm_bindgen]
impl Channel {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Channel, JsValue> {
        let storage = crate::storage::ClientStorage::new()?;
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

    #[wasm_bindgen(js_name = fromJsValue)]
    pub fn from_js_value(value: &JsValue) -> Result<Channel, JsValue> {
        serde_wasm_bindgen::from_value(value.clone()).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
impl wasm_bindgen::describe::WasmDescribe for Channel {
    fn describe() {
        <JsValue as wasm_bindgen::describe::WasmDescribe>::describe()
    }
}

impl wasm_bindgen::convert::IntoWasmAbi for Channel {
    type Abi = <JsValue as wasm_bindgen::convert::IntoWasmAbi>::Abi;
    fn into_abi(self) -> Self::Abi {
        serde_wasm_bindgen::to_value(&self).unwrap().into_abi()
    }
}

impl wasm_bindgen::convert::FromWasmAbi for Channel {
    type Abi = <JsValue as wasm_bindgen::convert::FromWasmAbi>::Abi;
    unsafe fn from_abi(js: Self::Abi) -> Self {
        let js_value = JsValue::from_abi(js);
        serde_wasm_bindgen::from_value(js_value).unwrap()
    }
}

impl wasm_bindgen::convert::RefFromWasmAbi for Channel {
    type Abi = <JsValue as wasm_bindgen::convert::RefFromWasmAbi>::Abi;
    type Anchor = ManuallyDrop<Channel>;

    unsafe fn ref_from_abi(js: Self::Abi) -> Self::Anchor {
        let js_value = JsValue::ref_from_abi(js);
        let channel: Channel = serde_wasm_bindgen::from_value(js_value).unwrap();
        ManuallyDrop::new(channel)
    }
}

impl wasm_bindgen::convert::RefMutFromWasmAbi for Channel {
    type Abi = <JsValue as wasm_bindgen::convert::RefMutFromWasmAbi>::Abi;
    type Anchor = ManuallyDrop<Channel>;

    unsafe fn ref_mut_from_abi(js: Self::Abi) -> Self::Anchor {
        let js_value = JsValue::ref_from_abi(js);
        let channel: Channel = serde_wasm_bindgen::from_value(js_value).unwrap();
        ManuallyDrop::new(channel)
    }
}
