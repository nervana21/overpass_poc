pub mod channel;
pub mod error;
pub mod storage;
pub mod types;

use crate::types::cell_builder::{Cell, CellBuilder};
use crate::types::dag_boc::DAGBOC;
use crate::types::ops::{ChannelOpCode, OpCode, WalletOpCode};
use crate::types::state_boc::StateBOC;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[derive(Serialize, Deserialize)]
pub struct ChannelConfig {
    pub initial_balance: u64,
    pub security_bits: usize,
    pub version: u32,
}

#[derive(Serialize, Deserialize)]
pub struct StateUpdate {
    pub nonce: u64,
    pub balance: u64,
    pub merkle_root: [u8; 32],
    pub cell_hash: [u8; 32],
}

#[wasm_bindgen]
pub struct Channel {
    state_boc: StateBOC,
    dag_boc: DAGBOC,
    nonce: u64,
}

#[wasm_bindgen]
impl Channel {
    #[wasm_bindgen(constructor)]
    pub fn new(config_str: &str) -> Result<Channel, JsValue> {
        console_error_panic_hook::set_once();

        let config: ChannelConfig = serde_json_wasm::from_str(config_str)
            .map_err(|e| JsValue::from_str(&format!("Config parse error: {}", e)))?;

        let state_boc = StateBOC::new();
        let dag_boc = DAGBOC::new();
        let mut cell_builder = CellBuilder::new();

        let initial_cell = Cell {
            cell_type: crate::types::cell_builder::CellType::Ordinary,
            data: Vec::new(),
            references: Vec::new(),
            slice: None,
            nonce: 0,
            balance: config.initial_balance,
        };

        cell_builder
            .add_cell(initial_cell)
            .map_err(|e| JsValue::from_str(&format!("Cell initialization error: {}", e)))?;

        Ok(Channel {
            state_boc,
            dag_boc,
            nonce: 0,
        })
    }

    #[wasm_bindgen]
    pub fn create_wallet(&mut self, entropy: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Creating new wallet BOC structure");

        let mut cell_data = entropy.to_vec();
        cell_data.insert(0, WalletOpCode::Create as u8);
        
        self.dag_boc
            .add_cell(cell_data)
            .map_err(|e| JsValue::from_str(&format!("Cell addition error: {}", e)))?;

        let state_cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: entropy.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: 0,
            balance: 0,
        };

        self.state_boc.add_cell(state_cell);
        self.nonce += 1;
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn update_state(&mut self, amount: u64, data: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Updating state with amount: {}", amount);

        let mut cell_data = data.to_vec();
        cell_data.insert(0, ChannelOpCode::Update as u8);
        
        self.dag_boc
            .add_cell(cell_data)
            .map_err(|e| JsValue::from_str(&format!("Cell addition error: {}", e)))?;

        let state_cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: data.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: 0,
        };

        self.state_boc.add_cell(state_cell);
        self.nonce += 1;
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn process_transaction(&mut self, tx_data: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Processing transaction");

        let mut cell_data = tx_data.to_vec();
        cell_data.insert(0, ChannelOpCode::CreatePayment as u8);
        
        self.dag_boc
            .add_cell(cell_data.clone())
            .map_err(|e| JsValue::from_str(&format!("Cell addition error: {}", e)))?;

        let state_cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: cell_data,
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: 0,
        };

        self.state_boc.add_cell(state_cell);
        self.nonce += 1;
        self.serialize_state()
    }
    #[wasm_bindgen]
    pub fn finalize_state(&mut self) -> Result<JsValue, JsValue> {
        console_log!("Finalizing state");
        
        let mut cell_data = Vec::new();
        cell_data.push(ChannelOpCode::Finalize as u8);
        
        self.dag_boc
            .add_cell(cell_data)
            .map_err(|e| JsValue::from_str(&format!("Cell addition error: {}", e)))?;

        let final_hash = self.state_boc.compute_hash();
        Ok(serde_wasm_bindgen::to_value(&final_hash)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))?)
    }

    #[wasm_bindgen]
    pub fn get_current_state(&self) -> Result<JsValue, JsValue> {
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn verify_state(&mut self, state_bytes: &[u8]) -> Result<bool, JsValue> {
        let mut submitted_state = StateBOC::deserialize(state_bytes)
            .map_err(|e| JsValue::from_str(&format!("State deserialization error: {}", e)))?;

        Ok(self.state_boc.compute_hash() == submitted_state.compute_hash())
    }

    fn serialize_state(&self) -> Result<JsValue, JsValue> {
        let state_boc_bytes = self
            .state_boc
            .serialize()
            .map_err(|e| JsValue::from_str(&format!("BOC serialization error: {}", e)))?;
        Ok(serde_wasm_bindgen::to_value(&state_boc_bytes)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))?)
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    console_log!("Overpass WASM module initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    use crate::types::state_boc::StateBOC;

    wasm_bindgen_test_configure!(run_in_browser);

    fn create_test_config() -> String {
        r#"{
            "initial_balance": 0,
            "security_bits": 256,
            "version": 1
        }"#.to_string()
    }

    #[wasm_bindgen_test]
    fn test_channel_creation() {
        let channel = Channel::new(&create_test_config()).unwrap();
        let state = channel.get_current_state().unwrap();
        let state_bytes: Vec<u8> = serde_wasm_bindgen::from_value(state).unwrap();
        let mut state_boc = StateBOC::deserialize(&state_bytes).unwrap();
        
        // Assert that a new channel's state is properly initialized
        assert_ne!(state_boc.compute_hash(), [0; 32], "New channel should have a non-zero state hash");
    }

    #[wasm_bindgen_test]
    fn test_transaction_processing() {
        let mut channel = Channel::new(&create_test_config()).unwrap();
        let tx_data = vec![1, 2, 3, 4];
        
        // Process transaction and verify state change
        let result = channel.process_transaction(&tx_data).unwrap();
        let state_bytes: Vec<u8> = serde_wasm_bindgen::from_value(result).unwrap();
        let mut state_boc = StateBOC::deserialize(&state_bytes).unwrap();
        
        let initial_hash = state_boc.compute_hash();
        assert_ne!(initial_hash, [0; 32], "Transaction should modify channel state");
    }

    #[wasm_bindgen_test]
    fn test_multiple_transactions() {
        let mut channel = Channel::new(&create_test_config()).unwrap();
        let tx_data = vec![1, 2, 3, 4];
        let mut previous_hash = [0; 32];

        for i in 0..3 {
            let result = channel.process_transaction(&tx_data).unwrap();
            let state_bytes: Vec<u8> = serde_wasm_bindgen::from_value(result).unwrap();
            let mut state_boc = StateBOC::deserialize(&state_bytes).unwrap();
            let current_hash = state_boc.compute_hash();
            
            // Ensure state changes with each transaction
            assert_ne!(current_hash, [0; 32], "Transaction {i} should produce valid state");
            
            if i > 0 {
                assert_ne!(
                    current_hash, 
                    previous_hash,
                    "Transaction {i} should produce different state than previous"
                );
            }
            
            previous_hash = current_hash;
        }
    }
}