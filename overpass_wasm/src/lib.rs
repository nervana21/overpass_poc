pub mod types;
pub mod error;
pub mod storage;
pub mod channel;


// Rest of WASM implementation...
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use types::cell_builder;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use crate::types::ops::{OpCode, WalletOpCode, ChannelOpCode};
use crate::types::dag_boc::DAGBOC;
use crate::types::state_boc::StateBOC;
use crate::types::cell_builder::{Cell, CellBuilder};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub struct Channel {
    config: ChannelConfig,
    state_boc: StateBOC,
    dag_boc: DAGBOC,
    nonce: u64,
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

        cell_builder.add_cell(initial_cell)
            .map_err(|e| JsValue::from_str(&format!("Cell initialization error: {}", e)))?;

        let channel = Channel {
            config,
            state_boc,
            dag_boc,
            nonce: 0,
        };

        Ok(channel)
    }
    #[wasm_bindgen]
    pub fn create_wallet(&mut self, entropy: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Creating new wallet BOC structure");

        let op = OpCode::Wallet(WalletOpCode::CreateChannel);
        let cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: entropy.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: 0,
            balance: 0,
        };

        self.state_boc.add_cell(cell);

        self.dag_boc.process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        self.nonce += 1;

        self.serialize_state()
    }
    #[wasm_bindgen]
    pub fn update_state(&mut self, amount: u64, data: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Updating state with amount: {}", amount);

        let op = OpCode::Channel(ChannelOpCode::UpdateState);
        let cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: data.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: amount,
        };

        self.state_boc.add_cell(cell);

        self.dag_boc.process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        self.nonce += 1;

        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn process_transaction(&mut self, tx_data: &[u8]) -> Result<JsValue, JsValue> {        console_log!("Processing transaction");

        let op = OpCode::Wallet(WalletOpCode::ProcessTransaction);
        let cell = crate::types::state_boc::Cell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: tx_data.to_vec(),
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: 0,
        };

        self.state_boc.add_cell(cell);

        self.dag_boc.process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        self.nonce += 1;

        self.serialize_state()
    }
    #[wasm_bindgen]
    pub fn finalize_state(&mut self) -> Result<JsValue, JsValue> {
        console_log!("Finalizing state");

        let op = OpCode::Channel(ChannelOpCode::FinalizeState);
        self.dag_boc.process_op_code(op)
            .map_err(|e| JsValue::from_str(&format!("OpCode processing error: {}", e)))?;

        let final_hash = self.state_boc.compute_hash();

        Ok(serde_wasm_bindgen::to_value(&final_hash)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))?)
    }

    #[wasm_bindgen]
    pub fn get_current_state(&self) -> Result<JsValue, JsValue> {
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn verify_state(&self, state_bytes: &[u8]) -> Result<bool, JsValue> {
        let submitted_state = StateBOC::deserialize(state_bytes)
            .map_err(|e| JsValue::from_str(&format!("State deserialization error: {}", e)))?;

        Ok(self.state_boc.compute_hash() == submitted_state.compute_hash())
    }

    fn serialize_state(&self) -> Result<JsValue, JsValue> {
        let state_boc_bytes = self.state_boc.serialize()
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