pub mod channel;
pub mod error;
pub mod storage;
pub mod types;

use crate::types::cell_builder::{Cell as CellBuilderCell, CellBuilder, CellType};
use crate::types::state_boc::{Cell as StateBOCCell, StateBOC};
use crate::types::dag_boc::DAGBOC;
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

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChannelConfig {
    pub initial_balance: u64,
    pub security_bits: usize,
    pub version: u32,
}

#[derive(Serialize, Deserialize)]
pub struct StateUpdate {
    pub nonce: u64,
}

#[wasm_bindgen]
pub struct Channel {
    state_boc: StateBOC,
    dag_boc: DAGBOC,
    nonce: u64,
}

impl Channel {
    fn initialize_cell(initial_balance: u64) -> Result<StateBOCCell, JsValue> {
        Ok(StateBOCCell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data: Vec::new(),
            references: Vec::new(),
            slice: None,
            nonce: 0,
            balance: initial_balance as i32,
        })
    }

    fn add_state_cell(&mut self, data: Vec<u8>) -> Result<(), JsValue> {
        let cell = StateBOCCell {
            cell_type: crate::types::state_boc::CellType::Ordinary,
            data,
            references: Vec::new(),
            slice: None,
            nonce: self.nonce,
            balance: 0,
        };

        self.state_boc.add_cell(cell);
        self.nonce += 1;
        Ok(())
    }

    fn serialize_state(&self) -> Result<JsValue, JsValue> {
        let state_boc_bytes = self
            .state_boc
            .serialize()
            .map_err(|e| JsValue::from_str(&format!("BOC serialization error: {}", e)))?;
        serde_wasm_bindgen::to_value(&state_boc_bytes)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))
    }

    fn handle_state_update(&mut self, payload: &[u8]) -> Result<(), JsValue> {
        let state_update: StateUpdate = bincode::deserialize(payload)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize state update: {}", e)))?;
        self.nonce = state_update.nonce;
        Ok(())
    }

    fn handle_cell_update(&mut self, payload: &[u8]) -> Result<(), JsValue> {
        let cell: CellBuilderCell = bincode::deserialize(payload)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize cell: {}", e)))?;
        self.add_state_cell(cell.data)?;
        Ok(())
    }

    fn process_data(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let mut offset = 0;

        // Header validation
        if data.len() < 4 {
            return Err(JsValue::from_str("Invalid data: too short"));
        }

        let msg_type = data[offset];
        offset += 1;

        let payload_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | (data[offset + 2] as usize);
        offset += 3;

        if data.len() < 4 + payload_len {
            return Err(JsValue::from_str("Invalid data: incomplete payload"));
        }

        let payload = &data[offset..offset + payload_len];
        match msg_type {
            0 => self.handle_state_update(payload)?,
            1 => self.handle_cell_update(payload)?,
            _ => return Err(JsValue::from_str("Invalid message type")),
        }

        Ok(())
    }
}

#[wasm_bindgen]
impl Channel {
    #[wasm_bindgen(constructor)]
    pub fn new(config_str: &str) -> Result<Channel, JsValue> {
        console_error_panic_hook::set_once();

        let config: ChannelConfig = serde_json_wasm::from_str(config_str)
            .map_err(|e| JsValue::from_str(&format!("Config parse error: {}", e)))?;

        let initial_cell = Self::initialize_cell(config.initial_balance)?;

        let mut state_boc = StateBOC::new();
        state_boc.add_cell(initial_cell);

        Ok(Channel {
            state_boc,
            dag_boc: DAGBOC::new(),
            nonce: 0,
        })
    }

    #[wasm_bindgen]
    pub fn create_wallet(&mut self, entropy: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Creating new wallet BOC structure");
        self.add_state_cell(entropy.to_vec())?;
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn update_state(&mut self, data: &[u8]) -> Result<JsValue, JsValue> {
        console_log!("Updating state");
        self.process_data(data)?;
        self.serialize_state()
    }

    #[wasm_bindgen]
    pub fn finalize_state(&mut self) -> Result<JsValue, JsValue> {
        console_log!("Finalizing state");
        let final_hash = self.state_boc.compute_hash();
        serde_wasm_bindgen::to_value(&final_hash)
            .map_err(|e| JsValue::from_str(&format!("State serialization error: {}", e)))
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
    }}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    console_log!("Overpass WASM module initialized");
}