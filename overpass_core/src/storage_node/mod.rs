// File: overpass_wasm/src/storage/mod.rs
pub mod node;

pub use node::{NodeConfig, OverpassNode};

use wasm_bindgen::prelude::*;
use web_sys::Storage;
use serde::{Serialize, Deserialize};
use crate::types::{ChannelId, ChannelState};

#[wasm_bindgen]
pub struct ClientStorage {
    // Use browser's localStorage for testing
    storage: Storage,
}

#[wasm_bindgen]
impl ClientStorage {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<ClientStorage, JsValue> {
        // Get window.localStorage
        let window = web_sys::window().ok_or("No window found")?;
        let storage = window.local_storage()?.ok_or("No localStorage found")?;
        
        Ok(Self { storage })
    }

    pub fn save_state(&self, channel_id: &str, state: &JsValue) -> Result<(), JsValue> {
        // Deserialize from JS
        let channel_state: ChannelState = serde_wasm_bindgen::from_value(state.clone())?;
        
        // Serialize to string for storage
        let state_string = serde_json::to_string(&channel_state)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        // Store in localStorage
        self.storage.set_item(channel_id, &state_string)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(())
    }

    pub fn load_state(&self, channel_id: &str) -> Result<JsValue, JsValue> {
        // Get from localStorage
        let state_string = match self.storage.get_item(channel_id)? {
            Some(s) => s,
            None => return Ok(JsValue::NULL),
        };

        // Deserialize
        let channel_state: ChannelState = serde_json::from_str(&state_string)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        // Serialize to JS
        Ok(serde_wasm_bindgen::to_value(&channel_state)?)
    }

    pub fn list_channels(&self) -> Result<Vec<String>, JsValue> {
        let mut channels = Vec::new();
        
        // Iterate localStorage keys
        for i in 0..self.storage.length()? {
            if let Some(key) = self.storage.key(i)? {
                if key.starts_with("channel-") {
                    channels.push(key);
                }
            }
        }
        
        Ok(channels)
    }
}