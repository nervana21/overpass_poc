use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum HTLCState {
    Locked,
    Unlocked,
    Refunded,
}

#[wasm_bindgen]
pub struct HTLCContract {
    hash_lock: [u8; 32],
    time_lock: u64,
    amount: u64,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    state: HTLCState,
}

#[wasm_bindgen]
impl HTLCContract {
    #[wasm_bindgen(constructor)]
    pub fn new(
        hash_lock: Vec<u8>,
        time_lock: u64,
        amount: u64,
        sender: Vec<u8>,
        recipient: Vec<u8>,
    ) -> Self {
        let mut lock = [0u8; 32];
        lock.copy_from_slice(&hash_lock);

        Self {
            hash_lock: lock,
            time_lock,
            amount,
            sender,
            recipient,
            state: HTLCState::Locked,
        }
    }

    // Getters with #[wasm_bindgen(getter)] attribute
    #[wasm_bindgen(getter)]
    pub fn hash_lock(&self) -> Vec<u8> {
        self.hash_lock.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn time_lock(&self) -> u64 {
        self.time_lock
    }

    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> u64 {
        self.amount
    }

    #[wasm_bindgen(getter)]
    pub fn sender(&self) -> Vec<u8> {
        self.sender.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn recipient(&self) -> Vec<u8> {
        self.recipient.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> HTLCState {
        self.state
    }

    /// Claims the HTLC using the preimage.
    #[wasm_bindgen]
    pub fn claim(&mut self, preimage: Vec<u8>) -> Result<(), JsValue> {
        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let hash = hasher.finalize();

        if hash.as_slice() != self.hash_lock {
            return Err(JsValue::from_str("Invalid preimage"));
        }

        self.state = HTLCState::Unlocked;
        Ok(())
    }

    /// Refunds the HTLC after the time lock expires.
    #[wasm_bindgen]
    pub fn refund(&mut self, current_time: u64) -> Result<(), JsValue> {
        if current_time < self.time_lock {
            return Err(JsValue::from_str("Time lock not expired"));
        }

        self.state = HTLCState::Refunded;
        Ok(())
    }
}
