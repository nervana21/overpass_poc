use wasm_bindgen::prelude::*;

use crate::types::state_boc::StateBOC;

#[wasm_bindgen]
pub struct WalletContract {
    balance: u64,
    nonce: u64,
    owner: Vec<u8>,
    state_boc: StateBOC,
}

#[wasm_bindgen]
impl WalletContract {
    #[wasm_bindgen(constructor)]
    pub fn new(owner: Vec<u8>, initial_balance: u64) -> Self {
        Self { balance: initial_balance, nonce: 0, owner, state_boc: StateBOC::new() }
    }

    #[wasm_bindgen(getter)]
    pub fn balance(&self) -> u64 { self.balance }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u64 { self.nonce }

    #[wasm_bindgen(getter)]
    pub fn owner(&self) -> Vec<u8> { self.owner.clone() }

    pub fn transfer(&mut self, _recipient: Vec<u8>, amount: u64) -> Result<JsValue, JsValue> {
        if self.balance < amount {
            return Err(JsValue::from_str("Insufficient balance"));
        }

        self.balance -= amount;
        self.nonce += 1;

        Ok(JsValue::from_str("Transfer successful"))
    }

    pub fn get_state(&self) -> Result<JsValue, JsValue> {
        let state = self.state_boc.serialize().map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(JsValue::from(js_sys::Uint8Array::from(&state[..])))
    }
}
