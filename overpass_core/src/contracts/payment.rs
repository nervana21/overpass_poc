use crate::types::state_boc::StateBOC;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PaymentChannelContract {
    balances: [u64; 2],
    nonce: u64,
    state_boc: StateBOC,
}

#[wasm_bindgen]
impl PaymentChannelContract {
    #[wasm_bindgen(constructor)]
    pub fn new(_alice: Vec<u8>, _bob: Vec<u8>, initial_balance: u64) -> Self {
        Self {
            balances: [initial_balance, initial_balance],
            nonce: 0,
            state_boc: StateBOC::new(),
        }
    }

    #[wasm_bindgen]
    pub fn transfer(
        &mut self,
        from_index: usize,
        to_index: usize,
        amount: u64,
    ) -> Result<(), JsValue> {
        if from_index >= 2 || to_index >= 2 {
            return Err(JsValue::from_str("Invalid participant index"));
        }

        if self.balances[from_index] < amount {
            return Err(JsValue::from_str("Insufficient balance"));
        }

        self.balances[from_index] -= amount;
        self.balances[to_index] += amount;
        self.nonce += 1;

        // Update state
        self.state_boc.update_balances(&self.balances);

        Ok(())
    }

    #[wasm_bindgen]
    pub fn settle(&self) -> Result<JsValue, JsValue> {
        let state = self
            .state_boc
            .serialize()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&state).unwrap())
    }
}
