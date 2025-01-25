use crate::types::dag_boc::DAGBOC;
use crate::types::ops::OpCode;
use crate::types::state_boc::StateBOC;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StateContract {
    merkle_root: [u8; 32],
    nonce: u64,
    state_boc: StateBOC,
    dag_boc: DAGBOC,
}

#[wasm_bindgen]
impl StateContract {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            merkle_root: [0u8; 32],
            nonce: 0,
            state_boc: StateBOC::new(),
            dag_boc: DAGBOC::new(),
        }
    }

    #[wasm_bindgen]
    pub fn update_state(&mut self, operation: JsValue, _data: Vec<u8>) -> Result<JsValue, JsValue> {
        let op_code: OpCode = from_value(operation)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize operation: {}", e)))?;

        self.dag_boc
            .process_op_code(op_code)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let cells = self.dag_boc.get_state_cells();
        self.state_boc.set_state_cells(cells.concat());
        self.merkle_root = self.state_boc.compute_hash();
        self.nonce += 1;

        Ok(JsValue::from_str("State updated successfully"))
    }

    #[wasm_bindgen]
    pub fn verify_state(&self, state_bytes: Vec<u8>) -> Result<bool, JsValue> {
        let submitted_state =
            StateBOC::deserialize(&state_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let current_hash = self.state_boc.compute_hash();
        let submitted_hash = submitted_state.compute_hash();

        Ok(current_hash == submitted_hash)
    }

    #[wasm_bindgen]
    pub fn get_merkle_root(&self) -> Vec<u8> {
        self.merkle_root.to_vec()
    }

    #[wasm_bindgen]
    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    #[wasm_bindgen]
    pub fn get_state(&self) -> Result<Vec<u8>, JsValue> {
        self.state_boc
            .serialize()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn reset_state(&mut self) {
        self.merkle_root = [0u8; 32];
        self.nonce = 0;
        self.state_boc = StateBOC::new();
        self.dag_boc = DAGBOC::new();
    }

    #[wasm_bindgen]
    pub fn compute_state_hash(&self) -> Vec<u8> {
        self.state_boc.compute_hash().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_contract() {
        let contract = StateContract::new();
        assert_eq!(contract.get_nonce(), 0);
        assert_eq!(contract.get_merkle_root(), vec![0u8; 32]);
    }
}

#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
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
        Self {
            balance: initial_balance,
            nonce: 0,
            owner,
            state_boc: StateBOC::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn balance(&self) -> u64 {
        self.balance
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    #[wasm_bindgen(getter)]
    pub fn owner(&self) -> Vec<u8> {
        self.owner.clone()
    }

    /// Transfers amount from this wallet to a recipient.
    pub fn transfer(&mut self, amount: u64) -> Result<(), JsValue> {
        if self.balance < amount {
            return Err(JsValue::from_str("Insufficient balance"));
        }

        self.balance -= amount;
        self.nonce += 1;

        // Update state
        self.state_boc.update_balance(self.balance);

        Ok(())
    }

    /// Retrieves the current state.
    pub fn get_state(&self) -> Result<JsValue, JsValue> {
        let state = self
            .state_boc
            .serialize()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&state).unwrap())
    }
}
