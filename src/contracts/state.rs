// src/contracts/state.rs

use anyhow::Result;

use crate::types::dag_boc::DAGBOC;
use crate::types::ops::OpCode;
use crate::types::state_boc::StateBOC;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct StateContract {
    merkle_root: [u8; 32],
    nonce: u64,
    state_boc: StateBOC,
    dag_boc: DAGBOC,
}

impl StateContract {
    pub fn new() -> Self {
        Self {
            merkle_root: [0u8; 32],
            nonce: 0,
            state_boc: StateBOC::new(),
            dag_boc: DAGBOC::new(),
        }
    }

    pub fn update_state(&mut self, op_code: OpCode, _data: &[u8]) -> Result<String> {
        self.dag_boc.process_op_code(op_code)?;

        let cells = self.dag_boc.get_state_cells();
        self.state_boc.set_state_cells(cells.concat());
        self.merkle_root = self.state_boc.compute_hash();
        self.nonce += 1;

        Ok("State updated successfully".to_string())
    }

    pub fn verify_state(&self, state_bytes: &[u8]) -> Result<bool> {
        let submitted_state = StateBOC::deserialize(state_bytes)?;

        let current_hash = self.state_boc.compute_hash();
        let submitted_hash = submitted_state.compute_hash();

        Ok(current_hash == submitted_hash)
    }

    pub fn get_merkle_root(&self) -> &[u8; 32] { &self.merkle_root }

    pub fn get_nonce(&self) -> u64 { self.nonce }

    pub fn get_state(&self) -> Result<Vec<u8>> { self.state_boc.serialize() }

    pub fn reset_state(&mut self) {
        self.merkle_root = [0u8; 32];
        self.nonce = 0;
        self.state_boc = StateBOC::new();
        self.dag_boc = DAGBOC::new();
    }

    pub fn compute_state_hash(&self) -> [u8; 32] { self.state_boc.compute_hash() }
}

impl Default for StateContract {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_contract() {
        let contract = StateContract::new();
        assert_eq!(contract.get_nonce(), 0);
        assert_eq!(contract.get_merkle_root(), &[0u8; 32]);
    }
}
