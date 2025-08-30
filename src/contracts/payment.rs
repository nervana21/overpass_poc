use anyhow::Result;

use crate::types::state_boc::StateBOC;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PaymentChannelContract {
    balances: [u64; 2],
    nonce: u64,
    state_boc: StateBOC,
}

impl PaymentChannelContract {
    pub fn new(_alice: &[u8], _bob: &[u8], initial_balance: u64) -> Self {
        Self { balances: [initial_balance, initial_balance], nonce: 0, state_boc: StateBOC::new() }
    }

    pub fn transfer(&mut self, from_index: usize, to_index: usize, amount: u64) -> Result<()> {
        if from_index >= 2 || to_index >= 2 {
            return Err(anyhow::anyhow!("Invalid participant index"));
        }

        if self.balances[from_index] < amount {
            return Err(anyhow::anyhow!("Insufficient balance"));
        }

        self.balances[from_index] -= amount;
        self.balances[to_index] += amount;
        self.nonce += 1;

        // Update state
        self.state_boc.update_balances(&self.balances);

        Ok(())
    }

    pub fn settle(&self) -> Result<Vec<u8>> { self.state_boc.serialize() }

    pub fn get_balances(&self) -> &[u64; 2] { &self.balances }

    pub fn get_nonce(&self) -> u64 { self.nonce }
}
