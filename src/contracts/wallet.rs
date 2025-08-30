use anyhow::Result;

use crate::types::state_boc::StateBOC;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct WalletContract {
    balance: u64,
    nonce: u64,
    owner: Vec<u8>,
    state_boc: StateBOC,
}

impl WalletContract {
    pub fn new(owner: Vec<u8>, initial_balance: u64) -> Self {
        Self { balance: initial_balance, nonce: 0, owner, state_boc: StateBOC::new() }
    }

    pub fn balance(&self) -> u64 { self.balance }

    pub fn nonce(&self) -> u64 { self.nonce }

    pub fn owner(&self) -> &[u8] { &self.owner }

    pub fn transfer(&mut self, _recipient: &[u8], amount: u64) -> Result<String> {
        if self.balance < amount {
            return Err(anyhow::anyhow!("Insufficient balance"));
        }

        self.balance -= amount;
        self.nonce += 1;

        Ok("Transfer successful".to_string())
    }

    pub fn get_state(&self) -> Result<Vec<u8>> { self.state_boc.serialize() }
}
