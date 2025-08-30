use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug)]
pub enum HTLCState {
    Locked,
    Unlocked,
    Refunded,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HTLCContract {
    hash_lock: [u8; 32],
    time_lock: u64,
    amount: u64,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    state: HTLCState,
}

impl HTLCContract {
    pub fn new(
        hash_lock: &[u8],
        time_lock: u64,
        amount: u64,
        sender: Vec<u8>,
        recipient: Vec<u8>,
    ) -> Result<Self> {
        if hash_lock.len() != 32 {
            return Err(anyhow::anyhow!("Hash lock must be exactly 32 bytes"));
        }

        let mut lock = [0u8; 32];
        lock.copy_from_slice(hash_lock);

        Ok(Self { hash_lock: lock, time_lock, amount, sender, recipient, state: HTLCState::Locked })
    }

    // Getters
    pub fn hash_lock(&self) -> &[u8; 32] { &self.hash_lock }

    pub fn time_lock(&self) -> u64 { self.time_lock }

    pub fn amount(&self) -> u64 { self.amount }

    pub fn sender(&self) -> &[u8] { &self.sender }

    pub fn recipient(&self) -> &[u8] { &self.recipient }

    pub fn state(&self) -> HTLCState { self.state }

    /// Claims the HTLC using the preimage.
    pub fn claim(&mut self, preimage: &[u8]) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        let hash = hasher.finalize();

        if hash.as_slice() != self.hash_lock {
            return Err(anyhow::anyhow!("Invalid preimage"));
        }

        self.state = HTLCState::Unlocked;
        Ok(())
    }

    /// Refunds the HTLC after the time lock expires.
    pub fn refund(&mut self, current_time: u64) -> Result<()> {
        if current_time < self.time_lock {
            return Err(anyhow::anyhow!("Time lock not expired"));
        }

        self.state = HTLCState::Refunded;
        Ok(())
    }
}
