use crate::bitcoin::bitcoin_types::{BitcoinLockState, HTLCParameters, StealthAddress};
use crate::bitcoin::client::BitcoinClient;
use bitcoin::Network;

#[derive(Debug)]
pub struct BitcoinRegtest {
    pub network: Network,
    pub client: BitcoinClient,
}

impl BitcoinRegtest {
    pub fn new() -> Self {
        let network = Network::Regtest;
        let client = BitcoinClient::new();

        Self { network, client }
    }

    pub fn create_htlc_parameters(
        &self,
        amount: u64,
        receiver: [u8; 20],
        hash_lock: [u8; 32],
        timeout_height: u32,
    ) -> HTLCParameters {
        self.client
            .create_htlc_parameters(amount, receiver, hash_lock, timeout_height)
    }

    pub fn create_lock_state(
        &self,
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<BitcoinLockState, String> {
        self.client.create_lock_state(
            lock_amount,
            lock_script_hash,
            lock_height,
            pubkey_hash,
            sequence,
            nonce,
            htlc_params,
            stealth_address,
        )
    }

    pub fn create_transaction(
        &self,
        prev_script: &bitcoin::ScriptBuf,
        value: u64,
        pubkey_hash: [u8; 20],
    ) -> Result<bitcoin::Transaction, String> {
        self.client
            .create_transaction(prev_script, value, pubkey_hash)
    }

    pub async fn verify_htlc(
        &self,
        state: &BitcoinLockState,
        preimage: &[u8],
    ) -> Result<bool, String> {
        self.client.verify_htlc(state, preimage).await
    }

    pub async fn cache_state(
        &self,
        state_hash: [u8; 32],
        state_data: Vec<u8>,
    ) -> Result<(), String> {
        self.client.cache_state(state_hash, state_data).await
    }

    pub async fn get_cached_state(&self, state_hash: [u8; 32]) -> Option<Vec<u8>> {
        self.client.get_cached_state(state_hash).await
    }
}
