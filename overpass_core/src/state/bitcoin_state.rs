use std::sync::RwLock;
use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use serde::{Serialize, Deserialize};
use bitcoin::hashes::HashEngine;
use std::sync::Arc;
use crate::bitcoin::bitcoin_types::StealthAddress;
use crate::bitcoin::bitcoin_types::HTLCParameters;
use std::collections::HashMap;
use crate::error::client_errors::{SystemError, SystemErrorType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinState {
    pub lock_amount: u64,
    pub lock_script_hash: [u8; 32],
    pub lock_height: u64,
    pub pubkey_hash: [u8; 20],
    pub sequence: u32,
    pub nonce: u64,
    pub htlc_params: Option<HTLCParameters>,
    pub stealth_address: Option<StealthAddress>,
}

impl Default for BitcoinState {
    fn default() -> Self {
        Self {
            lock_amount: 0,
            lock_script_hash: [0; 32],
            lock_height: 0,
            pubkey_hash: [0; 20],
            sequence: 0,
            nonce: 0,
            htlc_params: None,
            stealth_address: None,
        }
    }
}
impl BitcoinState {
    pub fn new(
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<Self, SystemError> {
        if let Some(params) = &htlc_params {
            if lock_amount < params.amount {
                return Err(SystemError::new(
                    SystemErrorType::InvalidAmount,
                    "Lock amount is less than HTLC requirement".to_string(),
                ));
            }
        }
        Ok(Self {
            lock_amount,
            lock_script_hash,
            lock_height,
            pubkey_hash,
            sequence,
            nonce,
            htlc_params,
            stealth_address,
        })
    }

    pub fn verify_timelock(&self, current_height: u32) -> bool {
        u64::from(current_height) >= self.lock_height
    }

    pub fn verify_hashlock(&self, preimage: &[u8], current_height: u32) -> Result<bool, SystemError> {
        if let Some(params) = &self.htlc_params {
            if !params.verify_timelock(current_height) {
                return Ok(false);
            }
            let hash = sha256d::Hash::hash(preimage);
            Ok(hash.to_byte_array() == params.hash_lock)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinLockState {
    pub lock_amount: u64,
    pub lock_script_hash: [u8; 32],
    pub lock_height: u64,
    pub pubkey_hash: [u8; 20],
    pub sequence: u32,
    pub nonce: u64,
    pub htlc_params: Option<HTLCParameters>,
    pub stealth_address: Option<StealthAddress>,
    #[serde(skip)]
    state_cache: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl BitcoinLockState {
    pub fn new(
        lock_amount: u64,
        lock_script_hash: [u8; 32],
        lock_height: u64,
        pubkey_hash: [u8; 20],
        sequence: u32,
        nonce: u64,
        htlc_params: Option<HTLCParameters>,
        stealth_address: Option<StealthAddress>,
    ) -> Result<Self, SystemError> {
        if let Some(params) = &htlc_params {
            if lock_amount < params.amount {
                return Err(SystemError::new(
                    SystemErrorType::InvalidAmount,
                    "Lock amount is less than HTLC requirement".to_string(),
                ));
            }
        }

        Ok(Self {
            lock_amount,
            lock_script_hash,
            lock_height,
            pubkey_hash,
            sequence,
            nonce,
            htlc_params,
            stealth_address,
            state_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn compute_state_hash(&self) -> Result<[u8; 32], SystemError> {
        let mut engine = sha256d::Hash::engine();
        engine.input(&self.lock_amount.to_le_bytes());
        engine.input(&self.lock_script_hash);
        engine.input(&self.lock_height.to_le_bytes());
        engine.input(&self.pubkey_hash);
        engine.input(&self.sequence.to_le_bytes());
        engine.input(&self.nonce.to_le_bytes());
        
        if let Some(htlc) = &self.htlc_params {
            let htlc_bytes = serde_json::to_vec(htlc)
                .map_err(|e| SystemError::new(SystemErrorType::SerializationError, e.to_string()))?;
            engine.input(&htlc_bytes);
        }
        
        Ok(*sha256d::Hash::from_engine(engine).as_byte_array())
    }

    pub async fn verify_state_transition(
        &self,
        next_state: &BitcoinLockState,
    ) -> Result<bool, SystemError> {
        if next_state.lock_height <= self.lock_height {
            return Ok(false);
        }

        if let Some(htlc) = &self.htlc_params {
            if !htlc.verify_timelock(next_state.lock_height as u32) {
                return Ok(false);
            }
        }

        if next_state.nonce <= self.nonce {
            return Ok(false);
        }

        let current_hash = self.compute_state_hash().await?;
        let next_hash = next_state.compute_state_hash().await?;

        if current_hash == next_hash {
            return Ok(false);
        }

        let mut cache = self.state_cache.write().unwrap();
        cache.insert(
            next_hash,
            serde_json::to_vec(next_state)
                .map_err(|e| SystemError::new(SystemErrorType::SerializationError, e.to_string()))?,
        );

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{bitcoin_transaction::BitcoinClient, bitcoin_types::OpReturnMetadata, client};
    use bitcoin::hashes::{sha256, Hash};

    #[test]
    fn test_create_htlc_parameters() {
        let client = BitcoinClient::new();
        let htlc = client.create_htlc_parameters(
            1_000_000,
            [1u8; 20],
            sha256::Hash::hash(&[0u8; 32]).to_byte_array(),
            144,
        );

        assert_eq!(htlc.amount, 1_000_000);
        assert_eq!(htlc.timeout_height, 144);
        assert_eq!(htlc.receiver, [1u8; 20]);
    }

    #[test]
    fn test_create_op_return_script() {
        let _client = BitcoinClient::new();
        let metadata = OpReturnMetadata::new(
            [0u8; 32],
            1,
            sha256::Hash::hash(&[0u8; 32]).to_byte_array(),
            vec![1, 2, 3],
            None,
            1,
            [0u8; 32],
        );

    }

    #[tokio::test]
    async fn test_verify_htlc() {
        let client = BitcoinClient::new();
        let preimage = [0u8; 32];
        let hash_lock = sha256::Hash::hash(&preimage).to_byte_array();

        let state = BitcoinState::new(
            1_000_000,
            [0u8; 32],
            100,
            [1u8; 20],
            0,
            0,
            Some(HTLCParameters {
                amount: 1_000_000,
                receiver: [1u8; 20],
                hash_lock,
                timeout_height: 144,
            }),
            None,
        ).unwrap();

        let valid = state.verify_hashlock(&preimage, 101).unwrap();
        assert!(valid);
    }
}