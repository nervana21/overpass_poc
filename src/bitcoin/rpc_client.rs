use std::sync::Arc;

use bitcoin::{Amount, Network, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("JSON-RPC error: {0}")]
    JsonRpcError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Bitcoin Core RPC error: {0}")]
    BitcoinCoreError(#[from] bitcoincore_rpc::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub network: Network,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 { 30 }

impl Default for BitcoinRpcConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8332".to_string(),
            user: "".to_string(),
            password: "".to_string(),
            network: Network::Bitcoin,
            timeout_seconds: default_timeout(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BitcoinRpcClient {
    pub config: BitcoinRpcConfig,
    pub inner: Arc<bitcoincore_rpc::Client>,
}

impl BitcoinRpcClient {
    /// Creates a new instance of `BitcoinRpcClient`.
    pub fn new(config: BitcoinRpcConfig) -> Result<Self, RpcError> {
        let client = bitcoincore_rpc::Client::new(
            &config.url,
            bitcoincore_rpc::Auth::UserPass(config.user.clone(), config.password.clone()),
        )
        .map_err(RpcError::BitcoinCoreError)?;
        Ok(Self { inner: Arc::new(client), config })
    }

    /// Gets the current block count from the Bitcoin network.
    pub async fn get_block_count(&self) -> Result<u64, RpcError> {
        Ok(self.inner.get_block_count().map_err(RpcError::BitcoinCoreError)?)
    }

    /// Retrieves a raw transaction by its TxID.
    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, RpcError> {
        self.inner.get_raw_transaction(txid, None).map_err(RpcError::BitcoinCoreError)
    }

    /// Sends a raw transaction to the Bitcoin network.
    pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
        self.inner.send_raw_transaction(tx).map_err(RpcError::BitcoinCoreError)
    }

    /// Gets the current balance of the wallet.
    pub async fn get_balance(&self) -> Result<Amount, RpcError> {
        self.inner.get_balance(None, None).map_err(RpcError::BitcoinCoreError)
    }
}
