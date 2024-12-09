use thiserror::Error;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use anyhow::Result;
use crate::error::client_errors::SystemError;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::Txid;
use crate::error::client_errors::SystemErrorType as SEType;

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Insufficient funds for the transaction")]
    InsufficientFunds,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

/// A Bitcoin client connected to a local regtest node via RPC.
#[derive(Debug, Clone)]
pub struct BitcoinClient {
    rpc: Arc<Client>,
}

impl BitcoinClient {
    pub fn new(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Result<Self> {
        let auth = Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string());
        let rpc_client = Client::new(rpc_url, auth)
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()))?;
        Ok(Self {
            rpc: Arc::new(rpc_client),
        })
    }

    pub fn rpc_client(&self) -> &Client {
        &self.rpc
    }

    pub fn get_block_count(&self) -> Result<u64> {
        self.rpc_client()
            .get_block_count()
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()).into())
    }

    pub fn generate_blocks(&self, num_blocks: u64, address: &str) -> Result<Vec<bitcoin::BlockHash>> {
        use std::str::FromStr;
        let addr = bitcoin::Address::from_str(address)
            .map_err(|e| SystemError::new(SEType::InvalidInput, e.to_string()))?;
        self.rpc_client()
            .generate_to_address(num_blocks, &addr.assume_checked())
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()).into())
    }

    pub fn get_new_address(&self) -> Result<bitcoin::Address> {
        self.rpc_client()
            .get_new_address(None, None)
            .map(|addr| addr.assume_checked())
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()).into())
    }

    pub fn get_balance(&self) -> Result<u64> {
        let balance = self.rpc_client()
            .get_balance(None, None)
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()))?;
        Ok(balance.to_sat())
    }

    pub fn send_raw_transaction_hex(&self, raw_tx_hex: &str) -> Result<Txid> {
        let raw_bytes = hex::decode(raw_tx_hex)
            .map_err(|e| SystemError::new(SEType::SerializationError, e.to_string()))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&raw_bytes)
            .map_err(|e| SystemError::new(SEType::DeserializationFailed, e.to_string()))?;
        let txid = self.rpc_client()
            .send_raw_transaction(&tx)
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()))?;
        Ok(txid)
    }

    pub fn get_spendable_utxo(&self, amount: u64) -> Result<(bitcoin::OutPoint, Vec<u8>)> {
        let unspent = self.rpc_client()
            .list_unspent(None, None, None, None, None)
            .map_err(|e| SystemError::new(SEType::RemoteError, e.to_string()))?;

        for u in unspent {
            if u.amount.to_sat() > amount {
                let txid = u.txid;
                let vout = u.vout;
                let outpoint = bitcoin::OutPoint { txid, vout };
                let script_pubkey = u.script_pub_key.as_bytes().to_vec();
                return Ok((outpoint, script_pubkey));
            }
        }
        Err(SystemError::new(SEType::InvalidInput, "No suitable UTXO found".to_owned()).into())
    }

    pub fn sign_raw_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let raw_bytes = hex::decode(raw_tx_hex)
            .map_err(|e| SystemError::new(SEType::SerializationError, e.to_string()))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&raw_bytes)
            .map_err(|e| SystemError::new(SEType::DeserializationFailed, e.to_string()))?;

        let signed = self.rpc_client()
            .sign_raw_transaction_with_wallet(&tx, None, None)
            .map_err(|e| SystemError::new(SEType::RpcError, e.to_string()))?;

        if signed.complete {
            Ok(hex::encode(bitcoin::consensus::encode::serialize(&signed.hex)))
        } else {
            Err(SystemError::new(SEType::RpcError, "Transaction signing incomplete".to_owned()).into())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoincore_rpc::{Auth, Client};

    #[test]
    fn test_rpc_client() -> Result<()> {
        let rpc_client = Client::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        )?;
        let block_count = rpc_client.get_block_count()?;
        println!("Current block count: {}", block_count);
        assert!(block_count > 0);

        Ok(())
    }

    #[test]
    fn test_rpc_client_with_custom_url() -> Result<()> {
        let rpc_client = Client::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        )?;
        let block_count = rpc_client.get_block_count()?;
        println!("Current block count: {}", block_count);
        assert!(block_count > 0);

        Ok(())
    }

    #[test]
    fn test_rpc_client_with_invalid_url() -> Result<()> {
        let result = Client::new(
            "http://127.0.0.1:18444",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        )?;
        let block_count = result.get_block_count();
        assert!(block_count.is_err());

        Ok(())
    }
    #[test]
    fn test_rpc_client_with_invalid_credentials() -> Result<()> {
        let result = Client::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword1".to_string())
        )?;
        let block_count = result.get_block_count();
        assert!(block_count.is_err());

        Ok(())
    }





    #[test]
    fn test_rpc_client_with_valid_credentials() -> Result<()> {
        let rpc_client = Client::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        )?;
        let block_count = rpc_client.get_block_count()?;
        println!("Current block count: {}", block_count);
        assert!(block_count > 0);

        Ok(())
    }

    #[test]
    fn test_rpc_client_with_custom_url_and_credentials() -> Result<()> {
        let rpc_client = Client::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        )?;
        let block_count = rpc_client.get_block_count()?;
        println!("Current block count: {}", block_count);
        assert!(block_count > 0);

        Ok(())
    }

    #[test]
    fn test_rpc_client_with_custom_url_and_credentials2() -> Result<()> {
        let rpc_client = Client::new(
            "http://127.0.0.1:18443",
            Auth::UserPass("rpcuser".to_string(), "rpcpassword".to_string())
        )?;
        let block_count = rpc_client.get_block_count()?;
        println!("Current block count: {}", block_count);
        assert!(block_count > 0);

        Ok(())
    }

}