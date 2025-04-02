// src/zkp/bitcoin_ephemeral_state.rs

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::consensus::encode;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, PublicKey, ScriptBuf};
use bitcoincore_rpc::{Auth, Client, RpcApi};

/// Represents a simple Bitcoin client for testing purposes.
pub struct BitcoinClient {
    rpc: Client,
    utxos: HashMap<String, (TxOut, bitcoin::OutPoint)>, // Keyed by txid
    secp: Secp256k1<All>,
    network: Network,
}

impl BitcoinClient {
    /// Creates a new Bitcoin client.
    pub fn new(
        rpc_url: &str,
        rpc_user: &str,
        rpc_password: &str,
        network: Network,
    ) -> Result<Self> {
        // Initialize the RPC client with credentials.
        let auth = Auth::UserPass(rpc_user.to_string(), rpc_password.to_string());
        let rpc = Client::new(rpc_url, auth)
            .context("Failed to create RPC client. Check RPC URL and credentials.")?;

        Ok(Self { rpc, utxos: HashMap::new(), secp: Secp256k1::new(), network })
    }

    /// Retrieves a new Bitcoin address.
    pub fn get_new_address(&self) -> Result<Address> {
        let address = self.rpc.get_new_address(None, None).context("Failed to get new address")?;
        Ok(address.assume_checked())
    }

    /// Generates a specified number of blocks to the given address (Regtest only).
    pub fn generate_blocks(&self, count: u32, address: &str) -> Result<()> {
        let addr = Address::from_str(address).context("Invalid Bitcoin address")?.assume_checked();
        self.rpc.generate_to_address(count.into(), &addr).context("Failed to generate blocks")?;
        Ok(())
    }

    /// Returns the total wallet balance in satoshis, including confirmed and unconfirmed UTXOs.
    /// This function reflects the wallet's complete spendable balance (excluding locked or immature funds).
    pub fn get_balance(&self) -> Result<u64> {
        let balance = self.rpc.get_balance(None, None).context("Failed to get balance")?;
        Ok(balance.to_sat())
    }

    /// Retrieves a spendable UTXO with the specified amount.
    pub fn get_spendable_utxo(&mut self, amount: u64) -> Result<(bitcoin::OutPoint, TxOut)> {
        // Refresh UTXO set
        self.refresh_utxos()?;

        // Find a UTXO with sufficient amount
        for (_, (tx_out, outpoint)) in &self.utxos {
            if tx_out.value >= Amount::from_sat(amount) {
                return Ok((*outpoint, tx_out.clone()));
            }
        }

        Err(anyhow!("No spendable UTXO found with the specified amount"))
    }

    /// Refreshes the UTXO set by fetching from the RPC.
    fn refresh_utxos(&mut self) -> Result<()> {
        self.utxos.clear();
        let utxos = self
            .rpc
            .list_unspent(None, None, None, None, None)
            .context("Failed to list unspent transactions")?;
        for utxo in utxos {
            let txid = utxo.txid.to_string();
            let tx_out = TxOut { value: utxo.amount, script_pubkey: utxo.script_pub_key };
            let outpoint = OutPoint { txid: utxo.txid, vout: utxo.vout };
            self.utxos.insert(txid, (tx_out, outpoint));
        }
        Ok(())
    }

    /// Signs a raw transaction hex.
    pub fn sign_raw_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let tx_bytes = hex::decode(raw_tx_hex).context("Failed to decode raw transaction hex")?;
        let tx: Transaction =
            encode::deserialize(&tx_bytes).context("Failed to deserialize transaction")?;

        let signed_tx = self
            .rpc
            .sign_raw_transaction_with_wallet(&tx, None, None)
            .context("Failed to sign transaction")?;

        let signed_tx_hex = hex::encode(signed_tx.hex);
        Ok(signed_tx_hex)
    }

    /// Sends a raw transaction given its hex representation.
    pub fn send_raw_transaction_hex(&self, raw_tx_hex: &str) -> Result<String> {
        let tx =
            self.rpc.send_raw_transaction(raw_tx_hex).context("Failed to send raw transaction")?;
        Ok(tx.to_string())
    }

    /// Creates a P2PKH script for demonstration purposes.
    pub fn create_p2pkh_script(&self, public_key: &PublicKey) -> ScriptBuf {
        Builder::new()
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_DUP)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_HASH160)
            .push_slice(&public_key.pubkey_hash())
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    /// Generates a key pair for signing transactions.
    pub fn generate_keypair(&self, secret_key: &SecretKey) -> PublicKey {
        PublicKey::from_private_key(
            &self.secp,
            &bitcoin::PrivateKey::from_slice(&secret_key[..], self.network).unwrap(),
        )
    }

    /// Creates or loads a wallet with the given name
    pub fn create_wallet(&self, wallet_name: &str) -> Result<()> {
        self.rpc
            .create_wallet(wallet_name, None, None, None, None)
            .context("Failed to create wallet via RPC")?;
        Ok(())
    }
}
