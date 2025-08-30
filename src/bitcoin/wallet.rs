//overpass_core/src/bitcoin/wallet.rs

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Network, Script, Transaction, TxOut};
// use secp256k1::{};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bitcoin::bitcoin_types::StealthAddress;

/// Errors related to wallet and key management
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Mnemonic generation failed: {0}")]
    MnemonicError(#[from] bip39::Error),

    #[error("BIP32 derivation error: {0}")]
    Bip32Error(#[from] bitcoin::bip32::Error),

    #[error("Invalid derivation path: {0}")]
    DerivationPathError(String),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] bitcoin::secp256k1::Error),

    #[error("Invalid network: {0}")]
    NetworkError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Key format error: {0}")]
    KeyFormatError(String),

    #[error("Address error: {0}")]
    AddressError(#[from] bitcoin::address::UnknownAddressTypeError),

    #[error("Stealth address error: {0}")]
    StealthAddressError(String),

    #[error("Sighash error: {0}")]
    SighashError(#[from] bitcoin::sighash::SighashTypeParseError),

    #[error("Serialization/Deserialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("UTF-8 conversion error: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Secp256k1 error: {0}")]
    SecpError(#[from] secp256k1::Error),

    #[error("taproot error: {0}")]
    TaprootError(#[from] bitcoin::sighash::TaprootError),
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    mnemonic: String,
    xpriv: Xpriv,
    xpub: Xpub,
    network: Network,
    encryption_key: Vec<u8>,
    stealth_keys: Option<StealthKeyPair>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StealthKeyPair {
    scan_key: SecretKey,
    spend_key: SecretKey,
}

impl Wallet {
    pub fn create(network: Network) -> Result<Self, WalletError> {
        let entropy = rand::thread_rng().gen::<[u8; 32]>();
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
        let seed = mnemonic.to_seed("");
        let xpriv = Xpriv::new_master(network, &seed)?;
        let xpub = Xpub::from_priv(&bitcoin::secp256k1::Secp256k1::new(), &xpriv);
        let encryption_key = Wallet::generate_encryption_key(256);
        let stealth_keys = Wallet::generate_stealth_keys()?;

        Ok(Wallet {
            mnemonic: mnemonic.to_string(),
            xpriv,
            xpub,
            network,
            encryption_key,
            stealth_keys: Some(stealth_keys),
        })
    }

    fn generate_encryption_key(security_bits: usize) -> Vec<u8> {
        let mut rng = OsRng;
        let key_size = security_bits / 8;
        let mut key = vec![0u8; key_size];
        rng.fill_bytes(&mut key);
        key
    }

    pub fn create_hd_wallet(&self, passphrase: &str) -> Result<Wallet, WalletError> {
        let entropy = rand::thread_rng().gen::<[u8; 32]>();
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
        let seed = mnemonic.to_seed(passphrase);
        let xpriv = Xpriv::new_master(self.network, &seed)?;
        let xpub = Xpub::from_priv(&bitcoin::secp256k1::Secp256k1::new(), &xpriv);
        let stealth_keys = Wallet::generate_stealth_keys()?;

        Ok(Wallet {
            mnemonic: mnemonic.to_string(),
            xpriv,
            xpub,
            network: self.network,
            encryption_key: self.encryption_key.clone(),
            stealth_keys: Some(stealth_keys),
        })
    }

    pub fn generate_stealth_keys() -> Result<StealthKeyPair, WalletError> {
        let mut rng = OsRng;
        Ok(StealthKeyPair {
            scan_key: {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                let secret_key = SecretKey::from_slice(&bytes)?;
                secret_key
            },
            spend_key: {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                let secret_key = SecretKey::from_slice(&bytes)?;
                secret_key
            },
        })
    }

    pub fn create_stealth_address_internal(
        &self,
        wallet: &Wallet,
    ) -> Result<StealthAddress, WalletError> {
        let stealth_keys = wallet
            .stealth_keys
            .as_ref()
            .ok_or_else(|| WalletError::StealthAddressError("No stealth keys found".to_string()))?;
        let secp = Secp256k1::new();
        let scan_pubkey = PublicKey::from_secret_key(&secp, &stealth_keys.scan_key);
        let spend_pubkey = PublicKey::from_secret_key(&secp, &stealth_keys.spend_key);
        let mut nonce = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        Ok(StealthAddress::new(scan_pubkey, spend_pubkey, nonce))
    }

    pub fn encrypt_wallet_internal(&self, wallet: &Wallet) -> Result<String, WalletError> {
        let serialized_wallet = serde_json::to_string(&wallet)?;
        let encrypted_wallet = self.encrypt_data(&serialized_wallet)?;
        Ok(BASE64.encode(encrypted_wallet))
    }

    pub fn decrypt_wallet_internal(&self, encrypted_wallet: &str) -> Result<Wallet, WalletError> {
        let encrypted_data = BASE64.decode(encrypted_wallet)?;
        let decrypted_wallet = self.decrypt_data(&encrypted_data)?;
        let wallet = serde_json::from_str(&decrypted_wallet)?;
        Ok(wallet)
    }

    fn encrypt_data(&self, data: &str) -> Result<Vec<u8>, WalletError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&self.encryption_key[..12]);
        let encrypted_data = cipher
            .encrypt(nonce, data.as_bytes())
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
        Ok(encrypted_data)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<String, WalletError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&self.encryption_key[..12]);
        let decrypted_data = cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
        Ok(String::from_utf8(decrypted_data)?)
    }

    pub fn sign_transaction(
        &self,
        wallet: &Wallet,
        transaction: &mut Transaction,
        input_index: usize,
        prev_script: &Script,
        value: u64,
    ) -> Result<(), WalletError> {
        let stealth_keys = wallet
            .stealth_keys
            .as_ref()
            .ok_or_else(|| WalletError::StealthAddressError("No stealth keys found".to_string()))?;
        let mut sighash_cache = SighashCache::new(&mut *transaction);
        let sighash = sighash_cache.taproot_signature_hash(
            input_index,
            &Prevouts::All(&[TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: prev_script.into(),
            }]),
            None, // annex
            None, // leaf_hash
            TapSighashType::Default,
        )?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &stealth_keys.spend_key);
        let message = Message::from_digest_slice(sighash.as_ref())?;
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        transaction.input[input_index].witness.push(signature.as_ref().to_vec());
        Ok(())
    }
}
