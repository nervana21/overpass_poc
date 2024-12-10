// src/privacy/stealth_addresses.rs

use crate::bitcoin::bitcoin_types::StealthAddress;
use crate::error::client_errors::{SystemError, SystemErrorType};

use bitcoin::secp256k1::{All, Secp256k1, PublicKey, SecretKey, Scalar};
use sha2::{Sha256, Digest};
use rand::{thread_rng, rngs::ThreadRng};

/// A struct representing a stealth address manager.
#[derive(Clone, Debug)]
pub struct StealthAddressManager {
    curve: Secp256k1<All>,
    rng: ThreadRng,
}

impl StealthAddressManager {
    pub fn new() -> Self {
        Self {
            curve: Secp256k1::new(),
            rng: thread_rng(),
        }
    }

    pub fn generate_stealth_address(
        &mut self,
        recipient_key: &PublicKey,
    ) -> Result<StealthAddress, SystemError> {
        StealthAddressGenerator {
            curve: self.curve.clone(),
            rng: self.rng.clone(),
        }
        .generate_stealth_address(recipient_key)
    }
}

pub struct StealthAddressGenerator {
    curve: Secp256k1<All>,
    rng: ThreadRng,
}

impl StealthAddressGenerator {
    pub fn generate_stealth_address(
        &mut self,
        recipient_key: &PublicKey,
    ) -> Result<StealthAddress, SystemError> {
        // Generate ephemeral key pair
        let ephemeral_privkey = SecretKey::new(&mut self.rng);
        let ephemeral_pubkey = PublicKey::from_secret_key(&self.curve, &ephemeral_privkey);

        // Compute shared secret
        let tweak = Scalar::random();
        let shared_point = recipient_key
            .mul_tweak(&self.curve, &tweak)
            .map_err(|e| SystemError::new(SystemErrorType::CryptoError, e.to_string()))?;

        // Generate stealth address components
        let view_tag = self.generate_view_tag(&shared_point);
        let spend_key = self.derive_spend_key(&shared_point)?;

        Ok(StealthAddress::new(
            ephemeral_pubkey,
            PublicKey::from_secret_key(&self.curve, &spend_key),
            view_tag,
        ))
    }

    fn generate_view_tag(&self, shared_point: &PublicKey) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&shared_point.serialize());
        hasher.finalize().into()
    }

    fn derive_spend_key(&self, shared_point: &PublicKey) -> Result<SecretKey, SystemError> {
        let mut hasher = Sha256::new();
        hasher.update(&shared_point.serialize());

        let hash = hasher.finalize();
        SecretKey::from_slice(&hash).map_err(|e| {
            SystemError::new(SystemErrorType::CryptoError, e.to_string())
        })
    }
}
