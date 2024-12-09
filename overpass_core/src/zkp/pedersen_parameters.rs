// src/zkp/pedersen_parameters.rs

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::Digest;   
use sha2::Sha256;
use serde::{Serialize, Deserialize};

/// Core cryptographic parameters for Pedersen commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenParameters {
    /// Base generator point.
    #[serde(with = "curve25519_dalek::serde::ristretto::point")]
    pub g: RistrettoPoint,
    /// Blinding generator point.
    #[serde(with = "curve25519_dalek::serde::ristretto::point")]
    pub h: RistrettoPoint,
    /// Security parameter (e.g., 128 bits).
    pub lambda: u32,
}

impl PedersenParameters {
    /// Creates default Pedersen parameters.
    pub fn new(lambda: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"Pedersen blinding generator");
        let hash = hasher.finalize();

        Self {
            g: RISTRETTO_BASEPOINT_POINT,
            h: RistrettoPoint::from_hash(hash),
            lambda,
        }
    }
}