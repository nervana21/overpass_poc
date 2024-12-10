// src/zkp/pedersen_parameters.rs

use serde_json::to_string;
use toml::to_string;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::Digest;   
use sha2::Sha256;
use bip39::serde as bip39;
use serde::{Deserialize, Serialize};


/// Core cryptographic parameters for Pedersen commitments.
#[derive(Debug, Clone)]
pub struct PedersenParameters {
    /// Base generator point.
    pub g: RistrettoPoint,
    /// Blinding generator point.
    pub h: RistrettoPoint,
    /// Security parameter (e.g., 128 bits).
    pub lambda: u32,
}

impl  Default for PedersenParameters {
    fn default() -> Self {
        Self::new(128)
    }
}   // Added Default trait implementation

impl PedersenParameters {
    /// Creates default Pedersen parameters.
    pub fn new(lambda: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"Pedersen blinding generator");
        let hash = hasher.finalize();

        Self {
            g: RISTRETTO_BASEPOINT_POINT,
            h: RistrettoPoint::hash_from_bytes::<Sha256>(hash.as_slice()),
            lambda,
        }
    }
}
// Added Serialize and Deserialize traits for PedersenParameters
#[derive(Serialize, Deserialize)]
pub struct SerdePedersenParameters {
    pub g: [u8; 32],
    pub h: [u8; 32],
    pub lambda: u32,
}

impl From<PedersenParameters> for SerdePedersenParameters {
    fn from(params: PedersenParameters) -> Self {
        SerdePedersenParameters {
            g: params.g.compress().to_bytes(),
            h: params.h.compress().to_bytes(),
            lambda: params.lambda,
        }
    }
}

impl From<SerdePedersenParameters> for PedersenParameters {
    fn from(serde_params: SerdePedersenParameters) -> Self {
        PedersenParameters {
            g: RistrettoPoint::from_compressed_bytes(&serde_params.g).unwrap(),
            h: RistrettoPoint::from_compressed_bytes(&serde_params.h).unwrap(),
            lambda: serde_params.lambda,
        }
    }
}

// Added a function to save PedersenParameters to a file
pub fn save_pedersen_parameters_to_file(params: PedersenParameters, file_path: &str) -> std::io::Result<()> {
    let serde_params: SerdePedersenParameters = params.into();
    let serialized = bip39::to_string(&serde_params).unwrap();
    std::fs::write(file_path, serialized)
}

// Added a function to load PedersenParameters from a file
pub fn load_pedersen_parameters_from_file(file_path: &str) -> std::io::Result<PedersenParameters> {
    let serialized = std::fs::read_to_string(file_path)?;
    let serde_params: SerdePedersenParameters = serde_json::from_str(&serialized)?;
    Ok(serde_params.into())
}
use toml::to_string;
#[test]
fn test_save_and_load_pedersen_parameters() {
    let params = PedersenParameters::new(128);
    let file_path = "test_pedersen_params.toml";
    save_pedersen_parameters_to_file(params, file_path).unwrap();
    let loaded_params = load_pedersen_parameters_from_file(file_path).unwrap();
    assert_eq!(params, loaded_params);
}
