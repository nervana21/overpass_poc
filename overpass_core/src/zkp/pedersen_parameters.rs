// src/zkp/pedersen_parameters.rs

use anyhow::{anyhow, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;

/// Parameters for Pedersen commitments
#[derive(Clone)]
pub struct PedersenParameters {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

// Manual Debug implementation since RistrettoPoint doesn't implement Debug
impl Debug for PedersenParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PedersenParameters")
            .field("g", &self.g.compress().to_bytes())
            .field("h", &self.h.compress().to_bytes())
            .finish()
    }
}

// Manual Serialize implementation
impl Serialize for PedersenParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serde_params = SerdePedersenParameters::from(self.clone());
        serde_params.serialize(serializer)
    }
}

// Manual Deserialize implementation
impl<'de> Deserialize<'de> for PedersenParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serde_params = SerdePedersenParameters::deserialize(deserializer)?;
        Ok(Self::from(serde_params))
    }
}

impl PedersenParameters {
    /// Creates new PedersenParameters with the given points
    pub fn new(g: RistrettoPoint, h: RistrettoPoint) -> Self {
        Self { g, h }
    }

    /// Creates parameters from compressed bytes
    pub fn from_compressed_bytes(g_bytes: [u8; 32], h_bytes: [u8; 32]) -> Result<Self> {
        let g = CompressedRistretto::from_slice(&g_bytes)?
            .decompress()
            .ok_or_else(|| anyhow!("Invalid g point bytes"))?;

        let h = CompressedRistretto::from_slice(&h_bytes)?
            .decompress()
            .ok_or_else(|| anyhow!("Invalid h point bytes"))?;

        Ok(Self { g, h })
    }
    /// Compresses the parameters to bytes
    pub fn to_compressed_bytes(&self) -> (CompressedRistretto, CompressedRistretto) {
        (self.g.compress(), self.h.compress())
    }
}

impl Default for PedersenParameters {
    fn default() -> Self {
        // Use deterministic points derived from hashing for defaults
        use sha2::{Digest, Sha512};

        let g_bytes = {
            let mut hasher = Sha512::new();
            hasher.update(b"g_point");
            let hash = hasher.finalize();
            RistrettoPoint::from_uniform_bytes(&hash.into())
        };

        let h_bytes = {
            let mut hasher = Sha512::new();
            hasher.update(b"h_point");
            let hash = hasher.finalize();
            RistrettoPoint::from_uniform_bytes(&hash.into())
        };

        Self {
            g: g_bytes,
            h: h_bytes,
        }
    }
}

/// Serializable wrapper for PedersenParameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerdePedersenParameters {
    pub g: [u8; 32],
    pub h: [u8; 32],
}

impl From<PedersenParameters> for SerdePedersenParameters {
    fn from(params: PedersenParameters) -> Self {
        Self {
            g: params.g.compress().to_bytes(),
            h: params.h.compress().to_bytes(),
        }
    }
}

impl From<SerdePedersenParameters> for PedersenParameters {
    fn from(serde_params: SerdePedersenParameters) -> Self {
        PedersenParameters::from_compressed_bytes(serde_params.g, serde_params.h)
            .expect("Invalid Pedersen parameter bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_serialization() -> Result<()> {
        let params = PedersenParameters::default();

        // Test direct serialization
        let serialized = serde_json::to_string(&params)?;
        let deserialized: PedersenParameters = serde_json::from_str(&serialized)?;

        // Compare compressed bytes
        let (orig_g, orig_h) = params.to_compressed_bytes();
        let (new_g, new_h) = deserialized.to_compressed_bytes();

        assert_eq!(orig_g.to_bytes(), new_g.to_bytes());
        assert_eq!(orig_h.to_bytes(), new_h.to_bytes());

        Ok(())
    }

    #[test]
    fn test_compressed_bytes() -> Result<()> {
        let params = PedersenParameters::default();
        let (g_compressed, h_compressed) = params.to_compressed_bytes();

        let reconstructed = PedersenParameters::from_compressed_bytes(
            g_compressed.to_bytes(),
            h_compressed.to_bytes(),
        )?;

        let (new_g, new_h) = reconstructed.to_compressed_bytes();
        assert_eq!(g_compressed.to_bytes(), new_g.to_bytes());
        assert_eq!(h_compressed.to_bytes(), new_h.to_bytes());

        Ok(())
    }

    #[test]
    fn test_default_deterministic() {
        let params1 = PedersenParameters::default();
        let params2 = PedersenParameters::default();

        let (g1, h1) = params1.to_compressed_bytes();
        let (g2, h2) = params2.to_compressed_bytes();

        assert_eq!(g1.to_bytes(), g2.to_bytes());
        assert_eq!(h1.to_bytes(), h2.to_bytes());
    }

    #[test]
    fn test_invalid_bytes() {
        let result = PedersenParameters::from_compressed_bytes([0u8; 32], [0u8; 32]);
        assert!(result.is_err());
    }
}
