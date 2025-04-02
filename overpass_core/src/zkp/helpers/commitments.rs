// src/zkp/commitments.rs

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::zkp::pedersen_parameters::PedersenParameters;

pub type Bytes32 = [u8; 32];
pub type Point = RistrettoPoint;

/// Generates a random blinding factor.
pub fn generate_random_blinding() -> Bytes32 {
    let mut rng = OsRng;
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    blinding
}

/// Computes Pedersen commitment.
pub fn pedersen_commit(
    value: [u64; 2],
    blinding: Bytes32,
    hparams: &PedersenParameters,
) -> Bytes32 {
    let total: u64 = value.iter().sum();
    let value_scalar = Scalar::from(total);
    let blinding_scalar = Scalar::from_bytes_mod_order(blinding);
    let commitment = hparams.g * value_scalar + hparams.h * blinding_scalar;
    hash_point(commitment)
}

/// Hashes a RistrettoPoint to bytes32 using SHA256.
pub fn hash_point(point: Point) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(point.compress().as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::pedersen_parameters::PedersenParameters;

    #[test]
    fn test_generate_random_blinding_length() {
        let b = generate_random_blinding();
        assert_eq!(b.len(), 32);
    }

    #[test]
    fn test_pedersen_commit_consistency() {
        let params = PedersenParameters::default();
        let value = [100, 0];
        let blinding = generate_random_blinding();

        let c1 = pedersen_commit(value.clone(), blinding, &params);
        let c2 = pedersen_commit(value, blinding, &params);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_hash_point_output_length() {
        let point = RistrettoPoint::default();
        let hash = hash_point(point);
        assert_eq!(hash.len(), 32);
    }
}
