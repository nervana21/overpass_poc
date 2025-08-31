// src/zkp/helpers/merkle.rs

use std::collections::HashMap;

use sha2::{Digest, Sha256};

pub type Bytes32 = [u8; 32];

/// Computes the Merkle root from wallet roots.
pub fn compute_global_root(wallet_roots: &HashMap<Bytes32, Bytes32>) -> Result<Bytes32, String> {
    let leaves: Vec<Bytes32> = wallet_roots.values().cloned().collect();
    Ok(compute_merkle_root(leaves))
}

/// Computes the Merkle root from channel state.
pub fn compute_channel_root(channel_id: Bytes32, commitment: Bytes32, nonce: u64) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(channel_id);
    hasher.update(commitment);
    hasher.update(nonce.to_le_bytes());
    let result = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&result);
    root
}

/// Computes Merkle root from a list of leaves.
pub fn compute_merkle_root(mut leaves: Vec<Bytes32>) -> Bytes32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 != 0 {
            leaves.push(*leaves.last().unwrap());
        }
        leaves = leaves.chunks(2).map(|pair| hash_pair(pair[0], pair[1])).collect();
    }
    leaves[0]
}

/// Computes the global Merkle root from a sorted slice of leaves.
pub fn compute_global_root_from_sorted(sorted_hashes: &[Bytes32]) -> Bytes32 {
    if sorted_hashes.is_empty() {
        return [0u8; 32];
    }
    let mut current_level = sorted_hashes.to_vec();
    while current_level.len() > 1 {
        if current_level.len() % 2 != 0 {
            current_level.push(*current_level.last().unwrap());
        }
        current_level = current_level.chunks(2).map(|pair| hash_pair(pair[0], pair[1])).collect();
    }
    current_level[0]
}

/// Hashes two bytes32 together to form parent node.
pub fn hash_pair(left: Bytes32, right: Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&result);
    parent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_merkle_root_determinism() {
        let leaves = vec![[1u8; 32], [2u8; 32]];
        let root1 = compute_merkle_root(leaves.clone());
        let root2 = compute_merkle_root(leaves);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_merkle_root_empty() {
        let root = compute_merkle_root(vec![]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_hash_pair_inequality() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(hash_pair(a, b), hash_pair(b, a));
    }
}
