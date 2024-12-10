// src/zkp/tree.rs

use crate::zkp::helpers::Bytes32;
use std::fmt;
use std::error::Error;
use sha2::{Digest, Sha256};

/// Represents errors that can occur in the Merkle Tree operations.
#[derive(Debug)]
pub enum MerkleTreeError {
    InvalidInput(String),
    ProofGenerationFailed(String),
    ProofVerificationFailed(String),
    // Add other relevant error variants as needed
}

impl fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleTreeError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            MerkleTreeError::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            MerkleTreeError::ProofVerificationFailed(msg) => write!(f, "Proof verification failed: {}", msg),
        }
    }
}

impl Error for MerkleTreeError {}

/// Represents a simple Merkle Tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<Bytes32>,
    pub root: Bytes32,
    pub tree: Vec<Vec<Bytes32>>, // Level 0: leaves, Level n: root
}

impl MerkleTree {
    /// Creates a new empty Merkle Tree.
    pub fn new() -> Self {
        let leaves = Vec::new();
        let root = [0u8; 32];
        let tree = Vec::new();
        Self { leaves, root, tree }
    }

    /// Inserts a new leaf and updates the tree incrementally.
    pub fn insert(&mut self, leaf: Bytes32) -> Result<(), MerkleTreeError> {
        self.leaves.push(leaf);
        self.update_tree_on_insert()
    }

    /// Updates a leaf at a given position and recomputes the tree.
    pub fn update(&mut self, old_leaf: Bytes32, new_leaf: Bytes32) -> Result<(), MerkleTreeError> {
        if let Some(pos) = self.leaves.iter().position(|x| x == &old_leaf) {
            self.leaves[pos] = new_leaf;
            self.update_tree_on_update(pos)
        } else {
            Err(MerkleTreeError::InvalidInput("Old leaf not found".to_string()))
        }
    }

    /// Deletes a leaf and updates the tree incrementally.
    pub fn delete(&mut self, leaf: Bytes32) -> Result<(), MerkleTreeError> {
        if let Some(pos) = self.leaves.iter().position(|x| x == &leaf) {
            self.leaves.remove(pos);
            self.update_tree_on_delete(pos)
        } else {
            Err(MerkleTreeError::InvalidInput("Leaf to delete not found".to_string()))
        }
    }

    /// Recomputes the entire tree. Use for initial construction or drastic changes.
    #[allow(dead_code)]
    fn recompute_tree(&mut self) {
        if self.leaves.is_empty() {
            self.root = [0u8; 32];
            self.tree = Vec::new();
            return;
        }
        let mut current_level = self.leaves.clone();
        self.tree = vec![current_level.clone()];
        while current_level.len() > 1 {
            if current_level.len() % 2 != 0 {
                current_level.push(*current_level.last().unwrap());
            }
            current_level = current_level.chunks(2).map(|pair| hash_pair(pair[0], pair[1])).collect();
            self.tree.push(current_level.clone());
        }
        self.root = current_level[0];
    }
    /// Incrementally updates the tree upon inserting a new leaf.
    fn update_tree_on_insert(&mut self) -> Result<(), MerkleTreeError> {
        let mut level = self.tree.len();
        if level == 0 {
            self.tree.push(self.leaves.clone());
            level = 1;
        } else {
            self.tree[0] = self.leaves.clone();
        }

        let mut pos = self.leaves.len() - 1;
        while level < self.tree.len() || self.tree[level-1].len() > 1 {
            let current_level = &self.tree[level-1];
            let mut next_level = if level < self.tree.len() {
                self.tree[level].clone()
            } else {
                Vec::new()
            };

            let parent_pos = pos / 2;
            let sibling_pos = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            
            let hash = if sibling_pos < current_level.len() {
                if pos % 2 == 0 {
                    hash_pair(current_level[pos], current_level[sibling_pos])
                } else {
                    hash_pair(current_level[sibling_pos], current_level[pos])
                }
            } else {
                current_level[pos]
            };

            if parent_pos >= next_level.len() {
                next_level.push(hash);
            } else {
                next_level[parent_pos] = hash;
            }

            if level >= self.tree.len() {
                self.tree.push(next_level);
            } else {
                self.tree[level] = next_level;
            }

            pos = parent_pos;
            level += 1;
        }

        self.root = self.tree.last().unwrap()[0];
        Ok(())
    }

    /// Incrementally updates the tree upon updating a leaf.
    fn update_tree_on_update(&mut self, pos: usize) -> Result<(), MerkleTreeError> {
        if self.tree.is_empty() {
            return Ok(());
        }

        let mut current_pos = pos;
        self.tree[0] = self.leaves.clone();

        for level in 0..self.tree.len()-1 {
            let current_level = &self.tree[level];
            let sibling_pos = if current_pos % 2 == 0 { current_pos + 1 } else { current_pos - 1 };
            let parent_pos = current_pos / 2;

            let hash = if sibling_pos < current_level.len() {
                if current_pos % 2 == 0 {
                    hash_pair(current_level[current_pos], current_level[sibling_pos])
                } else {
                    hash_pair(current_level[sibling_pos], current_level[current_pos])
                }
            } else {
                current_level[current_pos]
            };

            self.tree[level + 1][parent_pos] = hash;
            current_pos = parent_pos;
        }

        self.root = self.tree.last().unwrap()[0];
        Ok(())
    }

    /// Incrementally updates the tree upon deleting a leaf.
    fn update_tree_on_delete(&mut self, _pos: usize) -> Result<(), MerkleTreeError> {
        if self.leaves.is_empty() {
            self.tree.clear();
            self.root = [0u8; 32];
            return Ok(());
        }

        // Update the base level
        self.tree[0] = self.leaves.clone();

        // Recompute each level
        let mut current_level = self.tree[0].clone();
        for level in 1..self.tree.len() {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_pair(chunk[0], chunk[1]));
                } else {
                    next_level.push(chunk[0]);
                }
            }
            
            self.tree[level] = next_level.clone();
            current_level = next_level;
        }

        // Update root
        self.root = self.tree.last().unwrap()[0];
        Ok(())
    }    /// Generates a Merkle proof for a given leaf.
    pub fn get_proof(&self, leaf: &Bytes32) -> Option<Vec<Bytes32>> {
        let pos = self.leaves.iter().position(|x| x == leaf)?;
        let mut proof = Vec::new();
        let mut index = pos;
        for level in &self.tree[..self.tree.len()-1] {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            if sibling_index < level.len() {
                proof.push(level[sibling_index]);
            }
            index /= 2;
        }
        Some(proof)
    }

    /// Verifies a Merkle proof.
    pub fn verify_proof(&self, leaf: &Bytes32, proof: &[Bytes32], root: &Bytes32) -> bool {
        let mut computed_hash = *leaf;
        for sibling in proof {
            if computed_hash < *sibling {
                computed_hash = hash_pair(computed_hash, *sibling);
            } else {
                computed_hash = hash_pair(*sibling, computed_hash);
            }
        }
        &computed_hash == root
    }
}

/// Hashes two Bytes32 together to form a parent node using SHA256.
pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&left);
    hasher.update(&right);
    let result = hasher.finalize();
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&result);
    parent
}

/// Represents a Merkle proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub path: Vec<Bytes32>, // List of sibling hashes along the path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::helpers::hash_pair;
    use anyhow::Result;

    #[test]
    fn test_merkle_tree_basic_operations() -> Result<(), MerkleTreeError> {
        let mut merkle_tree = MerkleTree::new();

        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        let leaf4 = [4u8; 32];

        // Insert leaves
        merkle_tree.insert(leaf1)?;
        merkle_tree.insert(leaf2)?;
        merkle_tree.insert(leaf3)?;
        merkle_tree.insert(leaf4)?;

        // Verify root
        let expected_root = hash_pair(hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf4));
        assert_eq!(merkle_tree.root, expected_root);

        // Generate and verify proof for leaf1
        let proof = merkle_tree.get_proof(&leaf1).unwrap();
        assert!(merkle_tree.verify_proof(&leaf1, &proof, &merkle_tree.root));

        // Update leaf2
        let new_leaf2 = [22u8; 32];
        merkle_tree.update(leaf2, new_leaf2)?;

        let expected_new_root = hash_pair(hash_pair(leaf1, new_leaf2), hash_pair(leaf3, leaf4));
        assert_eq!(merkle_tree.root, expected_new_root);

        // Generate and verify proof for new_leaf2
        let proof_new_leaf2 = merkle_tree.get_proof(&new_leaf2).unwrap();
        assert!(merkle_tree.verify_proof(&new_leaf2, &proof_new_leaf2, &merkle_tree.root));

        // Delete leaf3
        merkle_tree.delete(leaf3)?;

        let expected_after_delete_root = hash_pair(hash_pair(leaf1, new_leaf2), hash_pair(leaf4, leaf4));
        assert_eq!(merkle_tree.root, expected_after_delete_root);

        Ok(())
    }
}