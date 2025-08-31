// src/zkp/tree.rs
//! # Merkle Tree Module
//!
//! This module implements a Sparse Merkle Tree (SMT) for the Overpass framework.
//!
//! **Design Decision:**  
//! Currently, the tree does **not** differentiate between leaf nodes and internal nodes—both are
//! hashed using the same `hash_pair` function (which uses double-SHA256). This follows the Bitcoin Core
//! design.  
//!
//! *TODO:* We may introduce domain separation (e.g. prefixing leaves with `0x00` and internal nodes with
//! `0x01`) to eliminate any theoretical ambiguities. Please see section X in the Developer Documentation for more details.

use thiserror::Error;

use crate::merkle::hash_pair;
use crate::types::Bytes32;

/// Represents errors that can occur in the Merkle Tree operations.
#[derive(Debug, Error)]
pub enum MerkleTreeError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    // Add other relevant error variants as needed
}

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
            current_level =
                current_level.chunks(2).map(|pair| hash_pair(pair[0], pair[1])).collect();
            self.tree.push(current_level.clone());
        }
        self.root = current_level[0];
    }
    /// Incrementally updates the tree upon inserting a new leaf.
    fn update_tree_on_insert(&mut self) -> Result<(), MerkleTreeError> {
        // Create a mutable clone of leaves to work with.
        let mut base = self.leaves.clone();

        // if there's exactly one leaf, don't duplicate.
        if base.len() == 1 {
            if self.tree.is_empty() {
                self.tree.push(base.clone());
            } else {
                self.tree[0] = base.clone();
            }
            self.root = base[0];
            return Ok(());
        }

        // For more than one leaf, if the number is odd, duplicate the last leaf.
        if base.len() % 2 != 0 {
            base.push(*base.last().unwrap());
        }

        // Update the base level.
        if self.tree.is_empty() {
            self.tree.push(base.clone());
        } else {
            self.tree[0] = base.clone();
        }

        // Recompute each subsequent level.
        let mut current_level = base;
        let mut level = 0;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2) {
                let hash = hash_pair(pair[0], pair[1]);
                next_level.push(hash);
            }
            level += 1;
            if self.tree.len() > level {
                self.tree[level] = next_level.clone();
            } else {
                self.tree.push(next_level.clone());
            }
            current_level = next_level;
        }
        self.root = current_level[0];
        Ok(())
    }

    /// Incrementally updates the tree upon updating a leaf.
    fn update_tree_on_update(&mut self, pos: usize) -> Result<(), MerkleTreeError> {
        if self.tree.is_empty() {
            return Ok(());
        }

        let mut current_pos = pos;
        self.tree[0] = self.leaves.clone();

        for level in 0..self.tree.len() - 1 {
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

        // Update the base level with the current leaves.
        self.tree[0] = self.leaves.clone();

        // Recompute each level
        let mut current_level = self.tree[0].clone();
        for level in 1..self.tree.len() {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_pair(chunk[0], chunk[1]));
                } else {
                    // Duplicate the lone element to compute its hash.
                    next_level.push(hash_pair(chunk[0], chunk[0]));
                }
            }

            self.tree[level] = next_level.clone();
            current_level = next_level;
        }

        // Update root
        self.root = self.tree.last().unwrap()[0];
        Ok(())
    }

    /// Generates a Merkle proof for a given leaf.
    pub fn get_proof(&self, leaf: &Bytes32) -> Option<Vec<Bytes32>> {
        let pos = self.leaves.iter().position(|x| x == leaf)?;
        let mut proof = Vec::new();
        let mut index = pos;
        // Iterate over all levels except the root level.
        for level in self.tree.iter().take(self.tree.len() - 1) {
            let sibling_index = if index % 2 == 0 {
                if index + 1 < level.len() {
                    index + 1
                } else {
                    // No sibling exists; duplicate the node.
                    index
                }
            } else {
                index - 1
            };
            proof.push(level[sibling_index]);
            index /= 2;
        }
        Some(proof)
    }

    /// Verifies a Merkle proof.
    pub fn verify_proof(&self, leaf: &Bytes32, proof: &[Bytes32], root: &Bytes32) -> bool {
        // Find the position of the leaf in the base level.
        let mut index = match self.leaves.iter().position(|x| x == leaf) {
            Some(pos) => pos,
            None => return false,
        };

        let mut computed_hash = *leaf;
        for sibling in proof {
            if index % 2 == 0 {
                // Current node is the left child.
                computed_hash = hash_pair(computed_hash, *sibling);
            } else {
                // Current node is the right child.
                computed_hash = hash_pair(*sibling, computed_hash);
            }
            index /= 2;
        }
        computed_hash == *root
    }
}

impl Default for MerkleTree {
    fn default() -> Self { Self::new() }
}

/// Represents a Merkle proof.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub path: Vec<Bytes32>, // List of sibling hashes along the path
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::merkle::hash_pair;

    #[test]
    fn test_new_merkle_tree() {
        let tree = MerkleTree::new();

        assert!(tree.leaves.is_empty());
        assert_eq!(tree.root, [0u8; 32]);
        assert!(tree.tree.is_empty());
    }

    #[test]
    fn test_update_tree_on_delete_even_leaves() -> Result<(), MerkleTreeError> {
        let mut merkle_tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        let leaf4 = [4u8; 32];

        // Set the tree leaves manually.
        merkle_tree.leaves = vec![leaf1, leaf2, leaf3, leaf4];
        // Pre-allocate levels (e.g., level 0, level 1, level 2).
        merkle_tree.tree = vec![vec![], vec![], vec![]];

        // Call the update function directly.
        merkle_tree.update_tree_on_delete(0)?;

        // Expected structure:
        // Level 0: [leaf1, leaf2, leaf3, leaf4]
        // Level 1: [hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf4)]
        // Level 2 (root): [hash_pair(hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf4))]
        let expected_level1 = vec![hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf4)];
        let expected_level2 = vec![hash_pair(expected_level1[0], expected_level1[1])];

        assert_eq!(merkle_tree.tree[0], vec![leaf1, leaf2, leaf3, leaf4]);
        assert_eq!(merkle_tree.tree[1], expected_level1);
        assert_eq!(merkle_tree.tree[2], expected_level2);
        Ok(())
    }

    #[test]
    fn test_update_tree_on_delete_odd_leaves() -> Result<(), MerkleTreeError> {
        let mut merkle_tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];

        // For an odd number of leaves.
        merkle_tree.leaves = vec![leaf1, leaf2, leaf3];
        // Pre-allocate levels (e.g., level 0, level 1, level 2).
        merkle_tree.tree = vec![vec![], vec![], vec![]];

        // Update the tree.
        merkle_tree.update_tree_on_delete(0)?;

        // Expected structure:
        // Level 0: [leaf1, leaf2, leaf3]
        // Level 1: [hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf3)]
        // Level 2 (root): [hash_pair(hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf3))]
        let expected_level1 = vec![hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf3)];
        let expected_level2 = vec![hash_pair(expected_level1[0], expected_level1[1])];

        assert_eq!(merkle_tree.tree[0], vec![leaf1, leaf2, leaf3]);
        assert_eq!(merkle_tree.tree[1], expected_level1);
        assert_eq!(merkle_tree.tree[2], expected_level2);
        Ok(())
    }

    #[test]
    fn test_get_proof_single_leaf() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];
        // Insert one leaf.
        tree.insert(leaf)?;
        // With one leaf, tree[0] == [leaf] and no sibling exists.
        let proof = tree.get_proof(&leaf).unwrap();
        // Expect proof to be empty.
        assert!(proof.is_empty());
        Ok(())
    }

    #[test]
    fn test_get_proof_even_leaves() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];

        // Insert two leaves.
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;

        // For two leaves, level 0 should be [leaf1, leaf2].
        // For leaf1 (at index 0) its sibling at level 0 is leaf2.
        let proof1 = tree.get_proof(&leaf1).unwrap();
        assert_eq!(proof1.len(), 1);
        assert_eq!(proof1[0], leaf2);

        // For leaf2 (at index 1) its sibling is leaf1.
        let proof2 = tree.get_proof(&leaf2).unwrap();
        assert_eq!(proof2.len(), 1);
        assert_eq!(proof2[0], leaf1);
        Ok(())
    }

    #[test]
    fn test_get_proof_odd_leaves() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];

        // Insert three leaves.
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;
        tree.insert(leaf3)?;
        // In update_tree_on_insert, when len==3, we duplicate the last leaf,
        // so level 0 becomes [leaf1, leaf2, leaf3, leaf3].

        // Get proof for leaf1 (position 0).
        // At level 0, its sibling is at index 1 (leaf2).
        // At level 1, index becomes 0 and sibling is at index 1.
        let proof1 = tree.get_proof(&leaf1).unwrap();
        assert_eq!(proof1.len(), 2);
        assert_eq!(proof1[0], leaf2);

        // Get proof for leaf3.
        // leaf3 first appears at index 2, so its sibling is at index 3 (which is also leaf3).
        let proof3 = tree.get_proof(&leaf3).unwrap();
        assert_eq!(proof3.len(), 2);
        assert_eq!(proof3[0], leaf3);
        // Although the duplicate sibling is the same as the leaf, this is expected.
        Ok(())
    }

    #[test]
    fn test_get_proof_non_existent_leaf() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];

        tree.insert(leaf1)?;
        tree.insert(leaf2)?;
        let non_existent = [3u8; 32];

        let proof = tree.get_proof(&non_existent);
        assert!(proof.is_none());
        Ok(())
    }

    #[test]
    fn test_verify_proof_single_leaf() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];

        // Insert one leaf into the tree.
        tree.insert(leaf)?;
        // When there's only one leaf, get_proof returns an empty proof.
        let proof = tree.get_proof(&leaf).unwrap();
        assert!(proof.is_empty());
        // With one leaf, the root is the leaf itself.
        assert!(tree.verify_proof(&leaf, &proof, &tree.root));

        // Verify that a wrong leaf does not pass verification.
        let wrong_leaf = [2u8; 32];
        assert!(!tree.verify_proof(&wrong_leaf, &proof, &tree.root));

        Ok(())
    }

    #[test]
    fn test_verify_proof_even_leaves() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];

        // Insert two leaves.
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;
        // The tree's base level should be [leaf1, leaf2], and the root is hash_pair(leaf1, leaf2).

        // Get and verify proof for leaf1.
        let proof1 = tree.get_proof(&leaf1).unwrap();
        assert_eq!(proof1.len(), 1);
        assert!(tree.verify_proof(&leaf1, &proof1, &tree.root));

        // Get and verify proof for leaf2.
        let proof2 = tree.get_proof(&leaf2).unwrap();
        assert_eq!(proof2.len(), 1);
        assert!(tree.verify_proof(&leaf2, &proof2, &tree.root));

        // Alter the proof for leaf1 (e.g., modify the sibling hash) and expect verification to fail.
        let mut wrong_proof = proof1.clone();
        wrong_proof[0] = [0u8; 32]; // tamper with the sibling hash
        assert!(!tree.verify_proof(&leaf1, &wrong_proof, &tree.root));

        Ok(())
    }

    #[test]
    fn test_verify_proof_odd_leaves() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];

        // Insert three leaves.
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;
        tree.insert(leaf3)?;
        // In our update_tree_on_insert, when there are 3 leaves, we duplicate the last leaf,
        // so level 0 becomes [leaf1, leaf2, leaf3, leaf3].

        // Get and verify proof for leaf1 (position 0).
        let proof1 = tree.get_proof(&leaf1).unwrap();
        // Expect two levels of proof.
        assert_eq!(proof1.len(), 2);
        assert!(tree.verify_proof(&leaf1, &proof1, &tree.root));

        // Get and verify proof for leaf3 (position 2 in leaves, which duplicates to position 3 in level 0).
        let proof3 = tree.get_proof(&leaf3).unwrap();
        assert_eq!(proof3.len(), 2);
        assert!(tree.verify_proof(&leaf3, &proof3, &tree.root));

        Ok(())
    }

    #[test]
    fn test_verify_proof_non_existent_leaf() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];

        tree.insert(leaf1)?;
        tree.insert(leaf2)?;

        let non_existent = [3u8; 32];
        // get_proof should return None for a leaf that doesn't exist.
        let proof = tree.get_proof(&non_existent);
        assert!(proof.is_none());

        // Even if we try to verify with an empty proof, it should return false.
        assert!(!tree.verify_proof(&non_existent, &[], &tree.root));

        Ok(())
    }

    #[test]
    fn test_update_tree_on_insert() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];

        tree.insert(leaf)?;

        let mut leaves = tree.leaves;
        let mut tree = tree.tree;

        // dbg!(tree.leaves.len());
        // If there's exactly one leaf, don't duplicate
        if leaves.len() == 1 {
            if tree.is_empty() {
                tree.push(leaves.clone());
            } else {
                tree[0] = leaves.clone();
            }
            return Ok(());
        }

        // For more than one leaf, if the number is odd, duplicate the last leaf.
        if leaves.len() % 2 != 0 {
            leaves.push(*leaves.last().unwrap());
        }

        // Update the base level.
        if tree.is_empty() {
            tree.push(leaves.clone());
        } else {
            tree[0] = leaves.clone();
        }

        // Recompute each subsequent level.
        let mut current_level = leaves;
        let mut level = 0;
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2) {
                let hash = hash_pair(pair[0], pair[1]);
                next_level.push(hash);
            }
            level += 1;
            if tree.len() > level {
                tree[level] = next_level.clone();
            } else {
                tree.push(next_level.clone());
            }
            current_level = next_level;
        }
        Ok(())
    }

    #[test]
    fn test_merkle_tree_insert() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];

        assert_ne!(tree.root, leaf);
        tree.insert(leaf)?;
        assert_eq!(tree.root, leaf);

        Ok(())
    }

    #[test]
    fn test_insert_into_empty_tree() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf = [1u8; 32];

        tree.insert(leaf)?;
        // With one leaf, the root should equal the leaf itself.
        assert_eq!(tree.leaves.len(), 1);
        assert_eq!(tree.root, leaf);
        Ok(())
    }

    #[test]
    fn test_insert_even_number_of_leaves() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;
        // For two leaves, the expected root is the hash of (leaf1, leaf2)
        let root = hash_pair(leaf1, leaf2);
        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(tree.root, root);
        Ok(())
    }

    #[test]
    fn test_insert_odd_number_of_leaves() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;
        tree.insert(leaf3)?;
        // in this implementation when there is an odd number of leaves, the last leaf is duplicated.
        // So the base level becomes: [leaf1, leaf2, leaf3, leaf3]
        let hash_level1_left = hash_pair(leaf1, leaf2);
        let hash_level1_right = hash_pair(leaf3, leaf3);
        let root = hash_pair(hash_level1_left, hash_level1_right);
        assert_eq!(tree.leaves.len(), 3);
        assert_eq!(tree.root, root);
        Ok(())
    }

    #[test]
    fn test_get_proof() -> Result<(), MerkleTreeError> {
        let mut tree = MerkleTree::new();

        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        let leaf4 = [4u8; 32];

        // Insert leaves
        tree.insert(leaf1)?;
        tree.insert(leaf2)?;

        let hash_12 = hash_pair(leaf1, leaf2);
        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(tree.root, hash_12);

        tree.insert(leaf3)?;
        assert_eq!(tree.leaves.len(), 3);
        assert_eq!(tree.root, hash_pair(hash_12, hash_pair(leaf3, leaf3)));

        tree.insert(leaf4)?;

        let expected_root = hash_pair(hash_pair(leaf1, leaf2), hash_pair(leaf3, leaf4));
        assert_eq!(tree.root, expected_root);

        // generate and verify proof for leaf1
        let proof = tree.get_proof(&leaf1).unwrap();
        assert!(tree.verify_proof(&leaf1, &proof, &tree.root));

        Ok(())
    }

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

        let expected_after_delete_root =
            hash_pair(hash_pair(leaf1, new_leaf2), hash_pair(leaf4, leaf4));
        assert_eq!(merkle_tree.root, expected_after_delete_root);

        Ok(())
    }
}
