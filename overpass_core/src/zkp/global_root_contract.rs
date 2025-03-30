// src/zkp/global_root_contract.rs

use crate::zkp::helpers::commitments::Bytes32;
use crate::zkp::helpers::merkle::compute_global_root;
use crate::zkp::helpers::state::verify_wallet_proof;

use crate::zkp::pedersen_parameters::{PedersenParameters, SerdePedersenParameters};
use anyhow::Result;
use std::collections::HashMap;
use thiserror::Error;

use super::helpers::state::StateProof as HelperStateProof;
use super::state_proof::{self, StateProof};
use super::tree::{MerkleTree, MerkleTreeError};

/// Represents errors in GlobalRootContract operations.
#[derive(Error, Debug)]
pub enum GlobalRootContractError {
    #[error("Wallet already registered")]
    WalletAlreadyRegistered,

    #[error("Wallet not found")]
    WalletNotFound,

    #[error("Proof verification failed")]
    ProofVerificationFailed,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Merkle tree error: {0}")]
    MerkleTreeError(#[from] MerkleTreeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Computation error: {0}")]
    ComputationError(String),
}

impl From<anyhow::Error> for GlobalRootContractError {
    fn from(err: anyhow::Error) -> Self {
        GlobalRootContractError::ComputationError(err.to_string())
    }
}

#[derive(Debug)]
/// Global Root Contract manages wallet roots and their proofs.
pub struct GlobalRootContract {
    wallet_roots: HashMap<Bytes32, Bytes32>,
    latest_proofs: HashMap<Bytes32, StateProof>,
    params: PedersenParameters,
    merkle_root: Bytes32,
    merkle_tree: MerkleTree,
}

impl GlobalRootContract {
    /// Creates a new GlobalRootContract with given Pedersen parameters.
    pub fn new(params: PedersenParameters) -> Self {
        let merkle_tree = MerkleTree::new();
        let merkle_root = merkle_tree.root;
        Self {
            wallet_roots: HashMap::new(),
            latest_proofs: HashMap::new(),
            params,
            merkle_root,
            merkle_tree,
        }
    }

    /// Saves PedersenParameters to a file in serialized form.
    pub fn save_pedersen_parameters_to_file(
        params: PedersenParameters,
        file_path: &str,
    ) -> Result<(), GlobalRootContractError> {
        let serde_params: SerdePedersenParameters = params.into();
        let serialized =
            serde_json::to_string(&serde_params).map_err(GlobalRootContractError::from)?;
        std::fs::write(file_path, serialized).map_err(GlobalRootContractError::from)
    }

    /// Loads PedersenParameters from a serialized file.
    pub fn load_pedersen_parameters_from_file(
        file_path: &str,
    ) -> Result<PedersenParameters, GlobalRootContractError> {
        let serialized =
            std::fs::read_to_string(file_path).map_err(GlobalRootContractError::from)?;
        let serde_params: SerdePedersenParameters =
            serde_json::from_str(&serialized).map_err(GlobalRootContractError::from)?;
        Ok(serde_params.into())
    }

    /// Registers a new wallet with its Merkle root.
    pub fn register_wallet(
        &mut self,
        wallet_id: Bytes32,
        wallet_merkle_root: Bytes32,
    ) -> Result<(), GlobalRootContractError> {
        if self.wallet_roots.contains_key(&wallet_id) {
            return Err(GlobalRootContractError::WalletAlreadyRegistered);
        }

        self.wallet_roots.insert(wallet_id, wallet_merkle_root);
        self.merkle_tree.insert(wallet_merkle_root)?;

        match compute_global_root(&self.wallet_roots) {
            Ok(root) => {
                self.merkle_root = root;
                Ok(())
            }
            Err(e) => Err(GlobalRootContractError::ComputationError(e)),
        }
    }

    /// Updates a wallet's Merkle root with a new proof.
    pub fn update_wallet(
        &mut self,
        wallet_id: Bytes32,
        wallet_root_update: Bytes32,
        proof: state_proof::StateProof, // Use fully qualified type
    ) -> Result<(), GlobalRootContractError> {
        // let old_root = self
        // .wallet_roots
        // .get(&wallet_id)
        // .ok_or(GlobalRootContractError::WalletNotFound)?
        // .clone();

        let old_root = *self
            .wallet_roots
            .get(&wallet_id)
            .ok_or(GlobalRootContractError::WalletNotFound)?;

        // Convert state_proof::StateProof to helpers::StateProof for verification
        let helper_proof = HelperStateProof {
            pi: proof.pi,
            public_inputs: proof.public_inputs.clone(),
            timestamp: proof.timestamp,
            params: self.params.clone(),
        };

        if !verify_wallet_proof(&old_root, &wallet_root_update, &helper_proof, &self.params) {
            return Err(GlobalRootContractError::ProofVerificationFailed);
        }

        self.wallet_roots.insert(wallet_id, wallet_root_update);

        self.merkle_tree
            .update(old_root, wallet_root_update)
            .map_err(GlobalRootContractError::from)?;

        match compute_global_root(&self.wallet_roots) {
            Ok(root) => {
                self.merkle_root = root;
                self.latest_proofs.insert(wallet_id, proof);
                Ok(())
            }
            Err(e) => Err(GlobalRootContractError::ComputationError(e)),
        }
    }
    /// Gets the current root for a wallet.
    pub fn get_wallet_root(&self, wallet_id: &Bytes32) -> Option<Bytes32> {
        self.wallet_roots.get(wallet_id).copied()
    }

    /// Lists all registered wallet IDs.
    pub fn list_wallets(&self) -> Vec<Bytes32> {
        self.wallet_roots.keys().copied().collect()
    }

    /// Gets the last proof for a wallet.
    pub fn get_latest_proof(&self, wallet_id: &Bytes32) -> Option<&StateProof> {
        self.latest_proofs.get(wallet_id)
    }

    /// Retrieves the current global Merkle root.
    pub fn get_global_merkle_root(&self) -> Bytes32 {
        self.merkle_root
    }

    /// Generates a Merkle proof for a given wallet.
    pub fn generate_proof(
        &self,
        wallet_id: Bytes32,
    ) -> Result<Vec<Bytes32>, GlobalRootContractError> {
        let wallet_merkle_root = self
            .wallet_roots
            .get(&wallet_id)
            .ok_or(GlobalRootContractError::WalletNotFound)?;

        self.merkle_tree
            .get_proof(wallet_merkle_root)
            .ok_or(GlobalRootContractError::ProofVerificationFailed)
    }

    /// Verifies a Merkle proof for a given wallet.
    pub fn verify_proof(
        &self,
        wallet_id: Bytes32,
        proof: &[Bytes32],
    ) -> Result<bool, GlobalRootContractError> {
        let wallet_root = self
            .wallet_roots
            .get(&wallet_id)
            .ok_or(GlobalRootContractError::WalletNotFound)?;

        Ok(self
            .merkle_tree
            .verify_proof(wallet_root, proof, &self.merkle_root))
    }
}

#[cfg(test)]
mod tests {
    use crate::zkp::helpers::state::current_timestamp;
    use crate::zkp::helpers::state::generate_state_proof;

    use super::*;

    fn setup_test_contract() -> GlobalRootContract {
        let params = PedersenParameters::default();
        GlobalRootContract::new(params)
    }

    #[test]
    fn test_new_global_root_contract() -> Result<(), GlobalRootContractError> {
        let contract = setup_test_contract();

        assert!(contract.wallet_roots.is_empty());
        assert!(contract.latest_proofs.is_empty());
        assert_eq!(contract.merkle_root, [0u8; 32]);
        assert!(contract.merkle_tree.leaves.is_empty());
        assert_eq!(contract.merkle_tree.root, [0u8; 32]);
        assert!(contract.merkle_tree.tree.is_empty());

        // dbg!(contract);

        Ok(())
    }

    #[test]
    fn test_register_wallet() -> Result<(), GlobalRootContractError> {
        let mut contract = setup_test_contract();
        let wallet_id = [1u8; 32];
        let wallet_merkle_root = [2u8; 32];

        contract.register_wallet(wallet_id, wallet_merkle_root)?;

        assert!(contract.wallet_roots.contains_key(&wallet_id));
        assert_eq!(
            contract.get_wallet_root(&wallet_id),
            Some(wallet_merkle_root)
        );

        // Try registering same wallet again
        let result = contract.register_wallet(wallet_id, wallet_merkle_root);
        assert!(matches!(
            result,
            Err(GlobalRootContractError::WalletAlreadyRegistered)
        ));

        Ok(())
    }

    #[test]
    fn test_update_wallet() -> Result<(), GlobalRootContractError> {
        let mut contract = setup_test_contract();
        let wallet_id = [1u8; 32];
        let init_wallet_state_commitment = [2u8; 32];

        contract.register_wallet(wallet_id, init_wallet_state_commitment)?;

        // Create a mock proof
        let new_commitment = [3u8; 32];
        let new_global_merkle_root = [4u8; 32];
        let mock_proof = StateProof {
            pi: generate_state_proof(
                init_wallet_state_commitment,
                new_commitment,
                new_global_merkle_root,
                &contract.params,
            )
            .pi,
            public_inputs: vec![
                init_wallet_state_commitment,
                new_commitment,
                new_global_merkle_root,
            ],
            timestamp: current_timestamp(),
        };

        // Update wallet with new root and proof
        contract.update_wallet(wallet_id, new_commitment, mock_proof.clone())?;

        // Verify the update
        assert_eq!(contract.get_wallet_root(&wallet_id), Some(new_commitment));

        // Test updating non-existent wallet
        let invalid_wallet = [22u8; 32];
        let invalid_result =
            contract.update_wallet(invalid_wallet, new_global_merkle_root, mock_proof.clone());
        assert!(matches!(
            invalid_result,
            Err(GlobalRootContractError::WalletNotFound)
        ));

        Ok(())
    }

    #[test]
    fn test_generate_and_verify_proof() -> Result<(), GlobalRootContractError> {
        let mut contract = setup_test_contract();
        let wallet_id = [1u8; 32];
        let wallet_merkle_root = [2u8; 32];

        contract.register_wallet(wallet_id, wallet_merkle_root)?;

        let proof = contract.generate_proof(wallet_id)?;
        assert!(contract.verify_proof(wallet_id, &proof)?);

        // Test with invalid wallet ID
        let invalid_id = [3u8; 32];
        assert!(matches!(
            contract.generate_proof(invalid_id),
            Err(GlobalRootContractError::WalletNotFound)
        ));

        Ok(())
    }

    #[test]
    fn test_list_wallets() -> Result<(), GlobalRootContractError> {
        let mut contract = setup_test_contract();
        let wallet_ids: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        for &id in &wallet_ids {
            contract.register_wallet(id, [0u8; 32])?;
        }

        let listed_wallets = contract.list_wallets();
        assert_eq!(listed_wallets.len(), wallet_ids.len());

        for id in wallet_ids {
            assert!(listed_wallets.contains(&id));
        }

        Ok(())
    }
}
