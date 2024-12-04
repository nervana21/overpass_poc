use crate::smt::wallet_sparse_merkle_tree::SparseMerkleTree;
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    pub balance: u64,
    pub nonce: u64,
    pub merkle_root: [u8; 32],
    pub proof: Option<Vec<Vec<u8>>>,
}


impl Default for WalletState {
    fn default() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            merkle_root: [0u8; 32],
            proof: None,
        }
    }
}

impl WalletState {
    pub fn new(initial_balance: u64) -> Self {
        let mut tree = SparseMerkleTree::new(32);
        let key = [0u8; 32];
        let value = initial_balance.to_le_bytes();
        tree.update(&key, &value);

        Self {
            balance: initial_balance,
            nonce: 0,
            merkle_root: tree.root,
            proof: None,
        }
    }

    pub fn transfer(&self, amount: u64) -> Result<Self, String> {
        if amount > self.balance {
            return Err("Insufficient balance".to_string());
        }

        let new_balance = self.balance - amount;

        let mut tree = SparseMerkleTree::new(32);
        let key = [0u8; 32];
        let value = new_balance.to_le_bytes();
        tree.update(&key, &value);

        let proof = tree.generate_proof(&key);

        Ok(Self {
            balance: new_balance,
            nonce: self.nonce + 1,
            merkle_root: tree.root,
            proof: Some(proof),
        })
    }

    pub fn verify_state_transition(&self, next_state: &Self) -> bool {
        if self.nonce + 1 != next_state.nonce {
            return false;
        }

        // Balance should decrease by the transfer amount
        if self.balance <= next_state.balance {
            return false;
        }

        // Verify the Merkle proof
        if let Some(proof) = &next_state.proof {
            let key = [0u8; 32];
            let value = next_state.balance.to_le_bytes();
            SparseMerkleTree::verify_proof(&self.merkle_root, proof, &key, &value)
        } else {
            false
        }
    }

    pub fn get_balance(&self) -> u64 {
        self.balance
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    pub fn get_proof(&self) -> Option<Vec<Vec<u8>>> {
        self.proof.clone()
    }

    pub fn deposit(&self, amount: u64) -> Self {
        let new_balance = self.balance + amount;
        let mut tree = SparseMerkleTree::new(32);
        let key = [0u8; 32];
        let value = new_balance.to_le_bytes();
        tree.update(&key, &value);

        Self {
            balance: new_balance,
            nonce: self.nonce + 1,
            merkle_root: tree.root,
            proof: None,
        }
    }

    pub fn update_merkle_proof(&mut self) {
        let mut tree = SparseMerkleTree::new(32);
        let key = [0u8; 32];
        let value = self.balance.to_le_bytes();
        tree.update(&key, &value);
        self.merkle_root = tree.root;
        self.proof = Some(tree.generate_proof(&key));
    }

    pub fn merge(&self, other: &Self) -> Result<Self, String> {
        if self.nonce != other.nonce {
            return Err("Nonce mismatch".to_string());
        }

        let mut tree = SparseMerkleTree::new(32);
        let key = [0u8; 32];
        let value = (self.balance + other.balance).to_le_bytes();
        tree.update(&key, &value);

        Ok(Self {
            balance: self.balance + other.balance,
            nonce: self.nonce + 1,
            merkle_root: tree.root,
            proof: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_wallet() {
        let wallet = WalletState::new(100);
        assert_eq!(wallet.balance, 100);
        assert_eq!(wallet.nonce, 0);
    }

    #[test]
    fn test_transfer() {
        let wallet = WalletState::new(100);
        let result = wallet.transfer(50);
        assert!(result.is_ok());
        let new_wallet = result.unwrap();
        assert_eq!(new_wallet.balance, 50);
        assert_eq!(new_wallet.nonce, 1);
    }

    #[test]
    fn test_insufficient_balance() {
        let wallet = WalletState::new(100);
        let result = wallet.transfer(150);
        assert!(result.is_err());
    }

    #[test]
    fn test_deposit() {
        let wallet = WalletState::new(100);
        let new_wallet = wallet.deposit(50);
        assert_eq!(new_wallet.balance, 150);
        assert_eq!(new_wallet.nonce, 1);
    }

    #[test]
    fn test_verify_state_transition() {
        let wallet = WalletState::new(100);
        let new_wallet = wallet.transfer(50).unwrap();
        assert!(wallet.verify_state_transition(&new_wallet));
    }

    #[test]
    fn test_merge_wallets() {
        let wallet1 = WalletState::new(100);
        let wallet2 = WalletState::new(50);
        let result = wallet1.merge(&wallet2);
        assert!(result.is_ok());
        let merged = result.unwrap();
        assert_eq!(merged.balance, 150);
    }
}
