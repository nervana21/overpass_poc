// src/zkp/transactions.rs

use anyhow::Result;
use midas::BitcoinTestClient;
use miniscript::bitcoin::absolute::LockTime;
use miniscript::bitcoin::transaction::{Transaction, Version};
use miniscript::bitcoin::Address;

/// Builds an OP_RETURN transaction embedding the provided data.
pub fn build_transaction(
    _client: &BitcoinTestClient,
    _address: &Address,
    _data: [u8; 32],
) -> Result<Transaction> {
    // TODO: Implement
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_time_zero() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert_eq!(tx.lock_time, LockTime::ZERO);
    }
}
