// ./src/common/error/mod.rs
//! Error types for the Overpass library
//!
//! This module defines error types used throughout the library,
//! providing detailed error information for debugging and handling.

use thiserror::Error;

use crate::types::ChannelId;
use crate::types::WalletId;

/// The main error type for the Overpass library
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// ZKP-related errors
    #[error(transparent)]
    Zkp(#[from] ZkpError),

    /// Channel-related errors
    #[error(transparent)]
    Channel(#[from] ChannelError),

    /// Wallet-related errors
    #[error(transparent)]
    Wallet(#[from] WalletError),

    /// Global state errors
    #[error(transparent)]
    Global(#[from] GlobalError),
}

/// Errors that can occur during ZKP operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkpError {
    /// Invalid proof
    #[error("Invalid ZKP proof")]
    InvalidProof,

    /// Proof generation failed
    #[error("ZKP proof generation failed")]
    ProofGenerationFailed,

    /// Invalid proof data
    #[error("Invalid ZKP proof data")]
    InvalidProofData,

    /// Circuit error
    #[error("ZKP circuit error")]
    CircuitError,

    /// Transfer amount cannot be zero
    #[error("Transfer amount cannot be zero")]
    InvalidZeroTransfer,
}

/// Errors that can occur during channel operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChannelError {
    /// Initial sender balance cannot be zero
    #[error("Initial sender balance cannot be zero")]
    InvalidZeroBalance,

    /// Insufficient balance for transfer
    #[error("Insufficient balance")]
    InsufficientBalance,

    /// Balance overflow during transfer
    #[error("Balance overflow: would exceed maximum value")]
    BalanceOverflow,

    /// Nonce overflow: cannot increment further
    #[error("Nonce overflow: cannot increment further")]
    ChannelNonceOverflow,

    /// Invalid nonce increment
    #[error("Invalid nonce increment")]
    InvalidNonceIncrement,

    /// Transfer amount cannot be zero
    #[error("Transfer amount cannot be zero")]
    InvalidZeroTransfer,

    /// Invalid balance change
    #[error("Invalid balance change")]
    InvalidBalanceChange,
}

/// Errors that can occur during wallet operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletError {
    /// Channel-related errors
    #[error(transparent)]
    Channel(#[from] ChannelError),

    /// Channel not found in wallet
    #[error("Channel not found in wallet: {0:?}")]
    ChannelNotFound(ChannelId),

    /// Wallet nonce overflow
    #[error("Nonce overflow: cannot increment further")]
    WalletNonceOverflow,
}

/// Errors that can occur during global state operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GlobalError {
    /// Wallet not found in global state
    #[error("Wallet not found in global state: {0:?}")]
    WalletNotFound(WalletId),

    /// Global state nonce overflow
    #[error("Global state nonce overflow: cannot increment further")]
    GlobalNonceOverflow,
}

/// Result type alias for the library
pub type Result<T> = std::result::Result<T, Error>;
