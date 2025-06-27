# Overpass Channels Protocol - E2E Integration Test

This repository includes a comprehensive end-to-end (E2E) test to verify the functionality of the Overpass Channels Protocol. The test simulates the creation, management, and verification of channel states, as well as anchoring states to Bitcoin via OP_RETURN transactions.

## Overview

The E2E test demonstrates:

- Initialization of a Bitcoin client and generation of blocks
- Creation of channel states and their transitions
- Updating Sparse Merkle Trees (SMTs) for wallet and channel state management
- Verification of Merkle proofs for channel state consistency
- Secure anchoring of state to Bitcoin using an OP_RETURN transaction

## Requirements

Before running the test, ensure the following dependencies are installed:

### Bitcoin Testnet Node

- A fully synchronized Bitcoin node configured for regtest or testnet mode
- Ensure RPC access is enabled

### Programming Environment

- Rust (for running the Overpass Protocol codebase)
- Cargo (Rust's package manager and build system)

### Dependencies

- The repository should include all necessary crates for Sparse Merkle Trees (SMTs), hashing (Poseidon), and Bitcoin interaction

## Running the Test

The test script is designed to be run in a Rust Nightly environment. Follow these steps to execute the test:

### 1. Clone the Repository

Download the repository to your local machine

### 2. Enter the PoC Directory

```
cd overpass_core
```

### 3. Build the Project

Ensure the project builds without errors:

```
cargo build
```

### 4. Run the Test

Execute the integration test using cargo:

```
 # From your project root (cd ./overpass_poc/overpass_core/)
cargo test --test midas_test -- --nocapture  # The --nocapture flag shows println outputs


```

## Expected Output

The test will log the following stages:

### Bitcoin Initialization

Generates a Bitcoin address and 101 blocks for the test environment, and outputs wallet balance.

Example:

```
Bitcoin client initialized
Generated address: bcrt1q2jaj9tdanu85m269ym27qn9e38va7ljdmg08kl
Generated 101 blocks
Wallet balance: 617499987108
```

### Channel State Creation

Creates an initial channel state with balances, metadata, and an SMT root.

Example:

```
Initial state created: ChannelState { balances: [100, 50], nonce: 0, metadata: [], merkle_root: [...] }
```

### State Transition

Logs balance deltas, nonce updates, and the resulting hashed state.

Example:

```
Delta balance 0: -3
Delta balance 1: 3
Delta nonce: 1
```

### Merkle Tree Updates

Updates and verifies the Sparse Merkle Tree with the new state.

### OP_RETURN Transaction

Creates and broadcasts an OP_RETURN transaction to anchor the state on Bitcoin.

Example:

```
Transaction sent with ID: c2a7098651e661eee11718265e748fe6032a2433e1d10eae00ad9625391e0935
```

### Test Completion

Confirms that all operations completed successfully.

Example:

```
Test completed successfully
test result: ok. 1 passed; 0 failed; finished in 1.08s
```

## Understanding the Code

The test script includes the following key components:

### Bitcoin Client Initialization

- Initializes a Bitcoin regtest client for creating blocks and managing UTXOs

### Channel State Management

- Creates and manages channel states using Sparse Merkle Trees

### Cryptographic Hashing

- Uses Poseidon hash function to compute state roots

### Merkle Proof Verification

- Verifies that channel states are valid against the SMT root

### OP_RETURN Transaction

- Anchors the SMT root on Bitcoin using an OP_RETURN transaction for trustless verification
