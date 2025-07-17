# Overpass Channels Protocol - E2E Integration Test

This repository includes a comprehensive end-to-end (E2E) test to verify the functionality of the Overpass Channels Protocol. The test simulates the creation, management, and verification of channel states, as well as anchoring states to Bitcoin via OP_RETURN transactions. For a detailed explanation of the protocol, refer to [ the overpass paper](overpass_paper.pdf).

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
