# Perfect Mathematical Composability: Overpass + zkAt

## Abstract

Overpass is a Layer-2 protocol for Bitcoin that achieves **perfect mathematical composability** — the ability to compose financial primitives so that verification stays constant-time and security guarantees multiply rather than degrade. Built on unilateral state channels, zero-knowledge proofs (ZKPs), and Sparse Merkle Trees (SMTs), it enables private, secure, and massively scalable off-chain transactions anchored to Bitcoin.

## 1. Core Idea

Traditional L2 systems suffer from the **composition cost theorem**:

```
VerifyCost(S) = Σ VerifyCost(C_i) + O(n²)
Security_total ≤ min(Security(C_i))
```

Overpass inverts this:  
For components A and B:

```
VerifyCost(A ⊕ B) = O(1)
Security(A ⊕ B) = Security(A) · Security(B)
FinalizeTime(A ⊕ B) = max(FinalizeTime(A), FinalizeTime(B))
```

Each state is **self-proving** — it carries a succinct, independently verifiable proof of validity. Proofs compose without loss of guarantees, enabling scaling without fragility.

## 2. zkAt: Policy-Private Authentication

Overpass integrates **zkAt** (Zero-Knowledge Access Transparency):

- **Policy commitments** define who can authorize state changes without revealing identities.
- Proofs show a transition complies with policy, but the policy itself remains hidden.
- zkAt+ extends this to **oblivious policy updates** without breaking the trustless guarantees.

zkAt compresses _identity expression_, not the physical L1 "exit pipe," so L1 UTXO capacity still bounds total identities — but with far greater flexibility in how policies and rights are managed.

## 3. Protocol Overview

### State Transition

```
function UpdateState(s_old, u, aux):
    s_new ← ComputeNewState(s_old, u)
    π ← GenerateProof(s_old, s_new, aux)
    assert VerifyProof(π)
    root_new ← UpdateMerkleRoot(s_new)
    return (s_new, π)
```

- **Local**: No global consensus for every update.
- **Constant-time verification**: Proofs check in O(1) regardless of system size.
- **Perfect isolation**: One channel's compromise cannot affect another.

### Hierarchy

```
Root → Wallet → Channel
```

- Channels operate independently but are anchored to a global root for settlement.

## 4. Architecture

- **Core Protocol**: State channel logic, ZK circuits, Bitcoin anchoring.
- **Proof System**: Plonky2-based circuits for constant-time proof verification.
- **Merkle Layer**: Sparse Merkle Trees for commitment to wallet/channel states.
- **L1 Interface**: Aggregates and anchors proofs to Bitcoin via OP_RETURN.

## 5. Key Properties

- **Scalability**: Throughput O(n·m), latency O(1), verification cost O(log d) → O(1) with recursion.
- **Security amplification**: Composing secure channels increases total security parameter λ.
- **Privacy**: zkAt hides policies; ZKPs hide transaction details.
- **Bitcoin compatibility**: Uses native UTXOs for settlement; no alt-consensus.

## 6. Getting Started

### Requirements

Before running the protocol, ensure the following dependencies are installed:

#### Bitcoin Node

- A fully synchronized Bitcoin node configured for regtest or testnet mode
- Ensure RPC access is enabled

#### Programming Environment

- Rust (for running the Overpass Protocol codebase)
- Cargo (Rust's package manager and build system)

#### Dependencies

- The repository includes all necessary crates for Sparse Merkle Trees (SMTs), hashing (Poseidon), and Bitcoin interaction

### Building and Testing

1. **Clone the Repository**

   ```bash
   git clone <repository-url>
   cd overpass_poc
   ```

2. **Build the Project**

   ```bash
   cargo build
   ```

3. **Run Integration Tests**

   ```bash
   # Run the comprehensive E2E test
   cargo test --test e2e_integration_test -- --nocapture

   # Run P2TR-specific tests
   cargo test --test e2e_p2tr_test -- --nocapture

   # Run midas test
   cargo test --test midas_test -- --nocapture
   ```

### E2E Test Overview

The integration tests demonstrate:

- Initialization of a Bitcoin client and generation of blocks
- Creation of channel states and their transitions
- Updating Sparse Merkle Trees (SMTs) for wallet and channel state management
- Verification of Merkle proofs for channel state consistency
- Secure anchoring of state to Bitcoin using OP_RETURN transactions

## 7. Implementation Notes

- **Cryptography**: Poseidon hash, ChaCha20-Poly1305 encryption
- **E2E tests** simulate:
  - Bitcoin regtest node setup
  - Channel state creation & update
  - Merkle proof verification
  - OP_RETURN anchoring
- **Modular design**: CLI, frontend, and WASM bindings optional

### Key Components

#### Bitcoin Client Initialization

- Initializes a Bitcoin regtest client for creating blocks and managing UTXOs

#### Channel State Management

- Creates and manages channel states using Sparse Merkle Trees

#### Cryptographic Hashing

- Uses Poseidon hash function to compute state roots

#### Merkle Proof Verification

- Verifies that channel states are valid against the SMT root

#### OP_RETURN Transaction

- Anchors the SMT root on Bitcoin using an OP_RETURN transaction for trustless verification

## 8. Research Directions

- **Recursive proofs** for unbounded composition
- **Advanced privacy**: hidden state commitments, confidential channels
- **Cross-chain proofs** for multi-asset interoperability

## 9. Status & Contributing

- Current stage: **Alpha**, not production-ready
- Contributions welcome — see `CONTRIBUTING.md`

---

**Documentation:**

- [Perfect Mathematical Composability Blueprint](docs/blueprint.md)
- [Overpass Paper](docs/overpass_paper.pdf)
- [Zero Knowledge Authentication](docs/zkAt.pdf)

**Contact:** info@overpass.network  
**License:** MIT
