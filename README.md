## Abstract

Overpass is a Layer-2 protocol that allows for constant time transaction verification without sacrificing desired Bitcoin security assumptions. Built using zero-knowledge proofs and unidirectional state channels, it enables private, secure, and massively scalable off-chain transactions anchored to Bitcoin.

## Core Idea

Each state transition is self-proving. It carries a succinct, independently verifiable proof of validity. Proofs compose without loss of guarantees, enabling scaling without fragility.

## Protocol Overview

### State Transition

```
function UpdateState(s_old, u, aux):
    s_new ← ComputeNewState(s_old, u)
    π ← GenerateProof(s_old, s_new, aux)
    assert VerifyProof(π)
    root_new ← UpdateMerkleRoot(s_new)
    return (s_new, π)
```

- Local: No global consensus for every update
- Constant-time verification: Proofs check in O(1) regardless of system size
- Channel isolation: One channel's compromise cannot affect another

### Hierarchy

```
Channel → Wallet → Root
```

- Channels operate independently but are anchored to a global root for settlement.

## Architecture

- Core Protocol: State channel logic, ZK circuits, Bitcoin anchoring
- Proof System: Constant-time proof verification
- Merkle Layer: Sparse Merkle Trees for commitment to wallet/channel states
- L1 Interface: Aggregates and anchors proofs to Bitcoin via OP_RETURN

## Key Properties

- Scalability: Throughput O(n·m), latency O(1), verification cost O(log d) → O(1) with recursion
- Security amplification: Composing secure channels increases total security parameter λ
- Privacy: zkAt hides policies; ZKPs hide transaction details
- Bitcoin compatibility: Uses native UTXOs for settlement; no alt-consensus

## Getting Started

### Building and Testing

1. Clone the Repository

   ```bash
   git clone https://github.com/nervana21/overpass_poc overpass_poc
   cd overpass_poc
   ```

2. Build the Project

   ```bash
   cargo build
   cargo test
   ```

3. Run Integration Tests

   ```bash
   # Run the comprehensive E2E test
   cargo test --test midas_test -- --nocapture
   ```

## Requirements

Requires a working `bitcoind` executable.

## Status & Contributing

- Current stage: Alpha, not production-ready
- Contributions welcome — see `CONTRIBUTING.md`

Documentation:

- [Perfect Mathematical Composability Blueprint](docs/blueprint.md)
- [Overpass Paper](docs/overpass_paper.pdf)
- [Zero Knowledge Authentication](docs/zkAt.pdf)

License: MIT
