# Sovereign Lattice: Architectural Roadmap

Sovereign Lattice is positioned as a formally verified, memory-safe alternative to traditional PBFT engines like Tendermint and HotStuff. While those systems offer high performance, their safety bounds are generally asserted via informal proofs and external models. Sovereign Lattice bridges this gap by mechanically verifying quorum safety in **Lean 4** and strictly enforcing those bounds via a zero-allocation, fixed-size Rust state machine.

This roadmap outlines our trajectory from a research-grade prototype to a production-ready, mission-critical consensus layer.

## Phase 1: Core State Machine & Mathematical Bounds (✅ Current)
- [x] Lean 4 Formal Verification of `quorum_intersection` and `PBFT_Safety`.
- [x] Rust PBFT State Machine with 101-byte deterministic wire parsing.
- [x] BLS12-381 Threshold Signatures for $O(1)$ signature verification (Aggregated in future).
- [x] Byzantine View-Change with strict Highest-QC inheritance (`Ghost Certificate` protection).
- [x] Write-Ahead Logging (WAL) with strict Fail-Stop recovery rules.

## Phase 2: Fuzzing & Adversarial Resilience (⏳ Next)
To transition from theoretical safety to empirical robustness, we will implement property-based testing.
- [ ] **Property-Based Testing (`proptest`):** Inject millions of randomized, out-of-order, and maliciously crafted byte payloads into the state machine to prove it never panics and never violates Lean 4 invariants.
- [ ] **Byzantine Scheduler:** A test harness that selectively drops, delays, and duplicates messages across a simulated network to stress-test Liveness and View-Change timeouts.

## Phase 3: Cryptography & Secure Transport (Research -> Production)
- [ ] **RFC 9380 Hash-to-Curve:** Replace the current scalar-hash stub in tests with the cryptographically secure `ExpandMsgXmd` standard via the `elliptic-curve::hash2curve` trait.
- [ ] **Authenticated Transport:** Wrap the raw Tokio TCP streams in mTLS or the Noise Protocol Framework to provide peer authentication and transport-level encryption.
- [ ] **Replay Protection:** Implement strictly enforced monotonic nonces at the transport layer to complement the state machine's sequence checks.

## Phase 4: Full-Stack Verification (Academic Goal)
To target top-tier computer science conferences (e.g., OSDI, SOSP, DSN), we aim to mathematically bind the Rust execution to the Lean logic.
- [ ] **TLA+ Modeling:** Model the Liveness and View-Change timeout properties in TLA+ to complement the Safety proofs in Lean.
- [ ] **Differential Testing (Bisimulation):** Develop a bridge that feeds the exact same network events into the Lean state machine and the compiled Rust binary, asserting that their resultant states match byte-for-byte.

## Phase 5: Production L1 Features (Long Term)
- [ ] **Dynamic Validator Sets:** Allow $N$ and $f$ to change across epochs safely without halting the chain.
- [ ] **Distributed Key Generation (DKG):** Integrate Pedersen/Feldman VSS to allow trustless setup of the BLS keys.
- [ ] **Mempool & Execution Pipelining:** Separate the consensus layer from application state transition via an ABCI-like interface (similar to CometBFT).

