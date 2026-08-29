<div align="center">

# Sovereign Lattice
### Provably Secure BFT Consensus Engine

*Engineered and Formally Verified by **Aria Fani** ([AixAria](https://github.com/AixAria0))*

</div>

---

# SOVEREIGN LATTICE: The Blueprint of Infallible Consensus

## 1. Abstract
Current Byzantine Fault Tolerant (BFT) systems rely on heuristic safety assumptions and probabilistic finality. **Sovereign Lattice** introduces a paradigm shift: a mathematically verified consensus framework bound by Gödel-Löb provability logic, executed in a high-performance Rust environment.

## 2. Dual-Layer Architecture
The system is strictly divided into two operational planes to isolate logical constraints from asynchronous network execution:

*   **The Provability Plane (Lean 4):** Acts as the absolute Genesis Block. It verifies the $\delta = 1$ state and ensures that network consistency is not just achieved, but logically infallible. It formally discharges BFT safety obligations, such as proving that a `Commit` strictly implies a valid `Prepare` phase.
*   **The Execution Plane (Rust):** An asynchronous, event-driven state machine handling real-time replication, garbage collection, and node timeout management without compromising the proved constraints.

## 3. Cryptographic Foundation
Sovereign Lattice leverages state-of-the-art threshold cryptography to ensure scalability and Byzantine resistance:
*   **Distributed Key Generation (DKG):** Feldman VSS integrated with Non-Interactive Zero-Knowledge (NIZK) Schnorr proofs for publicly verifiable share distribution.
*   **Signature Aggregation:** Threshold BLS over the BLS12-381 curve ensures constant-time verification and minimal bandwidth overhead, regardless of the validator count.
*   **FROST Integration:** A highly optimized two-round threshold Schnorr signing protocol for low-latency state confirmation.

---

## Core Invariants & Strict Semantics
*   **Strict No-Fallback Semantics:** Purges ambiguous quorum fallbacks during view changes. Any invalid `NewView` certificate triggers an immediate `MISSING_QUORUM_CERTIFICATE` rejection.
*   **Dual-Path Alignment:** Live execution paths and Write-Ahead Log (WAL) crash recovery share identical state-machine invariants, preventing state drift.
*   **Zero-Axiom Lean Verification:** The multi-view safety core is formally verified in Lean 4 with **zero axioms and zero `sorry` placeholders**, guaranteeing permanent historical immutability.

---

## Repository Structure

- `src/pbft.rs` — Core consensus engine, strict NewView verification, and state machine logic.
- `lean/GodelLobBFT.lean` — Formal verification proofs of Quorum Intersection, Single-View Safety, and Multi-View Equivocation Prevention.
- `tests/byzantine_cluster.rs` — Adversarial integration test suite validating fault injection and strict error handling.
- `docs/whitepaper.md` — Full academic whitepaper and architectural specification.

---

## Formal Verification Layer (Mathematical Invariants)

Our formal specification models honest local memory traces (`Option` semantics) and machine-checks absolute safety theorems with zero axioms and zero `sorry` placeholders in **Lean 4**:

- **Quorum Intersection (`quorum_intersection_size`):** In a network of $N = 3f + 1$, any two quorums of size $\ge 2f + 1$ intersect at least in $f + 1$ nodes.
- **Single-View Safety (`PBFT_Safety`):** Conflicting digests can never be committed within the same view.
- **Cross-View Inheritance (`cross_view_inheritance`):** View changes strictly inherit prior commitments via honest quorum overlaps.
- **Multi-View Safety (`Multi_View_Safety`):** Global historical immutability is preserved across arbitrary leader changes and view transitions.

**Check Formal Proofs (Lean 4 Engine):**
```bash
lake build

Operational Testing & Execution (Rust Runtime)
Running Byzantine Integration Tests
Execute the adversarial test suite via Cargo to validate runtime fault isolation, strict error checking, and no-fallback enforcement:
cargo test --test byzantine_cluster

Author & Lab
 * Principal Architect: Aria Fani
 * Research Brand: AixAria
 * License: MIT

