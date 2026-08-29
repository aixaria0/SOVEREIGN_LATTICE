<div align="center">

# Sovereign Lattice
### Provably Secure BFT Consensus Engine

*Engineered and Formally Verified by **Aria Fani** ([AixAria](https://github.com/AixAria))*

</div>

---

## Core Architecture

**Sovereign Lattice** is a high-assurance, production-grade Byzantine Fault Tolerant (PBFT) consensus engine written in **Rust**, with its core safety invariants formally verified and machine-checked in **Lean 4**. 

Developed under the **AixAria** research initiative, this framework eliminates protocol ambiguity, delivering absolute mathematical immunity against network partitions, equivocation, and adversarial leader failures.

### Key Invariants
- **Strict No-Fallback Semantics:** Purges ambiguous quorum fallbacks during view changes. Any invalid `NewView` certificate triggers an immediate `MISSING_QUORUM_CERTIFICATE` rejection.
- **Dual-Path Alignment:** Live execution paths and Write-Ahead Log (WAL) crash recovery share identical state-machine invariants, preventing state drift.
- **Zero-Axiom Lean Verification:** The multi-view safety core is formally verified in Lean 4 with **zero axioms and zero `sorry` placeholders**, guaranteeing permanent historical immutability.

---

## Repository Structure

- `src/pbft.rs` — Core consensus engine, strict NewView verification, and state machine logic.
- `lean/GodelLobBFT.lean` — Formal verification proofs of Quorum Intersection, Single-View Safety, and Multi-View Equivocation Prevention.
- `tests/byzantine_cluster.rs` — Adversarial integration test suite validating fault injection and strict error handling.

---

## Formal Verification Guarantees (Lean 4)

Our formal specification models honest local memory traces (`Option` semantics) and proves the following foundational theorems:

- **Quorum Intersection (`quorum_intersection_size`):** In a network of $N = 3f + 1$, any two quorums of size $\ge 2f + 1$ intersect at least in $f + 1$ nodes.
- **Single-View Safety (`PBFT_Safety`):** Conflicting digests can never be committed within the same view.
- **Cross-View Inheritance (`cross_view_inheritance`):** View changes strictly inherit prior commitments via honest quorum overlaps.
- **Multi-View Safety (`Multi_View_Safety`):** Global historical immutability is preserved across arbitrary leader changes and view transitions.

---

## Testing & Verification

### Running Rust Byzantine Integration Tests
Execute the adversarial test suite to validate fault isolation and strict error checking:
```bash
cargo test --test byzantine_cluster

Checking Formal Proofs in Lean 4
Verify the formal model using Lean 4 and Mathlib:
lake build

Author & Lab
 * Principal Architect: Aria Fani
 * Research Brand: AixAria
 * License: MIT

