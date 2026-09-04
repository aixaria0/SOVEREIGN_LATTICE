# Formal Verification Coverage (Lean 4)

Sovereign Lattice bridges the gap between theoretical consensus safety and production engineering. The core safety invariants of our protocol are mathematically verified using the **Lean 4** theorem prover. 

This document maps the theoretical properties to their Lean 4 proofs and current Rust implementation status.

## Verification Matrix

| Property | Description | Lean 4 Proof | Rust Enforcement |
| :--- | :--- | :--- | :--- |
| **Quorum Intersection** | Any two quorums of size `2f+1` intersect by at least one honest node. | ✅ `quorum_intersection` | ✅ Strict `2f+1` checks |
| **Single-View Safety** | Two different digests cannot be committed at the same sequence in the same view. | ✅ `PBFT_Safety` | ✅ `verify()` bounds |
| **Cross-View Inheritance** | A valid `NewView` transitions safely, inheriting the highest prepared certificate. | ✅ `cross_view_inheritance`| ✅ `NewViewCertificate` logic |
| **Multi-View Safety** | No conflicting commits can occur across view changes. | ✅ `Multi_View_Safety` | ⏳ View-Change integration |
| **Protocol Liveness** | The network eventually commits a block if the primary is honest. | ❌ Unverified | ⏳ Timeout engine pending |
| **WAL Recovery Safety** | A crashed node recovers precisely to its pre-crash state without violating invariants. | ❌ Unverified | ✅ Implemented, unproven |

## Theorem Highlights

### 1. Quorum Intersection (`quorum_intersection`)
Located in the `SovereignLattice` namespace, this theorem proves that for any network of size `N = 3f + 1`, any two subsets of size `2f + 1` will mathematically intersect by at least `f + 1` nodes. By extension, this guarantees at least one completely honest node exists in the intersection.
* **Status:** Fully machine-checked. No `sorry` axioms.

### 2. PBFT Safety (`PBFT_Safety`)
Proves that if a quorum commits digest `d1` and a quorum commits digest `d2` for the same sequence and view, `d1` must equal `d2`. It relies heavily on the immutability of honest nodes' preparation phases.
* **Status:** Fully machine-checked. 

### 3. Multi-View Safety (`Multi_View_Safety`)
The hardest invariant in BFT systems. It proves that if a digest `d1` is committed in view `v1`, no other digest `d2` can be committed at the same sequence in any future view `v2`. It inductively relies on `cross_view_inheritance`.
* **Status:** Proven in Lean 4. The strict integration of this specific theorem into the Rust `handle_message` router is currently heavily enforced via the `selected_prepared_certificate` bindings.

## A Note on "Provably Infallible"

We aim for absolute transparency. Sovereign Lattice formally verifies **PBFT safety properties under standard Byzantine assumptions**. The proofs currently focus on the state machine transition logic. 
Components interacting with the OS layer (TCP Tokio transport, Disk I/O for WAL, and BLS cryptography primitives) are assumed to be secure and behave as specified by their respective crates.

