# Sovereign Lattice: Threat Model & Security Assumptions

This document outlines the formal threat model, adversarial capabilities, and mitigation strategies implemented within the Sovereign Lattice PBFT consensus engine.

## 1. Core Assumptions

To guarantee safety and eventual liveness, Sovereign Lattice operates under the standard Byzantine Fault Tolerance (BFT) assumptions:
* **Network Topology:** The network consists of `N` nodes, where `N = 3f + 1`, and `f` is the maximum number of Byzantine (malicious or faulty) nodes.
* **Cryptography:** The BLS12-381 elliptic curve and its underlying pairing-based cryptography are secure against classical polynomial-time adversaries.
* **Network Synchrony:** The network is assumed to be partially synchronous. Safety is guaranteed under complete asynchrony, while liveness relies on periods of synchrony.
* **Authenticated Channels:** (Assumption) Nodes communicate over authenticated, point-to-point channels (e.g., mTLS / Noise Protocol - *Implementation pending in transport layer*).

## 2. Threat Mitigation Matrix

| Attack Vector | Status | Mitigation Mechanism |
| :--- | :--- | :--- |
| **Double Commit (Safety Violation)** | ✅ Proven | Requires `2f + 1` BLS signatures. Lean 4 formal proof guarantees honest quorum intersection. |
| **Leader Equivocation** | ✅ Prevented | Replicas actively reject differing `PrePrepare` digests for the same sequence and view. |
| **Ghost Certificate Attack** | ✅ Prevented | `NewView` transitions strictly validate inherited Quorum Certificates against bounded cryptographic signatures. |
| **Signature Forgery** | ✅ Prevented | All state transitions strictly require threshold-verified BLS12-381 signatures. |
| **Network Partition / Split Brain** | ✅ Prevented | System halts safely if `2f + 1` quorum is unreachable. |
| **Replay Attacks** | ⏳ Pending | Sequence tracking is implemented, but strict nonces at the transport layer are under development. |
| **Sybil Attacks** | ⏳ Out of Scope | PBFT assumes a permissioned registry. A Sybil-resistance mechanism (e.g., PoS) must be implemented at the application layer. |

## 3. Detailed Attack Vectors

### 3.1 Ghost Certificate Attack (View-Change Exploitation)
**Threat:** A malicious leader constructs a `NewView` message claiming a high-sequence prepared certificate that was never actually prepared by an honest quorum, attempting to force the network to adopt a malicious state.
**Mitigation:** The `cross_view_inheritance` logic requires the leader to embed the exact `PreparedCertificate` matching the highest sequence claimed by the quorum. The Rust engine verifies all `2f + 1` signatures on this embedded certificate. (Covered by internal adversarial test: `test_ghost_certificate_attack_rejected`).

### 3.2 Leader Equivocation
**Threat:** A Byzantine primary sends different `PrePrepare` blocks to different replicas for the same sequence number, attempting to split the network.
**Mitigation:** The Rust state machine caches `pre_prepared_proposals`. If a replica receives a valid signature from the primary but the digest differs from an already cached proposal for that view/sequence, it immediately drops the payload and logs an `EQUIVOCATION_DETECTED` error.

### 3.3 Crash Faults & State Loss
**Threat:** An honest node crashes after voting, loses its state in RAM, reboots, and votes differently, violating the `f` Byzantine assumption.
**Mitigation:** Integrated Write-Ahead Logging (WAL). All state mutations (PrePrepare, Prepare, Commit, ViewChange) are durably flushed to disk (`consensus_wal.log`) before the Rust engine processes them, allowing deterministic recovery.

