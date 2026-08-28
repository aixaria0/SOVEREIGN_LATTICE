# 🏛️ SOVEREIGN LATTICE
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Verified Engine](https://img.shields.io/badge/Verified-Lean_4-emerald.svg)](#-the-genesis-block-formal-verification)
[![Runtime](https://img.shields.io/badge/Runtime-Rust-orange.svg)](#-the-executable-layer-rust)
**Sovereign Lattice** is a formally verified, Byzantine Fault Tolerant (BFT) consensus framework. It bridges the absolute certainty of Gödel-Löb provability logic with the high-performance execution of modern Rust cryptography.
By splitting the architecture into a strict mathematical verification layer and a high-speed runtime layer, Sovereign Lattice ensures that consensus safety is not just assumed, but mathematically proven before a single byte of data is transmitted.
---
## 🔬 Architecture: The Two-Tier Engine
Sovereign Lattice operates on a dual-layer architecture, isolating logical constraint proofs from asynchronous execution.
### 1. The Genesis Block (Formal Verification in Lean 4)
The core safety rules of the network are etched into **Lean 4**. This layer removes heuristic trust entirely, replacing it with machine-checked proofs.
*   **Gödel-Löb Consistency:** Prevents circular self-justification within nodes.
*   **The $\delta = 1$ Lock:** Mathematically ensures global unrestricted state and geometric boundaries.
*   **BFT Safety Cores:** Formally verifies the `Commit implies Prepare` obligation across PBFT and HotStuff consensus models.
*   **Omnipresence Protocol:** Inductively proves that honest paths propagate state without consistency collapse.
### 2. The Executable Layer (Runtime in Rust)
The theoretical constraints proved in Lean 4 are mapped into a secure, event-driven runtime environment built in **Rust**.
*   **PBFT/HotStuff Monitor:** Event-driven state machine handling view-changes, commits, and garbage collection.
*   **Threshold Cryptography:** Implements Feldman VSS Distributed Key Generation (DKG).
*   **BLS12-381 Aggregation:** Compact signature aggregation for scalable, verifiable Byzantine thresholds.
---
## ⚙️ Core Capabilities

| Feature | Description | Implementation |
| :--- | :--- | :--- |
| **BFT Consensus** | 3-Phase Commit (PBFT) & View-Change. | Lean 4 (Proof) / Rust (Logic) |
| **Asynchronous Liveness** | Probabilistic Common Coin fallback. | Lean 4 (Axiomatic) |
| **Threshold Sigs** | BLS & FROST partial signing/aggregation. | Rust (`bls12_381`) |
| **Garbage Collection** | Stable checkpoints and watermark clearing. | Rust |

---
## 📂 Repository Structure
*   `formal_verification/` — Lean 4 workspace containing the `GodelLobBFT` namespace and absolute proofs.
*   `rust_engine/` — Rust workspace containing the executable PBFT monitor and cryptographic primitives.
*   `docs/` — Theoretical framework and formalization strategies.
---
## 🛠 Status
**Phase:** Genesis Block Sealed.  
The core BFT safety theorems and threshold cryptographic prototypes are successfully bridged.
---
## 🖋 Author
**Aria Fani** | [AixAria](https://github.com/aixaria0)  
*Architecting formally verified autonomy.*
