<h1 align="center">⬡ SOVEREIGN LATTICE</h1>
<h4 align="center">Formally Verified Asynchronous PBFT Consensus Engine</h4>

<p align="center">
  <a href="https://github.com/aixaria0/SOVEREIGN_LATTICE/actions">
    <img src="https://github.com/aixaria0/SOVEREIGN_LATTICE/actions/workflows/verify.yml/badge.svg" alt="CI/CD Pipeline">
  </a>
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Rust-Tokio_Transport-000000?style=for-the-badge&logo=rust" alt="Rust">
  </a>
  <a href="https://leanprover.github.io/">
    <img src="https://img.shields.io/badge/Lean_4-Formal_Proofs-4B0082?style=for-the-badge" alt="Lean 4">
  </a>
  <a href="https://github.com/aixaria0/SOVEREIGN_LATTICE">
    <img src="https://img.shields.io/badge/Crypto-Threshold_BLS-00FF66?style=for-the-badge&color=050505" alt="Crypto">
  </a>
</p>

<h3 align="center"><a href="https://aixaria0.github.io/SOVEREIGN_LATTICE/">🌐 LAUNCH LIVE COMMAND CENTER</a></h3>

---

**Sovereign Lattice** is an experimental research prototype demonstrating the architectural integration of formal mathematical proofs (Lean 4) with a high-performance, asynchronous Byzantine Fault Tolerant (PBFT) networking engine (Rust).

Unlike standard consensus engines that rely purely on runtime testing, this project establishes its foundational safety guarantees at the mathematical level using Gödel-Löb logic, while executing real-time cryptographic validation via Tokio.

## 🏗️ Architecture & Core Components

The architecture bridges the gap between theoretical consensus models and live network execution through three isolated but interconnected layers:

### 1. Formal Verification Layer (Lean 4)
The absolute truth of the consensus engine is strictly verified in `formal_verification/GodelLobBFT.lean`.
* **Quorum Intersection:** Mathematically proven that no two honest quorums can intersect at a Byzantine node.
* **PBFT Safety:** Formally verified that `Commit implies Prepare` and `Honest Prepare Uniqueness`, ensuring two conflicting block digests can never be committed at the same sequence height.

### 2. Cryptographic Core (Rust)
No mock cryptography. The engine evaluates actual signatures on the fly.
* **Standardized Hash-to-Curve:** Full compliance with **RFC 9380** (`BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`) preventing cross-protocol vulnerabilities.
* **Threshold BLS12-381:** Utilizes optimal ate pairings `e(sig, G2) == e(H(m), pk)` to securely verify payload integrity.

### 3. Asynchronous Transport (Tokio)
* **Zero-Trust Framing:** Implementation of strict 4-byte length-prefixed payload framing.
* **Memory Exhaustion Mitigation:** Hardcoded boundaries (40 to 4096 bytes) reject malformed, oversized, or microscopic frames before they reach the deserialization layer.

---

## 🛡️ Verification & Audit Status

The current commit workflows are fully automated via GitHub Actions on every push:
- `lake build` (Lean 4 Formal Proofs)
- `cargo test --workspace --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`

> **Note on Production Readiness:** These automated checks confirm reproducible builds, structural BFT conditions, and strict compiler hygiene in a documented environment. This repository is currently an **experimental research prototype**. It is not an independent security audit, and the Lean model formally verifies structural PBFT conditions, not the compiled Rust binary itself. 

## 🚀 Quick Start (Local Daemon)

Boot the secure daemon on your local environment:

```bash
cd rust_engine
cargo run

To test network framing and cryptographic payload ingestion, inject a zero-trust packet via the hardened TCP socket:
cargo run --bin injector

<p align="center">
<b>Architect:</b> AixAria | <a href="https://github.com/aixaria0">@aixaria0</a>
</p>

