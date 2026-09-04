# Sovereign Lattice: Protocol Specification

This document provides the formal specification for the Sovereign Lattice consensus engine. It defines the state machine, cryptographic bounds, and transition rules that govern the network.

## 1. System Model and Cryptography

Sovereign Lattice operates a Byzantine Fault Tolerant (BFT) state machine replication protocol over a partially synchronous network.
* **Network Size:** $N$ nodes, where $N = 3f + 1$.
* **Fault Tolerance:** Tolerates up to $f$ Byzantine nodes.
* **Quorum Requirement:** Any state transition requiring consensus mandates a quorum of $Q \ge 2f + 1$ valid votes.
* **Cryptography:** All messages are authenticated using **BLS12-381** threshold cryptography. Let $pk_i$ be the public key of node $i$ and $sk_i$ be its secret key. A signature $\sigma$ on message $m$ is valid if and only if $Verify(pk_i, \sigma, m) = true$.

## 2. Node State Definition

Each replica $i$ maintains the following local state:
* $v$: The current view number (initialized to $0$).
* $seq$: The highest sequence number observed or proposed.
* $prepared$: A map of valid Prepared Certificates, keyed by $(v, seq)$.
* $committed$: A map of valid Commit Certificates, keyed by $(v, seq)$.
* $WAL$: A Write-Ahead Log persisting state transitions to stable storage before in-memory mutation.

## 3. Message Formats

To eliminate deserialization panics, the core network layer strictly enforces a **101-byte fixed-size payload** for standard consensus phases. The byte layout is defined as follows:

| Offset | Length | Field | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` | 1 | `phase` | `u8` | 0: PrePrepare, 1: Prepare, 2: Commit, 3: ViewChange |
| `1` | 8 | `view` | `u64` | The consensus view number (Big-Endian). |
| `9` | 8 | `seq` | `u64` | The block sequence number (Big-Endian). |
| `17` | 32 | `digest` | `[u8; 32]` | SHA-256 (or equivalent) block payload digest. |
| `49` | 4 | `sender_id` | `u32` | The unique ID of the transmitting node. |
| `53` | 48 | `signature` | `G1Affine`| Compressed BLS12-381 cryptographic signature. |

*Note: `NewView` messages encapsulate multiple certificates and currently operate over a dynamic payload structure outside the base 101-byte bounds.*

## 4. State Transition Rules

### 4.1 Pre-Prepare Phase
The primary for view $v$ computes $p = v \pmod N$. 
Node $p$ broadcasts $\langle \text{PrePrepare}, v, seq, d, \sigma_p \rangle$.
**Acceptance Rule:** A replica $i$ accepts the message if:
1. The sender is the valid primary for view $v$.
2. $v$ matches the replica's current view.
3. No conflicting $\text{PrePrepare}$ (same $v$, same $seq$, different $d$) has been accepted.
4. The signature $\sigma_p$ is cryptographically valid.

### 4.2 Prepare Phase
Upon accepting a valid `PrePrepare`, replica $i$ broadcasts $\langle \text{Prepare}, v, seq, d, \sigma_i \rangle$.
**Transition to Prepared:** A replica achieves a `PreparedCertificate` for $(v, seq, d)$ once it collects a set $P$ of valid `Prepare` messages (including its own or the primary's `PrePrepare`) such that $|P| \ge 2f + 1$.

### 4.3 Commit Phase
Upon achieving a `PreparedCertificate`, replica $i$ broadcasts $\langle \text{Commit}, v, seq, d, \sigma_i \rangle$.
**Transition to Committed:** A replica strictly commits digest $d$ at sequence $seq$ once it collects a set $C$ of valid `Commit` messages such that $|C| \ge 2f + 1$. 

### 4.4 View-Change Protocol
If a replica detects primary failure (via timeout), it increments its view to $v+1$ and broadcasts $\langle \text{ViewChange}, v+1, seq_p, d_p, \sigma_i \rangle$, where $(seq_p, d_p)$ represents its highest `PreparedCertificate` (or $0$ if none exists).

The new primary $p' = (v+1) \pmod N$ waits for $2f + 1$ `ViewChange` votes to construct a `NewViewCertificate`. 
**Inheritance Rule:** The `NewViewCertificate` must mathematically bind to the highest sequence number reported in the $2f + 1$ quorum. Replicas will unconditionally reject the `NewView` transition if the primary fails to provide the cryptographic proof of the inherited `PreparedCertificate`.

