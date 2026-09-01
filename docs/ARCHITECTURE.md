# Sovereign Lattice – Architecture

## Dual-Plane Design
┌──────────────────────────────────────────────────────┐
│                  PROVABILITY PLANE                   │
│                     (Lean 4)                         │
│  • Gödel-Löb logic                                   │
│  • Quorum intersection                               │
│  • Single-view & multi-view safety                   │
│  • Zero sorry, machine-checked                       │
└─────────────────────┬────────────────────────────────┘
│ Mathematical Verification Bridge
┌─────────────────────▼────────────────────────────────┐
│                   EXECUTION PLANE                    │
│                      (Rust)                          │
│  • Asynchronous event-driven runtime                 │
│  • Multi-dealer Feldman / Pedersen DKG               │
│  • FROST & Threshold BLS signing                     │
│  • Strict no-fallback view-change                    │
└──────────────────────────────────────────────────────┘

## Data Flow

1. **Key Generation** – Joint DKG produces shares + group public key.  
2. **Transaction Proposal** – Leader proposes a block / batch.  
3. **Prepare & Commit** – Quorum certificates collected (BLS or FROST).  
4. **View Change** – Timeout triggers leader rotation; locked values are inherited.  
5. **Finality** – Once a quorum certificate is formed, the value is immutable by the Lean-proven invariants.

## Design Principles

- **Separation of concerns** – Mathematical truth lives in Lean; performance lives in Rust.
- **Zero-drift recovery** – Any validation failure aborts cleanly; no heuristic fallbacks.
- **Threshold cryptography first** – All quorum certificates are compact aggregate / threshold signatures.
