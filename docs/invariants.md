# Sovereign Lattice – Core Invariants

This document renders the machine-checked mathematical invariants of the Provability Plane in human-readable form.

## Quorum Intersection (Fundamental Safety Lemma)

**Setting**  
Network size $N = 3f + 1$, where $f$ is the maximum number of Byzantine nodes.  
A *quorum* is any set of nodes of size at least $2f + 1$.

**Theorem**  
Any two quorums $Q_1$ and $Q_2$ satisfy
$$|Q_1 \cap Q_2| \ge f + 1.$$

**Proof (combinatorial)**  
Assume for contradiction that $|Q_1 \cap Q_2| \le f$.  
Then
$$|Q_1 \cup Q_2| = |Q_1| + |Q_2| - |Q_1 \cap Q_2| \ge (2f+1) + (2f+1) - f = 3f + 2.$$
This exceeds the total number of nodes $N = 3f + 1$, which is impossible.  
Hence the assumption is false and every pair of quorums intersects in at least $f + 1$ nodes.

**Consequences**  
- No two conflicting values can both collect a quorum of prepares or commits.  
- At least one honest node belongs to every pair of quorums, preventing divergent decisions.  
- All higher safety properties (single-view safety, cross-view inheritance, historical immutability) rest on this lemma.

This theorem is formalized in Lean 4 with zero axioms and zero `sorry`.
