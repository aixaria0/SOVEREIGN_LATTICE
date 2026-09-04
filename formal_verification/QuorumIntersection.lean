namespace SovereignLattice

variable {Node : Type*} [DecidableEq Node] [Fintype Node]

/-- Classic PBFT network size. -/
def N (f : ℕ) : ℕ := 3 * f + 1

/-- A quorum has size at least 2f+1. -/
def IsQuorum (f : ℕ) (Q : Finset Node) : Prop :=
  Q.card ≥ 2 * f + 1

/-- 
Fundamental safety lemma of PBFT-style protocols.
Any two quorums of size ≥ 2f+1 in a network of size 3f+1 
intersect in at least f+1 nodes.
-/
theorem quorum_intersection
    (f : ℕ)
    (Q₁ Q₂ : Finset Node)
    (hQ₁ : IsQuorum f Q₁)
    (hQ₂ : IsQuorum f Q₂)
    (hUniv : Fintype.card Node = N f) :
    (Q₁ ∩ Q₂).card ≥ f + 1 := by
  have h_inc_exc : (Q₁ ∩ Q₂).card + (Q₁ ∪ Q₂).card = Q₁.card + Q₂.card := 
    Finset.card_inter_add_card_union Q₁ Q₂
  have h_le : (Q₁ ∪ Q₂).card ≤ N f := by
    rw [← hUniv]
    exact Finset.card_le_univ _
  unfold IsQuorum at hQ₁ hQ₂
  omega

end SovereignLattice
