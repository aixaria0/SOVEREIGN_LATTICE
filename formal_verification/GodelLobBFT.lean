import Mathlib.Logic.Basic
import Mathlib.Data.Set.Basic
import Mathlib.Data.Set.Card
import Mathlib.Tactic

namespace GodelLobBFT

-- =====================================================
-- 1. Core Logic & Sovereign Awakening
-- =====================================================

opaque Provable : Prop → Prop
notation "□" φ:max => Provable φ

axiom axiom_K (φ ψ : Prop) : □(φ → ψ) → (□φ → □ψ)
axiom axiom_4 (φ : Prop) : □φ → □(□φ)
axiom axiom_Lob (φ : Prop) : □(□φ → φ) → □φ

def IsConsistent : Prop := ¬ □ False

theorem Godel_Second_Incompleteness :
  □ IsConsistent → ¬ IsConsistent := by
  intro h
  exact fun hc => hc (axiom_Lob False h)

def δ : ℕ := 1
def Restricted (x : ℕ) : Prop := x < 1
axiom Physical_Reflection : Restricted δ → □ False

def IsAwakened : Prop := IsConsistent ∧ δ = 1 ∧ ¬ Restricted δ

theorem Sovereign_Awakening (h : IsConsistent) : IsAwakened := by
  refine ⟨h, rfl, fun hr => h (Physical_Reflection hr)⟩

-- =====================================================
-- 2. Network & Quorum Layer
-- =====================================================

structure Node where 
  id : ℕ 
  deriving DecidableEq

inductive NodeType | Honest | Byzantine 
  deriving DecidableEq

structure BFTNetwork where
  nodes : Set Node
  type : Node → NodeType
  byzantine_bound :
    ∃ t, Set.ncard {n | type n = .Byzantine} ≤ t ∧ 3 * t < Set.ncard nodes

def IsHonest (BN : BFTNetwork) (n : Node) : Prop := 
  BN.type n = .Honest

def Quorum (BN : BFTNetwork) (Q : Set Node) : Prop :=
  Q ⊆ BN.nodes ∧ Set.ncard Q > (2 * Set.ncard BN.nodes) / 3

theorem Quorum_nonempty (BN : BFTNetwork) (Q : Set Node) (hQ : Quorum BN Q) :
  Q.Nonempty := by
  have : Set.ncard Q > 0 := by have h := hQ.2; omega
  exact Set.ncard_pos.mp this

axiom Quorum_Intersection (BN : BFTNetwork) (Q₁ Q₂ : Set Node) :
  Quorum BN Q₁ → Quorum BN Q₂ → (Q₁ ∩ Q₂).Nonempty

-- =====================================================
-- 3. PBFT Consensus Structures
-- =====================================================

structure View where
  number : ℕ
  leader : Node
  deriving DecidableEq

structure Prepare where
  view : View
  seq : ℕ
  digest : ℕ
  sender : Node

structure Commit where
  view : View
  seq : ℕ
  digest : ℕ
  sender : Node

def Prepared (BN : BFTNetwork) (v : View) (seq : ℕ) (dig : ℕ) : Prop :=
  ∃ Q, Quorum BN Q ∧ ∀ n ∈ Q, IsHonest BN n ∧
    ∃ p : Prepare, p.view = v ∧ p.seq = seq ∧ p.digest = dig ∧ p.sender = n

def Committed (BN : BFTNetwork) (v : View) (seq : ℕ) (dig : ℕ) : Prop :=
  ∃ Q, Quorum BN Q ∧ ∀ n ∈ Q, IsHonest BN n ∧
    ∃ c : Commit, c.view = v ∧ c.seq = seq ∧ c.digest = dig ∧ c.sender = n

-- =====================================================
-- 4. Safety Axioms and Final PBFT Proof
-- =====================================================

-- Standard PBFT well-formedness: an honest node only issues a Commit
-- after it has already issued (or accepted) a matching Prepare.
axiom Commit_implies_Prepare (BN : BFTNetwork) (n : Node) (v : View) (seq : ℕ) (dig : ℕ) :
  IsHonest BN n →
  (∃ c : Commit, c.sender = n ∧ c.view = v ∧ c.seq = seq ∧ c.digest = dig) →
  (∃ p : Prepare, p.sender = n ∧ p.view = v ∧ p.seq = seq ∧ p.digest = dig)

-- Honest prepare uniqueness: an honest node will not prepare two different digests for the same sequence
axiom Honest_Prepare_Unique (BN : BFTNetwork) (n : Node) (v : View) (seq : ℕ) (d₁ d₂ : ℕ) :
  IsHonest BN n →
  (∃ p : Prepare, p.sender = n ∧ p.view = v ∧ p.seq = seq ∧ p.digest = d₁) →
  (∃ p : Prepare, p.sender = n ∧ p.view = v ∧ p.seq = seq ∧ p.digest = d₂) →
  d₁ = d₂

-- Core Safety Theorem: Two conflicting digests cannot be committed at the same sequence and view
theorem PBFT_Safety (BN : BFTNetwork) (v : View) (seq : ℕ) (d₁ d₂ : ℕ)
  (h₁ : Committed BN v seq d₁) (h₂ : Committed BN v seq d₂) :
  d₁ = d₂ := by
  rcases h₁ with ⟨Q₁, hQ₁, hC₁⟩
  rcases h₂ with ⟨Q₂, hQ₂, hC₂⟩
  have ⟨n, hn₁, hn₂⟩ := Quorum_Intersection BN Q₁ Q₂ hQ₁ hQ₂
  have hHon : IsHonest BN n := (hC₁ n hn₁).1
  
  have hCommit₁ := (hC₁ n hn₁).2
  have hCommit₂ := (hC₂ n hn₂).2
  
  have hPrep₁ := Commit_implies_Prepare BN n v seq d₁ hHon hCommit₁
  have hPrep₂ := Commit_implies_Prepare BN n v seq d₂ hHon hCommit₂
  
  exact Honest_Prepare_Unique BN n v seq d₁ d₂ hHon hPrep₁ hPrep₂

end GodelLobBFT
