import Mathlib.Data.Finset.Basic
import Mathlib.Tactic

set_option linter.unusedVariables false
set_option linter.unusedSectionVars false

namespace GodelLobBFT

variable {Node : Type} [DecidableEq Node] [Fintype Node]

local notation "N" => Fintype.card Node

def IsQuorum {α : Type} (f : ℕ) (Q : Finset α) : Prop := Q.card ≥ 2 * f + 1

theorem quorum_intersection_size {f : ℕ} (hN : N = 3 * f + 1)
  (Q₁ Q₂ : Finset Node) (hQ₁ : IsQuorum f Q₁) (hQ₂ : IsQuorum f Q₂) :
  (Q₁ ∩ Q₂).card ≥ f + 1 := by
  have h_union : (Q₁ ∪ Q₂).card ≤ N := Finset.card_le_univ _
  have h_inc_exc : (Q₁ ∩ Q₂).card + (Q₁ ∪ Q₂).card = Q₁.card + Q₂.card := Finset.card_inter_add_card_union _ _
  unfold IsQuorum at hQ₁ hQ₂
  omega

theorem honest_quorum_intersection {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (Q₁ Q₂ : Finset Node) (hQ₁ : IsQuorum f Q₁) (hQ₂ : IsQuorum f Q₂) :
  ∃ n ∈ Q₁ ∩ Q₂, n ∉ Byzantine := by
  have h_int_size := quorum_intersection_size hN Q₁ Q₂ hQ₁ hQ₂
  by_contra h_all_byz
  have h_subset : Q₁ ∩ Q₂ ⊆ Byzantine := by
    intro x hx
    by_contra h_not_byz
    apply h_all_byz
    exact ⟨x, hx, h_not_byz⟩
  have h_subset_card : (Q₁ ∩ Q₂).card ≤ Byzantine.card := Finset.card_le_card h_subset
  omega

structure View where
  number : ℕ
deriving DecidableEq

structure HonestState where
  prepared : View → ℕ → Option ℕ
  committed : View → ℕ → Option ℕ
  locked_digests : ℕ → Option ℕ
  rule_commit_implies_prepare : ∀ v seq d, committed v seq = some d → prepared v seq = some d
  rule_lock_enforcement : ∀ v seq d, prepared v seq = some d → locked_digests seq = some d
  rule_lock_consistency : ∀ v seq d1 d2, locked_digests seq = some d1 → prepared v seq = some d2 → d1 = d2

def IsHonest (Byzantine : Finset Node) (network_state : Node → Option HonestState) (n : Node) : Prop :=
  n ∉ Byzantine ∧ (network_state n).isSome

def NodePrepared (network_state : Node → Option HonestState) (n : Node) (v : View) (seq : ℕ) (d : ℕ) : Prop :=
  ∀ state, network_state n = some state → state.prepared v seq = some d

def NodeCommitted (network_state : Node → Option HonestState) (n : Node) (v : View) (seq : ℕ) (d : ℕ) : Prop :=
  ∀ state, network_state n = some state → state.committed v seq = some d

def Prepared (f : ℕ) (Byzantine : Finset Node) (network_state : Node → Option HonestState) (v : View) (seq : ℕ) (dig : ℕ) : Prop :=
  ∃ Q, IsQuorum f Q ∧ ∀ n ∈ Q, IsHonest Byzantine network_state n → NodePrepared network_state n v seq dig

def Committed (f : ℕ) (Byzantine : Finset Node) (network_state : Node → Option HonestState) (v : View) (seq : ℕ) (dig : ℕ) : Prop :=
  ∃ Q, IsQuorum f Q ∧ ∀ n ∈ Q, IsHonest Byzantine network_state n → NodeCommitted network_state n v seq dig

theorem honest_prepare_unique (Byzantine : Finset Node) (network_state : Node → Option HonestState)
  (v : View) (seq : ℕ) (d₁ d₂ : ℕ) (n : Node)
  (hHonest : IsHonest Byzantine network_state n)
  (hP1 : NodePrepared network_state n v seq d₁)
  (hP2 : NodePrepared network_state n v seq d₂) :
  d₁ = d₂ := by
  rcases hHonest with ⟨_, hState⟩
  cases h : network_state n with
  | none =>
    rw [h] at hState
    simp_all
  | some state =>
    have eq1 := hP1 state h
    have eq2 := hP2 state h
    rw [eq1] at eq2
    injection eq2

theorem honest_commit_implies_prepare (Byzantine : Finset Node) (network_state : Node → Option HonestState)
  (v : View) (seq : ℕ) (d : ℕ) (n : Node)
  (hHonest : IsHonest Byzantine network_state n)
  (hC : NodeCommitted network_state n v seq d) :
  NodePrepared network_state n v seq d := by
  intro state hState
  have hComm := hC state hState
  exact state.rule_commit_implies_prepare v seq d hComm

theorem actual_no_equivocation_across_views {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (network_state : Node → Option HonestState)
  (v1 v2 : View) (seq : ℕ) (dig1 dig2 : ℕ)
  (h_network_valid : ∀ n, n ∉ Byzantine → (network_state n).isSome)
  (h_commit1 : Committed f Byzantine network_state v1 seq dig1)
  (h_prep2 : Prepared f Byzantine network_state v2 seq dig2) :
  dig1 = dig2 := by
  rcases h_commit1 with ⟨Q₁, hQ₁, hC₁⟩
  rcases h_prep2 with ⟨Q₂, hQ₂, hP₂⟩
  have ⟨n, hn_int, hn_not_byz⟩ := honest_quorum_intersection hN Byzantine hByz Q₁ Q₂ hQ₁ hQ₂
  have hn_honest : IsHonest Byzantine network_state n := ⟨hn_not_byz, h_network_valid n hn_not_byz⟩
  have hn_in_Q1 : n ∈ Q₁ := (Finset.mem_inter.mp hn_int).left
  have hn_in_Q2 : n ∈ Q₂ := (Finset.mem_inter.mp hn_int).right
  have hn_commits_d1 := hC₁ n hn_in_Q1 hn_honest
  have hn_prepares_d2 := hP₂ n hn_in_Q2 hn_honest
  have hn_prepares_d1 := honest_commit_implies_prepare Byzantine network_state v1 seq dig1 n hn_honest hn_commits_d1
  rcases hn_honest with ⟨_, hState⟩
  cases h : network_state n with
  | none => 
    rw [h] at hState
    simp_all
  | some state =>
    have hp1_eq := hn_prepares_d1 state h
    have hlock_eq := state.rule_lock_enforcement v1 seq dig1 hp1_eq
    have hp2_eq := hn_prepares_d2 state h
    exact state.rule_lock_consistency v2 seq dig1 dig2 hlock_eq hp2_eq

theorem Multi_View_Safety {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (network_state : Node → Option HonestState)
  (v1 v2 : View) (seq : ℕ) (d1 d2 : ℕ)
  (h_v2_ge_v1 : v2.number ≥ v1.number)
  (h_network_valid : ∀ n, n ∉ Byzantine → (network_state n).isSome)
  (h_commit1 : Committed f Byzantine network_state v1 seq d1)
  (h_commit2 : Committed f Byzantine network_state v2 seq d2) :
  d1 = d2 := by
  have h_cases : v1.number = v2.number ∨ v1.number < v2.number := by omega
  rcases h_cases with heq | hlt
  · have h_v1_eq_v2 : v1 = v2 := by cases v1; cases v2; simp_all
    rw [h_v1_eq_v2] at h_commit1
    rcases h_commit1 with ⟨Q₁, hQ₁, hC₁⟩
    rcases h_commit2 with ⟨Q₂, hQ₂, hC₂⟩
    have ⟨n, hn_int, hn_not_byz⟩ := honest_quorum_intersection hN Byzantine hByz Q₁ Q₂ hQ₁ hQ₂
    have hn_honest : IsHonest Byzantine network_state n := ⟨hn_not_byz, h_network_valid n hn_not_byz⟩
    have hn_in_Q1 : n ∈ Q₁ := (Finset.mem_inter.mp hn_int).left
    have hn_in_Q2 : n ∈ Q₂ := (Finset.mem_inter.mp hn_int).right
    have hn_commits_d1 := hC₁ n hn_in_Q1 hn_honest
    have hn_commits_d2 := hC₂ n hn_in_Q2 hn_honest
    have hn_prepares_d1 := honest_commit_implies_prepare Byzantine network_state v2 seq d1 n hn_honest hn_commits_d1
    have hn_prepares_d2 := honest_commit_implies_prepare Byzantine network_state v2 seq d2 n hn_honest hn_commits_d2
    exact honest_prepare_unique Byzantine network_state v2 seq d1 d2 n hn_honest hn_prepares_d1 hn_prepares_d2
  · rcases h_commit2 with ⟨Q₂, hQ₂, hC₂⟩
    have h_prep2 : Prepared f Byzantine network_state v2 seq d2 := by
      use Q₂
      exact ⟨hQ₂, fun n hn_in h_honest => honest_commit_implies_prepare Byzantine network_state v2 seq d2 n h_honest (hC₂ n hn_in h_honest)⟩
    exact actual_no_equivocation_across_views hN Byzantine hByz network_state v1 v2 seq d1 d2 h_network_valid h_commit1 h_prep2

end GodelLobBFT

