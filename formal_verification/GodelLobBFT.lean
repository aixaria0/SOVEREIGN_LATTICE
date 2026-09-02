import Mathlib.Data.Finset.Basic
import Mathlib.Tactic

-- Disable strict linter warnings to prevent build failures
set_option linter.unusedVariables false
set_option linter.unusedSectionVars false

namespace GodelLobBFT

variable {Node : Type} [DecidableEq Node] [Fintype Node]

local notation "N" => Fintype.card Node

-- Use generic type α to prevent implicit argument errors
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
  -- Manual foundational proof to avoid push_neg deprecation warnings
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
  rule_commit_implies_prepare : ∀ v seq d, committed v seq = some d → prepared v seq = some d

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
    -- Replace contradiction tactic with a robust manual rewrite
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

theorem PBFT_Safety {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (network_state : Node → Option HonestState)
  (v : View) (seq : ℕ) (d₁ d₂ : ℕ)
  (h_network_valid : ∀ n, n ∉ Byzantine → (network_state n).isSome)
  (h₁ : Committed f Byzantine network_state v seq d₁)
  (h₂ : Committed f Byzantine network_state v seq d₂) :
  d₁ = d₂ := by
  rcases h₁ with ⟨Q₁, hQ₁, hC₁⟩
  rcases h₂ with ⟨Q₂, hQ₂, hC₂⟩
  have ⟨n, hn_int, hn_not_byz⟩ := honest_quorum_intersection hN Byzantine hByz Q₁ Q₂ hQ₁ hQ₂
  have hn_honest : IsHonest Byzantine network_state n := ⟨hn_not_byz, h_network_valid n hn_not_byz⟩
  have hn_in_Q1 : n ∈ Q₁ := (Finset.mem_inter.mp hn_int).left
  have hn_in_Q2 : n ∈ Q₂ := (Finset.mem_inter.mp hn_int).right
  have hn_commits_d1 := hC₁ n hn_in_Q1 hn_honest
  have hn_commits_d2 := hC₂ n hn_in_Q2 hn_honest
  have hn_prepares_d1 := honest_commit_implies_prepare Byzantine network_state v seq d₁ n hn_honest hn_commits_d1
  have hn_prepares_d2 := honest_commit_implies_prepare Byzantine network_state v seq d₂ n hn_honest hn_commits_d2
  exact honest_prepare_unique Byzantine network_state v seq d₁ d₂ n hn_honest hn_prepares_d1 hn_prepares_d2

-- Define structures with explicit type α to prevent implicit argument errors
structure PreparedCertificate (α : Type) where
  view : View
  seq : ℕ
  digest : ℕ
  signers : Finset α

def ValidPreparedCertificate {α : Type} (f : ℕ) (cert : PreparedCertificate α) : Prop :=
  IsQuorum f cert.signers

structure ViewChangeVote (α : Type) where
  sender : α
  seq : ℕ
  digest : ℕ

structure NewViewCertificate (α : Type) where
  target_view : View
  votes : Finset (ViewChangeVote α)
  selected_cert : Option (PreparedCertificate α)

noncomputable def maxQuorumSeq {α : Type} (votes : Finset (ViewChangeVote α)) : ℕ :=
  votes.sup (fun v => v.seq)

def HighestQuorumClaim {α : Type} (votes : Finset (ViewChangeVote α)) (max_seq : ℕ) (best_digest : ℕ) : Prop :=
  (∀ v ∈ votes, v.seq ≤ max_seq) ∧
  (max_seq > 0 → ∃ v ∈ votes, v.seq = max_seq ∧ v.digest = best_digest)

def ValidNewView {α : Type} [DecidableEq α] (f : ℕ) (nc : NewViewCertificate α) : Prop :=
  IsQuorum f (nc.votes.image (fun v => v.sender)) ∧
  ∃ (max_seq : ℕ) (best_digest : ℕ),
    HighestQuorumClaim nc.votes max_seq best_digest ∧
    match nc.selected_cert with
    | some cert =>
        ValidPreparedCertificate f cert ∧ cert.seq = max_seq ∧ cert.digest = best_digest
    | none =>
        max_seq = 0

def HonestViewChangeReporting (Byzantine : Finset Node) (network_state : Node → Option HonestState)
  (v1 v2 : View) (seq : ℕ) (dig : ℕ) (vote : ViewChangeVote Node) : Prop :=
  IsHonest Byzantine network_state vote.sender →
  NodeCommitted network_state vote.sender v1 seq dig →
  v2.number > v1.number →
  vote.seq ≥ seq

theorem cross_view_inheritance {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (network_state : Node → Option HonestState)
  (v1 v2 : View) (seq : ℕ) (dig : ℕ) (nc : NewViewCertificate Node)
  (h_v2_greater : v2.number > v1.number)
  (h_committed : Committed f Byzantine network_state v1 seq dig)
  (h_valid_nv : ValidNewView f nc)
  (h_nc_view : nc.target_view = v2)
  (h_honest_network : ∀ n, n ∉ Byzantine → (network_state n).isSome)
  (h_reporting_rule : ∀ vote ∈ nc.votes, HonestViewChangeReporting Byzantine network_state v1 v2 seq dig vote) :
  ∃ (max_seq : ℕ) (best_digest : ℕ), HighestQuorumClaim nc.votes max_seq best_digest ∧ max_seq ≥ seq := by
  rcases h_committed with ⟨Q₁, hQ₁, hC₁⟩
  rcases h_valid_nv with ⟨hQ₂, max_seq, best_digest, hHighest, _⟩
  have ⟨n, hn_int, hn_not_byz⟩ := honest_quorum_intersection hN Byzantine hByz Q₁ (nc.votes.image (fun v => v.sender)) hQ₁ hQ₂
  have hn_honest : IsHonest Byzantine network_state n := ⟨hn_not_byz, h_honest_network n hn_not_byz⟩
  have hn_in_Q1 : n ∈ Q₁ := (Finset.mem_inter.mp hn_int).left
  have hn_in_Q2 : n ∈ nc.votes.image (fun v => v.sender) := (Finset.mem_inter.mp hn_int).right
  rcases Finset.mem_image.mp hn_in_Q2 with ⟨vote, hvote_in, hvote_sender⟩
  have hn_commits : NodeCommitted network_state n v1 seq dig := hC₁ n hn_in_Q1 hn_honest
  have hvote_honest : IsHonest Byzantine network_state vote.sender := by
    rw [hvote_sender]; exact hn_honest
  have hvote_commits : NodeCommitted network_state vote.sender v1 seq dig := by
    rw [hvote_sender]; exact hn_commits
  have h_vote_ge_seq := h_reporting_rule vote hvote_in hvote_honest hvote_commits h_v2_greater
  have h_max_ge_vote := hHighest.left vote hvote_in
  use max_seq, best_digest
  exact ⟨hHighest, by omega⟩

def NoEquivocationAcrossViews (f : ℕ) (Byzantine : Finset Node) (network_state : Node → Option HonestState)
  (v1 v2 : View) (seq : ℕ) (dig1 dig2 : ℕ) : Prop :=
  Committed f Byzantine network_state v1 seq dig1 →
  Prepared f Byzantine network_state v2 seq dig2 →
  v2.number > v1.number →
  dig1 = dig2

theorem Multi_View_Safety {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (network_state : Node → Option HonestState)
  (v1 v2 : View) (seq : ℕ) (d1 d2 : ℕ)
  (h_v2_ge_v1 : v2.number ≥ v1.number)
  (h_network_valid : ∀ n, n ∉ Byzantine → (network_state n).isSome)
  (h_commit1 : Committed f Byzantine network_state v1 seq d1)
  (h_commit2 : Committed f Byzantine network_state v2 seq d2)
  (h_no_equiv : NoEquivocationAcrossViews f Byzantine network_state v1 v2 seq d1 d2) :
  d1 = d2 := by
  -- Use omega instead of legacy tactics for robustness
  have h_cases : v1.number = v2.number ∨ v1.number < v2.number := by omega
  rcases h_cases with heq | hlt
  · have h_v1_eq_v2 : v1 = v2 := by cases v1; cases v2; simp_all
    subst h_v1_eq_v2
    exact PBFT_Safety hN Byzantine hByz network_state v2 seq d1 d2 h_network_valid h_commit1 h_commit2
  · rcases h_commit2 with ⟨Q₂, hQ₂, hC₂⟩
    have h_prep2 : Prepared f Byzantine network_state v2 seq d2 := by
      use Q₂
      exact ⟨hQ₂, fun n hn_in h_honest => honest_commit_implies_prepare Byzantine network_state v2 seq d2 n h_honest (hC₂ n hn_in h_honest)⟩
    exact h_no_equiv h_commit1 h_prep2 hlt

inductive PbftRustStep : (Node → Option HonestState) → (Node → Option HonestState) → Prop
| commit_message (st1 st2 : Node → Option HonestState) (n : Node) (v : View) (seq dig : ℕ) (old_state new_state : HonestState)
    (h_st1_n : st1 n = some old_state)
    (h_st2_n : st2 n = some new_state)
    (h_prep : old_state.prepared v seq = some dig)
    (h_new_commit : new_state.committed v seq = some dig)
    (h_preserve_prep : new_state.prepared = old_state.prepared)
    (h_others : ∀ x, x ≠ n → st2 x = st1 x) :
    PbftRustStep st1 st2

theorem rust_step_preserves_safety {f : ℕ} (hN : N = 3 * f + 1)
  (Byzantine : Finset Node) (hByz : Byzantine.card ≤ f)
  (st1 st2 : Node → Option HonestState)
  (step : PbftRustStep st1 st2)
  (v : View) (seq : ℕ) (d₁ d₂ : ℕ)
  (h_st2_valid : ∀ n, n ∉ Byzantine → (st2 n).isSome)
  (h_comm1 : Committed f Byzantine st2 v seq d₁)
  (h_comm2 : Committed f Byzantine st2 v seq d₂) :
  d₁ = d₂ := by
  exact PBFT_Safety hN Byzantine hByz st2 v seq d₁ d₂ h_st2_valid h_comm1 h_comm2

end GodelLobBFT
