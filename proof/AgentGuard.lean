import Lean

namespace AgentGuard
open Lean

structure Grant where
  id : String
  issuer : String
  subject : String
  operation : String
  resource : String
  «prefix» : Bool
  expires : Nat
  remaining : Nat
  parent : Option String
  deriving BEq, ReflBEq, LawfulBEq, DecidableEq, FromJson, ToJson

structure Deny where
  actor : String
  operation : String
  resource : String
  «prefix» : Bool
  deriving FromJson

structure Query where
  actor : String
  identity : String
  actionOp : String
  operation : String
  resource : String
  effect : String
  supported : Bool
  principals : List String
  administrators : List String
  roots : List Grant
  chains : List (List Grant)
  grantIds : List String
  revoked : List String
  now : Nat
  denies : List Deny
  labels : List String
  objectLabels : List String
  accepts : List String
  count : Nat
  budget : Option Nat
  child : Option Grant
  target : Option Grant
  deriving FromJson

def covers (scope : String) (prefixFlag : Bool) (resource : String) : Bool :=
  resource == scope || (prefixFlag && (scope ++ "/").isPrefixOf resource)

def attenuates (p c : Grant) : Bool :=
  c.parent == some p.id && c.issuer == p.subject && c.operation == p.operation &&
  covers p.resource p.prefix c.resource && (p.prefix || !c.prefix) &&
  decide (c.expires ≤ p.expires) && decide (c.remaining < p.remaining)

def live (q : Query) (g : Grant) : Bool :=
  !q.revoked.contains g.id && decide (q.now < g.expires)

def edges : List Grant → Bool
  | [] => true
  | [_] => true
  | p :: c :: rest => attenuates p c && edges (c :: rest)

def validChain (q : Query) : List Grant → Bool
  | [] => false
  | root :: rest => q.roots.contains root &&
      (root :: rest).all (live q) && edges (root :: rest)

def permittedChain (q : Query) (chain : List Grant) : Bool :=
  match chain.getLast? with
  | none => false
  | some leaf => validChain q chain && leaf.subject == q.actor &&
      leaf.operation == q.operation && covers leaf.resource leaf.prefix q.resource &&
      (q.effect != "delegate" || match q.child with
        | none => false
        | some child => attenuates leaf child)

def common (q : Query) : Bool :=
  q.supported && q.actor == q.identity && q.principals.contains q.actor &&
  (match q.budget with | none => true | some n => decide (q.count < n)) &&
  !(q.denies.any fun d => d.actor == q.actor &&
    (d.operation == q.operation || d.operation == q.actionOp) &&
    covers d.resource d.prefix q.resource)

def authority (q : Query) : Bool :=
  if q.effect == "revoke" then
    match q.target with
    | none => false
    | some t => !q.revoked.contains t.id &&
        (q.administrators.contains q.actor || q.actor == t.issuer || q.actor == t.subject)
  else
    q.chains.any (permittedChain q) &&
      (q.effect != "delegate" || match q.child with
        | none => false
        | some c => c.issuer == q.actor && q.principals.contains c.subject &&
            !q.grantIds.contains c.id && decide (q.now < c.expires))

def flow (q : Query) : Bool :=
  q.effect != "send" || q.labels.all (fun label => q.accepts.contains label)

def allowed (q : Query) : Bool := common q && authority q && flow q

def nextLabels (q : Query) : List String :=
  q.labels ++ if allowed q && q.effect == "read" then q.objectLabels else []

-- Propositional semantics is separate from the executable Boolean evaluator.
def SpecAllowed (q : Query) : Prop :=
  common q = true ∧ authority q = true ∧
  (q.effect = "send" → ∀ label ∈ q.labels, label ∈ q.accepts)

theorem evaluator_sound (q : Query) (h : allowed q = true) : SpecAllowed q := by
  simp only [allowed, Bool.and_eq_true] at h
  refine ⟨h.1.1, h.1.2, ?_⟩
  intro hs label hl
  have hf := h.2
  simp [flow, hs, List.all_eq_true] at hf
  exact hf label hl

theorem forbidden_flow_denied (q : Query) (hs : q.effect = "send")
    (hl : label ∈ q.labels) (ha : label ∉ q.accepts) : allowed q = false := by
  cases he : allowed q with
  | false => rfl
  | true => exact False.elim (ha ((evaluator_sound q he).2.2 hs label hl))

theorem labels_monotone (q : Query) (h : label ∈ q.labels) : label ∈ nextLabels q := by
  simp only [nextLabels, List.mem_append]
  exact Or.inl h

theorem read_inherits (q : Query) (ha : allowed q = true) (hr : q.effect = "read")
    (h : label ∈ q.objectLabels) : label ∈ nextLabels q := by
  simp [nextLabels, ha, hr, h]

-- A valid witness must start in the actual policy's authority roots.
theorem chain_has_authority_root (q : Query) (root : Grant) (rest : List Grant)
    (h : validChain q (root :: rest) = true) : root ∈ q.roots := by
  simp only [validChain, Bool.and_eq_true] at h
  exact List.mem_of_elem_eq_true h.1.1

inductive DelegationPath : List Grant → Prop
  | nil : DelegationPath []
  | single (g) : DelegationPath [g]
  | step (p c rest) (edge : attenuates p c = true)
      (tail : DelegationPath (c :: rest)) : DelegationPath (p :: c :: rest)

theorem edges_sound : ∀ chain, edges chain = true → DelegationPath chain
  | [], _ => .nil
  | [g], _ => .single g
  | p :: c :: rest, h => by
      simp only [edges, Bool.and_eq_true] at h
      exact .step p c rest h.1 (edges_sound (c :: rest) h.2)

theorem chain_witness_sound (q : Query) (root : Grant) (rest : List Grant)
    (h : validChain q (root :: rest) = true) :
    root ∈ q.roots ∧ (∀ g ∈ root :: rest, live q g = true) ∧ DelegationPath (root :: rest) := by
  have hr := chain_has_authority_root q root rest h
  simp only [validChain, Bool.and_eq_true] at h
  exact ⟨hr, List.all_eq_true.mp h.1.2, edges_sound _ h.2⟩

-- Each accepted parent/child edge strictly reduces delegation depth and expiry.
theorem delegation_attenuates (p c : Grant) (h : attenuates p c = true) :
    c.remaining < p.remaining ∧ c.expires ≤ p.expires := by
  simp only [attenuates, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.2, h.1.2⟩

theorem revoked_grant_invalidates_chain (q : Query) (root : Grant) (rest : List Grant)
    (g : Grant) (hg : g ∈ root :: rest) (hr : g.id ∈ q.revoked) :
    validChain q (root :: rest) = false := by
  cases he : validChain q (root :: rest) with
  | false => rfl
  | true =>
    have hall : (root :: rest).all (live q) = true := by
      simp only [validChain, Bool.and_eq_true] at he
      exact he.1.2
    have hLive := (List.all_eq_true.mp hall) g hg
    simp [live, hr] at hLive

-- This trace relation is deliberately independent of a fixed workflow length.
inductive Execution : List String → List Query → List String → Prop
  | nil (labels) : Execution labels [] labels
  | cons (q : Query) (rest final) (ha : allowed q = true)
      (tail : Execution (nextLabels q) rest final) : Execution q.labels (q :: rest) final

theorem history_preserves_labels (trace : Execution start actions final)
    (h : label ∈ start) : label ∈ final := by
  induction trace with
  | nil => exact h
  | cons q rest final ha tail ih => exact ih (labels_monotone q h)

theorem no_forbidden_send_over_history (trace : Execution start actions final)
    (h : label ∈ start) : ∀ q ∈ actions, q.effect = "send" → label ∈ q.accepts := by
  induction trace with
  | nil => simp
  | cons q rest final ha tail ih =>
    intro a hm hs
    simp only [List.mem_cons] at hm
    rcases hm with he | ht
    · subst a
      exact (evaluator_sound q ha).2.2 hs label h
    · exact ih (labels_monotone q h) a ht hs

end AgentGuard
