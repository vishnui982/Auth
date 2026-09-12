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
  resource == scope || (prefixFlag && (scope ++ "/").toList.isPrefixOf resource.toList)

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

def denialOverlaps (q : Query) (d : Deny) : Bool :=
  covers d.resource d.prefix q.resource ||
    (q.effect == "delegate" && match q.child with
      | none => false
      | some c => covers c.resource c.prefix d.resource)

def common (q : Query) : Bool :=
  q.supported && q.actor == q.identity && q.principals.contains q.actor &&
  (match q.budget with | none => true | some n => decide (q.count < n)) &&
  !(q.denies.any fun d => d.actor == q.actor &&
    (d.operation == q.operation || d.operation == q.actionOp) &&
    denialOverlaps q d)

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
  (q.labels ++ if allowed q && q.effect == "read" then q.objectLabels else []).eraseDups.mergeSort
    (fun a b => a ≤ b)

-- Declarative authorization rules: fields, membership, inequalities and witnesses.
-- These do not define authority in terms of the evaluator's Boolean answer.
def ScopeCovers (scope : String) (prefixFlag : Bool) (resource : String) : Prop :=
  resource = scope ∨ (prefixFlag = true ∧ (scope ++ "/").toList <+: resource.toList)

def Attenuation (p c : Grant) : Prop :=
  c.parent = some p.id ∧ c.issuer = p.subject ∧ c.operation = p.operation ∧
  ScopeCovers p.resource p.prefix c.resource ∧ (p.prefix = true ∨ c.prefix = false) ∧
  c.expires ≤ p.expires ∧ c.remaining < p.remaining

def LiveGrant (q : Query) (g : Grant) : Prop :=
  g.id ∉ q.revoked ∧ q.now < g.expires

def AuthorityEdges : List Grant → Prop
  | [] => True
  | [_] => True
  | p :: c :: rest => Attenuation p c ∧ AuthorityEdges (c :: rest)

def RootedChain (q : Query) : List Grant → Prop
  | [] => False
  | root :: rest => root ∈ q.roots ∧ (∀ g ∈ root :: rest, LiveGrant q g) ∧
      AuthorityEdges (root :: rest)

def GrantPermission (q : Query) (chain : List Grant) : Prop :=
  match chain.getLast? with
  | none => False
  | some leaf => RootedChain q chain ∧ leaf.subject = q.actor ∧
      leaf.operation = q.operation ∧ ScopeCovers leaf.resource leaf.prefix q.resource ∧
      (q.effect ≠ "delegate" ∨ match q.child with
        | none => False
        | some c => Attenuation leaf c)

def DenialOverlaps (q : Query) (d : Deny) : Prop :=
  ScopeCovers d.resource d.prefix q.resource ∨
    (q.effect = "delegate" ∧ match q.child with
      | none => False
      | some c => ScopeCovers c.resource c.prefix d.resource)

def CommonConditions (q : Query) : Prop :=
  q.supported = true ∧ q.actor = q.identity ∧ q.actor ∈ q.principals ∧
  (match q.budget with | none => True | some n => q.count < n) ∧
  ¬ (∃ d ∈ q.denies, d.actor = q.actor ∧
    (d.operation = q.operation ∨ d.operation = q.actionOp) ∧ DenialOverlaps q d)

def Authority (q : Query) : Prop :=
  if q.effect = "revoke" then
    match q.target with
    | none => False
    | some t => t.id ∉ q.revoked ∧
        (q.actor ∈ q.administrators ∨ q.actor = t.issuer ∨ q.actor = t.subject)
  else
    (∃ chain ∈ q.chains, GrantPermission q chain) ∧
      (q.effect ≠ "delegate" ∨ match q.child with
        | none => False
        | some c => c.issuer = q.actor ∧ c.subject ∈ q.principals ∧
            c.id ∉ q.grantIds ∧ q.now < c.expires)

def SpecAllowed (q : Query) : Prop :=
  CommonConditions q ∧ Authority q ∧
  (q.effect = "send" → ∀ label ∈ q.labels, label ∈ q.accepts)

@[simp] theorem covers_correct : covers s p r = true ↔ ScopeCovers s p r := by
  simp [covers, ScopeCovers]

@[simp] theorem attenuation_correct : attenuates p c = true ↔ Attenuation p c := by
  simp [attenuates, Attenuation, and_assoc]

@[simp] theorem live_correct : live q g = true ↔ LiveGrant q g := by
  simp [live, LiveGrant]

@[simp] theorem edges_correct : ∀ chain, edges chain = true ↔ AuthorityEdges chain
  | [] => by simp [edges, AuthorityEdges]
  | [_] => by simp [edges, AuthorityEdges]
  | p :: c :: rest => by simp [edges, AuthorityEdges, edges_correct (c :: rest)]

@[simp] theorem chain_correct : validChain q chain = true ↔ RootedChain q chain := by
  cases chain <;> simp [validChain, RootedChain, List.all_eq_true, and_assoc]

@[simp] theorem permission_correct : permittedChain q chain = true ↔ GrantPermission q chain := by
  unfold permittedChain GrantPermission
  split <;> cases q.child <;> simp [and_assoc]

@[simp] theorem denial_correct : denialOverlaps q d = true ↔ DenialOverlaps q d := by
  cases h : q.child <;> simp [denialOverlaps, DenialOverlaps, h]

@[simp] theorem common_correct : common q = true ↔ CommonConditions q := by
  cases h : q.budget <;> simp [common, CommonConditions, h, and_assoc]

@[simp] theorem authority_correct : authority q = true ↔ Authority q := by
  unfold authority Authority
  split <;> cases q.target <;> cases q.child <;> simp_all [List.any_eq_true, and_assoc, or_assoc]

theorem evaluator_correct (q : Query) : allowed q = true ↔ SpecAllowed q := by
  by_cases hs : q.effect = "send" <;>
    simp [allowed, SpecAllowed, flow, hs, List.all_eq_true, and_assoc]

theorem evaluator_sound (q : Query) (h : allowed q = true) : SpecAllowed q :=
  (evaluator_correct q).mp h

theorem evaluator_complete (q : Query) (h : SpecAllowed q) : allowed q = true :=
  (evaluator_correct q).mpr h

theorem forbidden_flow_denied (q : Query) (hs : q.effect = "send")
    (hl : label ∈ q.labels) (ha : label ∉ q.accepts) : allowed q = false := by
  cases he : allowed q with
  | false => rfl
  | true => exact False.elim (ha ((evaluator_sound q he).2.2 hs label hl))

theorem labels_monotone (q : Query) (h : label ∈ q.labels) : label ∈ nextLabels q := by
  simp only [nextLabels, List.mem_mergeSort, List.mem_eraseDups, List.mem_append]
  exact Or.inl h

theorem read_inherits (q : Query) (ha : allowed q = true) (hr : q.effect = "read")
    (h : label ∈ q.objectLabels) : label ∈ nextLabels q := by
  simp [nextLabels, List.mem_eraseDups, ha, hr, h]

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

-- Scope attenuation is semantic containment for every resource, not just
-- a comparison of the two grant resource strings.
theorem delegation_scope_contained (p c : Grant) (h : attenuates p c = true)
    (hr : ScopeCovers c.resource c.prefix r) : ScopeCovers p.resource p.prefix r := by
  have edge := attenuation_correct.mp h
  rcases edge with ⟨_, _, _, scope, flags, _, _⟩
  rcases hr with he | ⟨hc, hr⟩
  · simpa [he] using scope
  · have hp : p.prefix = true := by
      rcases flags with hp | hf
      · exact hp
      · simp [hc] at hf
    apply Or.inr
    refine ⟨hp, ?_⟩
    rcases scope with he | ⟨_, hs⟩
    · simpa [he] using hr
    · have hcPrefix : c.resource.toList <+: (c.resource ++ "/").toList := by
        rw [String.toList_append]
        exact List.prefix_append _ _
      exact hs.trans (hcPrefix.trans hr)

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

theorem protected_read_prevents_later_leak (q : Query) (ha : allowed q = true)
    (hr : q.effect = "read") (hl : label ∈ q.objectLabels)
    (tail : Execution (nextLabels q) actions final) :
    ∀ a ∈ actions, a.effect = "send" → label ∈ a.accepts :=
  no_forbidden_send_over_history tail (read_inherits q ha hr hl)

theorem ordinary_authority_has_witness (q : Query) (ha : allowed q = true)
    (hr : q.effect ≠ "revoke") : ∃ chain ∈ q.chains, GrantPermission q chain := by
  have h := (evaluator_sound q ha).2.1
  simp only [Authority, if_neg hr] at h
  exact h.1

theorem delegation_cannot_cover_denied_resource (q : Query) (d : Deny) (c : Grant)
    (hd : d ∈ q.denies) (ha : d.actor = q.actor)
    (hop : d.operation = q.operation ∨ d.operation = q.actionOp)
    (he : q.effect = "delegate") (hc : q.child = some c)
    (hs : ScopeCovers c.resource c.prefix d.resource) : allowed q = false := by
  cases h : allowed q with
  | false => rfl
  | true =>
    have commonSpec := (evaluator_sound q h).1
    rcases commonSpec with ⟨_, _, _, _, noDeny⟩
    apply False.elim
    apply noDeny
    refine ⟨d, hd, ha, hop, Or.inr ⟨he, ?_⟩⟩
    simp [hc, hs]

end AgentGuard
