import Coffre.Access

/-!
# What the access rules promise

Each theorem below is about the model in `Access.lean`, which the
differential test holds to `packages/core/src/access.ts`.

- `credential_within_holder`: a request made on a credential holds no more
  than its holder holds now, whatever the credential says.
- `personal_token_within_issuer`: a personal token holds no more than its
  issuer held when they made it, under any policy since: roles widened,
  environments protected or not, grants added.
- `role_edits_never_widen_credentials`: what a credential's scope leaves to
  its holder is the same under every role definition.
- `protected_never_widens`: a person holds no more in a protected
  environment than in the same one unprotected, under a policy whose roles
  are valid (`definitionProblem`).
- `owner_issued_only`: a service reads a project's sensitive values only on
  a credential whose grant there an Owner of the project issued (R32).
-/

namespace Coffre

/-! ## Unfolding -/

theorem Table.get?_some {α} {t : Table α} {k : String} {a : α} :
    t.get? k = some a → (k, a) ∈ t := by
  unfold Table.get?
  intro h
  cases hf : t.find? (·.1 == k) with
  | none => simp [hf] at h
  | some e =>
    simp [hf] at h
    have := List.mem_of_find?_eq_some hf
    have hk := List.find?_some hf
    simp at hk
    obtain ⟨k', a'⟩ := e
    simp at h hk
    subst h; subst hk
    exact this

/-- `holds` reads its holder only through `guarded`. -/
theorem holds_congr {d p x h h'} (hg : guarded h x = guarded h' x) :
    holds d p x h = holds d p x h' := by
  cases d <;> simp [holds, hg]

theorem scopeHolds_congr {p x} {h h' : Holdings} (hc : h.cred = h'.cred)
    (hg : guarded h x = guarded h' x) : scopeHolds h p x = scopeHolds h' p x := by
  unfold scopeHolds
  rw [hc]
  congr 1
  funext g
  rw [holds_congr hg]

/-- `allows` reads the protected environments only through `guarded` at the place. -/
theorem allows_withProtected {h : Holdings} {ps p x}
    (hg : guarded (h.withProtected ps) x = guarded h x) :
    allows (h.withProtected ps) p x = allows h p x := by
  have hs := scopeHolds_congr (p := p) (h := h.withProtected ps) (h' := h) rfl hg
  have hh : ∀ d, holds d p x (h.withProtected ps) = holds d p x h := fun d => holds_congr hg
  unfold allows held
  rw [hs]
  simp only [hh]
  rfl

theorem withProtected_twice (h : Holdings) (ps qs) :
    (h.withProtected qs).withProtected ps = h.withProtected ps := rfl

theorem allows_withProtected_eq {h : Holdings} {ps qs p x}
    (hg : guarded (h.withProtected ps) x = guarded (h.withProtected qs) x) :
    allows (h.withProtected ps) p x = allows (h.withProtected qs) p x := by
  have := allows_withProtected (h := h.withProtected qs) (ps := ps) (p := p) (x := x)
    (by rwa [withProtected_twice])
  rwa [withProtected_twice] at this

/-- A project-wide permission does not look at protection at all. -/
theorem holds_projectOnly {d p x h h'} (hp : p.projectOnly = true) :
    holds d p x h = holds d p x h' := by
  cases d <;> simp [holds, hp]

theorem allows_withProtected_projectOnly {h : Holdings} {ps p x} (hp : p.projectOnly = true) :
    allows (h.withProtected ps) p x = allows h p x := by
  unfold allows held scopeHolds
  simp only [Holdings.withProtected]
  congr 2
  · congr 1; funext g; rw [holds_projectOnly hp]
  · rw [holds_projectOnly hp]
  · congr 1; funext g; rw [holds_projectOnly hp]

/-! ## A request on a credential holds no more than its holder -/

/-- What a credential leaves to a request, the holder holds without it. -/
theorem credential_within_holder {h : Holdings} {p x} (ha : allows h p x = true) :
    allows { h with cred := none } p x = true := by
  unfold allows at *
  simp only [Bool.and_eq_true, Bool.or_eq_true] at ha
  simp only [Option.isNone_none, Bool.true_or, Bool.true_and]
  exact ha.2

/-- And the scope caps it: a request on one holds only what a grant of the scope held there. -/
theorem credential_within_scope {h : Holdings} {s p x} (hc : h.cred = some s)
    (ha : allows h p x = true) : scopeHolds h p x = true := by
  unfold allows at ha
  simp [hc] at ha
  exact ha.1

/-! ## Role edits never widen a credential -/

/-- Whatever an Owner makes of the roles, a credential's scope leaves the same to its holder. -/
theorem role_edits_never_widen_credentials (h : Holdings) (roles instanceRoles : Table RoleDef) (p x) :
    scopeHolds { h with policy := { h.policy with roles, instanceRoles } } p x = scopeHolds h p x :=
  scopeHolds_congr rfl (by simp [guarded, protects])

/-- So a request on a credential holds, under any role edit, only what its scope held as issued. -/
theorem credential_capped_under_edits {h : Holdings} {s roles instanceRoles p x} (hc : h.cred = some s)
    (ha : allows { h with policy := { h.policy with roles, instanceRoles } } p x = true) :
    scopeHolds h p x = true := by
  rw [← role_edits_never_widen_credentials h roles instanceRoles p x]
  exact credential_within_scope (by simpa using hc) ha

/-! ## A personal token holds no more than its issuer did

A personal token's grant at `x₀` keeps its role's columns, each cut down to
what its issuer held at `x₀` then (`heldColumns`). The theorem: at any place
`x` and under any policy later, what the token leaves to a request, the
issuer held at `x` when they made it, as protected or not as `x` is now.

Two assumptions about places, which the database keeps: no grant names an
environment of id `""` (`heldColumns` asks at such an environment for one no
grant names), and a place's slug is the one its environment has (`slugOf`):
a rename is a change the issuer's current holdings decide, as
`credential_within_holder` says. -/

/-- No grant, of the holder or of its credential, names the environment `""`. -/
def NoBlankEnv (h : Holdings) : Prop :=
  (∀ g ∈ h.grants, g.place.env ≠ some "") ∧ ∀ s, h.cred = some s → ∀ g ∈ s, g.env ≠ some ""

/-- A place whose slug is its environment's, as `slugOf` names them. -/
def Located (slugOf : String → Option String) (x : Place) : Prop :=
  ∀ id slug, x.env = some (id, slug) → slug = slugOf id

theorem covers_project {g : GrantPlace} {proj : String} {x : Place} (hx : x.project = proj)
    (hc : covers g ⟨proj, none⟩ = true) : covers g x = true := by
  unfold covers at *
  cases hp : g.project <;> cases he : g.env <;> simp_all [Place.envId]

theorem inScope_project {s : Scope} {proj : String} {x : Place} (hx : x.project = proj)
    (hi : inScope s ⟨proj, none⟩ = true) : inScope s x = true := by
  unfold inScope at *
  simp only [Bool.and_eq_true] at *
  refine ⟨hx ▸ hi.1, ?_⟩
  cases he : x.env with
  | none => simpa using hi.2
  | some e =>
    obtain ⟨_, slug⟩ := e
    cases hf : s.environments <;> simp_all [Filter.isAll, admits]

/-- From a project to a place in it, where neither looks at protection. -/
theorem allows_project {h : Holdings} {proj p} {x : Place} (hx : x.project = proj)
    (hp : p.projectOnly = true ∨ guarded h x = false)
    (ha : allows h p ⟨proj, none⟩ = true) : allows h p x = true := by
  have hg0 : guarded h ⟨proj, none⟩ = false := by simp [guarded]
  have hh : ∀ d, holds d p ⟨proj, none⟩ h = holds d p x h := by
    intro d
    cases d with
    | none => rfl
    | some d =>
      rcases hp with hp | hp
      · simp [holds, hp]
      · simp [holds, hp, hg0]
  unfold allows held scopeHolds at *
  simp only [Bool.and_eq_true, Bool.or_eq_true, List.any_eq_true] at *
  obtain ⟨hcred, hheld⟩ := ha
  refine ⟨?_, ?_⟩
  · rcases hcred with hn | ⟨g, hg, hcov, hhold⟩
    · exact Or.inl hn
    · exact Or.inr ⟨g, hg, covers_project hx hcov, by rw [← hh]; exact hhold⟩
  · rcases hheld with ⟨hin, hhold⟩ | ⟨g, hg, hcov, hhold⟩
    · exact Or.inl ⟨inScope_project hx hin, by rw [← hh]; exact hhold⟩
    · exact Or.inr ⟨g, hg, covers_project hx hcov, by rw [← hh]; exact hhold⟩

theorem covers_blank {g : GrantPlace} {proj : String} {x : Place}
    (hx : x.project = proj) (hne : g.env ≠ some "")
    (hc : covers g ⟨proj, some ("", none)⟩ = true) : covers g x = true := by
  unfold covers at *
  cases hp : g.project <;> cases hge : g.env <;> simp_all [Place.envId]

theorem inScope_blank {s : Scope} {proj : String} {x : Place} {id slug}
    (hx : x.project = proj) (he : x.env = some (id, slug))
    (hi : inScope s ⟨proj, some ("", none)⟩ = true) : inScope s x = true := by
  unfold inScope at *
  simp only [Bool.and_eq_true] at *
  refine ⟨hx ▸ hi.1, ?_⟩
  rw [he]
  cases hf : s.environments <;> simp_all [admits]

/-- From the environment no grant names to any environment of the project, both protected. -/
theorem allows_blank {h : Holdings} {proj p} {x : Place} {id slug} (hx : x.project = proj)
    (he : x.env = some (id, slug)) (hb : NoBlankEnv h)
    (hg : guarded h ⟨proj, some ("", none)⟩ = guarded h x)
    (ha : allows h p ⟨proj, some ("", none)⟩ = true) : allows h p x = true := by
  have hh : ∀ d, holds d p ⟨proj, some ("", none)⟩ h = holds d p x h := fun d => by
    cases d <;> simp [holds, hg]
  unfold allows held scopeHolds at *
  simp only [Bool.and_eq_true, Bool.or_eq_true, List.any_eq_true] at *
  obtain ⟨hcred, hheld⟩ := ha
  refine ⟨?_, ?_⟩
  · rcases hcred with hn | ⟨g, hg', hcov, hhold⟩
    · exact Or.inl hn
    · refine Or.inr ⟨g, hg', ?_, by rw [← hh]; exact hhold⟩
      cases hcr : h.cred with
      | none => simp [hcr] at hg'
      | some s =>
        simp [hcr] at hg'
        exact covers_blank hx (hb.2 s hcr g hg') hcov
  · rcases hheld with ⟨hin, hhold⟩ | ⟨g, hg', hcov, hhold⟩
    · exact Or.inl ⟨inScope_blank hx he hin, by rw [← hh]; exact hhold⟩
    · exact Or.inr ⟨g, hg', covers_blank hx (hb.1 g hg') hcov, by rw [← hh]; exact hhold⟩

theorem mem_within {p : Permission} {col cap : List Permission} (h : p ∈ within col (some cap)) : p ∈ cap := by
  simp [within] at h
  exact h.2

/-- A grant as a personal token keeps it: its role's columns at `x₀`, within what its issuer held there. -/
def IssuedBy (h₀ : Holdings) (slugOf : String → Option String) (g : ScopeGrant) : Prop :=
  ∃ (x₀ : Place) (pol : Policy), Located slugOf x₀ ∧ x₀.project = g.project ∧ x₀.envId = g.env ∧
    g.cols = (issuedGrant g.project g.env g.role pol (some (heldColumns h₀ x₀))).cols

theorem guarded_withProtected_every {h : Holdings} {x : Place} {id slug} (he : x.env = some (id, slug)) :
    guarded (h.withProtected [EVERY_ENVIRONMENT]) x = !h.service := by
  simp [guarded, he, protects, Holdings.withProtected]

theorem guarded_withProtected_none {h : Holdings} {x : Place} :
    guarded (h.withProtected []) x = false := by
  unfold guarded
  cases x.env <;> simp [protects, Holdings.withProtected]

theorem located_eq {slugOf : String → Option String} {x₀ x : Place} {g : ScopeGrant} {e : String}
    (hge : g.env = some e) (hcov : covers g.place x = true) (hproj : x₀.project = g.project)
    (henv : x₀.envId = g.env) (h₀ : Located slugOf x₀) (h₁ : Located slugOf x) : x₀ = x := by
  unfold covers ScopeGrant.place at hcov
  simp [hge] at hcov
  obtain ⟨pr, en⟩ := x₀
  obtain ⟨pr', en'⟩ := x
  cases en with
  | none => simp_all [Place.envId]
  | some a =>
    cases en' with
    | none => simp_all [Place.envId]
    | some b =>
      obtain ⟨i, si⟩ := a
      obtain ⟨j, sj⟩ := b
      simp only [Place.envId, Option.map_some] at henv hcov
      have hi : i = e := by simpa [hge] using henv
      have hj : j = e := by simpa using hcov.2
      subst hi hj
      have e1 := h₀ _ si rfl
      have e2 := h₁ _ sj rfl
      simp_all

theorem project_place {x₀ : Place} {g : ScopeGrant} (hge : g.env = none)
    (hproj : x₀.project = g.project) (henv : x₀.envId = g.env) : x₀ = ⟨g.project, none⟩ := by
  obtain ⟨pr, en⟩ := x₀
  cases en <;> simp_all [Place.envId]

/--
**A personal token never holds more than its issuer did.** Whatever the
policy has become (`h₁.policy`: roles widened, environments protected),
whatever grants its issuer holds now, a request on a token whose every
grant `h₀` issued (`IssuedBy`) holds `p` at `x` only if `h₀` held `p` at `x`
when they issued it, as protected as `x` is now.
-/
theorem personal_token_within_issuer {h₀ h₁ : Holdings} {slugOf : String → Option String}
    {s : List ScopeGrant} {p : Permission} {x : Place}
    (hcred : h₁.cred = some s) (hissued : ∀ g ∈ s, IssuedBy h₀ slugOf g)
    (hservice : h₁.service = h₀.service) (hblank : NoBlankEnv h₀) (hx : Located slugOf x)
    (ha : allows h₁ p x = true) :
    allows (h₀.withProtected h₁.policy.protectedEnvs) p x = true := by
  have hs := credential_within_scope hcred ha
  unfold scopeHolds at hs
  simp only [hcred, Option.getD_some, List.any_eq_true, Bool.and_eq_true] at hs
  obtain ⟨g, hgs, hcov, hhold⟩ := hs
  obtain ⟨x₀, pol, hloc₀, hproj, henv, hcols⟩ := hissued g hgs
  have hdef : scopeDef g = ⟨within (((pol.roles.get? g.role).map (·.normal)).getD []) (some (heldColumns h₀ x₀).normal),
      within (((pol.roles.get? g.role).map (·.prot)).getD []) (some (heldColumns h₀ x₀).prot)⟩ := by
    simp [scopeDef, hcols, issuedGrant]
  have hg' : guarded (h₀.withProtected h₁.policy.protectedEnvs) x = guarded h₁ x := by
    simp [guarded, Holdings.withProtected, hservice, protects]
  have hxproj : x.project = g.project := by
    unfold covers ScopeGrant.place at hcov; split at hcov <;> simp_all
  by_cases hp : p.projectOnly = true
  · -- A project-wide permission: the normal column, which protection never changes.
    have hin : p ∈ (heldColumns h₀ x₀).normal := by
      simp only [holds, hp, ite_true, hdef] at hhold
      exact mem_within (List.contains_iff_mem.mp hhold)
    simp only [heldColumns, List.mem_filter] at hin
    have h0 : allows h₀ p x₀ = true := by rw [allows_withProtected_projectOnly hp] at hin; exact hin.2
    rw [allows_withProtected_projectOnly hp]
    cases hge : g.env with
    | none => exact allows_project hxproj (Or.inl hp) (project_place hge hproj henv ▸ h0)
    | some e => exact located_eq hge hcov hproj henv hloc₀ hx ▸ h0
  · have hpf : p.projectOnly = false := by simpa using hp
    cases hgx : guarded h₁ x with
    | false =>
      -- Not protected now: the normal column, what the issuer held as if nothing were.
      have hin : p ∈ (heldColumns h₀ x₀).normal := by
        simp only [holds, hpf, hgx, hdef] at hhold
        exact mem_within (by simpa using hhold)
      simp only [heldColumns, List.mem_filter] at hin
      have hz : allows (h₀.withProtected []) p x = true := by
        cases hge : g.env with
        | none =>
          exact allows_project hxproj (Or.inr guarded_withProtected_none)
            (project_place hge hproj henv ▸ hin.2)
        | some e => exact located_eq hge hcov hproj henv hloc₀ hx ▸ hin.2
      rw [allows_withProtected_eq (qs := []) (by rw [hg', hgx, guarded_withProtected_none])]
      exact hz
    | true =>
      -- Protected now, for a person: the protected column, what the issuer held as if everything were.
      have hin : p ∈ (heldColumns h₀ x₀).prot := by
        simp only [holds, hpf, hgx, hdef] at hhold
        exact mem_within (by simpa using hhold)
      simp only [heldColumns, List.mem_filter] at hin
      obtain ⟨id, slug, hxe⟩ : ∃ id slug, x.env = some (id, slug) := by
        unfold guarded at hgx
        cases he : x.env with
        | none => simp [he] at hgx
        | some e => exact ⟨e.1, e.2, rfl⟩
      have hsvc : h₀.service = false := by
        unfold guarded at hgx; simp at hgx; rw [← hservice]; exact hgx.1
      have hgall : guarded (h₀.withProtected [EVERY_ENVIRONMENT]) x = true := by
        rw [guarded_withProtected_every hxe, hsvc]; rfl
      have hz : allows (h₀.withProtected [EVERY_ENVIRONMENT]) p x = true := by
        cases hge : g.env with
        | none =>
          have hx₀ := project_place hge hproj henv
          have hany : anyOf x₀ = ⟨g.project, some ("", none)⟩ := by rw [hx₀]; rfl
          rw [hany] at hin
          refine allows_blank hxproj hxe ⟨hblank.1, hblank.2⟩ ?_ hin.2
          rw [guarded_withProtected_every (id := "") (slug := none) rfl, guarded_withProtected_every hxe]
        | some e =>
          have hx₀ := located_eq hge hcov hproj henv hloc₀ hx
          have hany : anyOf x₀ = x₀ := by simp [anyOf, hx₀, hxe]
          rw [hany, hx₀] at hin
          exact hin.2
      rw [allows_withProtected_eq (qs := [EVERY_ENVIRONMENT]) (by rw [hg', hgx, hgall])]
      exact hz

/-! ## Protection never widens -/

/-- `definitionProblem`'s last rule: a role holds no more in a protected environment than in one that is not. -/
def ValidDef (d : RoleDef) : Prop := ∀ q ∈ d.prot, q ∈ d.normal

def ValidPolicy (pol : Policy) : Prop :=
  (∀ e ∈ pol.roles, ValidDef e.2) ∧ ∀ e ∈ pol.instanceRoles, ValidDef e.2

/-- Every grant of the credential kept columns a valid role would: `issuedGrant` of one, or a built-in's name. -/
def ValidCred (h : Holdings) : Prop := ∀ s, h.cred = some s → ∀ g ∈ s, ValidDef (scopeDef g)

theorem builtin_valid : ∀ e ∈ builtinRoles, ValidDef e.2 := by
  intro e he q hq
  simp [builtinRoles] at he
  rcases he with h | h | h | h | h | h | h <;> subst h <;>
    simp [Permission.all, Permission.projectOnly] at hq ⊢ <;> (try rcases hq with h | h | h | h | h) <;>
    (try subst h) <;> simp_all

theorem holds_unguarded {d : Option RoleDef} {p x} {h h' : Holdings}
    (hv : ∀ d', d = some d' → ValidDef d') (hg : guarded h' x = false) :
    holds d p x h = true → holds d p x h' = true := by
  cases d with
  | none => simp [holds]
  | some d =>
    unfold holds
    by_cases hp : p.projectOnly = true
    · simp [hp]
    · simp only [hp, hg]
      cases guarded h x
      · simp
      · simp only [ite_true, List.contains_iff_mem, Bool.false_eq_true, ite_false]
        exact hv d rfl p

/--
**A person holds no more in a protected environment.** Under a policy whose
roles are valid, what someone holds at `x` while its environment is
protected (`ps`), they hold there unprotected (`qs`) too.
-/
theorem protected_never_widens {h : Holdings} {ps qs p x}
    (hpol : ValidPolicy h.policy) (hcred : ValidCred h)
    (hg : guarded (h.withProtected qs) x = false)
    (ha : allows (h.withProtected ps) p x = true) : allows (h.withProtected qs) p x = true := by
  have vr : ∀ r d, h.policy.roles.get? r = some d → ValidDef d := fun r d hd => hpol.1 _ (Table.get?_some hd)
  have vi : ∀ r d, h.policy.instanceRoles.get? r = some d → ValidDef d := fun r d hd => hpol.2 _ (Table.get?_some hd)
  unfold allows held scopeHolds at *
  simp only [Holdings.withProtected, Bool.and_eq_true, Bool.or_eq_true, List.any_eq_true] at *
  obtain ⟨hc, hh⟩ := ha
  refine ⟨?_, ?_⟩
  · rcases hc with hn | ⟨g, hgs, hcov, hhold⟩
    · exact Or.inl hn
    · refine Or.inr ⟨g, hgs, hcov, holds_unguarded ?_ hg hhold⟩
      intro d hd
      cases hcr : h.cred with
      | none => simp [hcr] at hgs
      | some s => simp [hcr] at hgs; cases hd; exact hcred s hcr g hgs
  · rcases hh with ⟨hin, hhold⟩ | ⟨g, hgs, hcov, hhold⟩
    · exact Or.inl ⟨hin, holds_unguarded (vi _) hg hhold⟩
    · exact Or.inr ⟨g, hgs, hcov, holds_unguarded (vr _) hg hhold⟩

/-! ## Only an Owner of the project gives a service its sensitive values (R32)

`issuedScope` in `packages/server/src/api/services.ts` keeps each grant of a
service's credential as `serviceGrant` does: its role's columns now, reading
the sensitive values there only if its issuer is an Owner of the project
(`ownsProject`), and, replacing a binding, no more than that one did
(`narrowest`). -/

def narrowest (now before : ScopeGrant) : ScopeGrant :=
  let both (a b : List Permission) := a.filter (b.contains ·)
  let a := scopeDef now
  let b := scopeDef before
  { now with
    cols := some ⟨both a.normal b.normal, both a.prot b.prot⟩,
    sensitive := now.sensitive.map (· && before.sensitive == some true) }

def serviceGrant (caller : Holdings) (project : String) (env : Option String) (role : String)
    (before : Option ScopeGrant) : ScopeGrant :=
  let now := { issuedGrant project env role caller.policy none with sensitive := some (ownsProject caller project) }
  match before with
  | none => now
  | some b => narrowest now b

/-- Whoever owns a project, as `ownsProject` says: a person on a session, an Owner whose scope takes in the whole project, or an Owner by a grant on it. -/
theorem ownsProject_iff {c : Holdings} {proj : String} :
    ownsProject c proj = true ↔ c.cred = none ∧ c.service = false ∧
      ((c.role = "owner" ∧ inScope c.scope ⟨proj, none⟩ = true) ∨
        ∃ g ∈ c.grants, g.role = "owner" ∧ covers g.place ⟨proj, none⟩ = true) := by
  unfold ownsProject
  cases c.cred <;> simp

theorem serviceGrant_sensitive {caller proj env role before} :
    (serviceGrant caller proj env role before).sensitive = some true → ownsProject caller proj = true := by
  unfold serviceGrant narrowest
  cases before <;> cases ownsProject caller proj <;> simp

theorem serviceGrant_project {caller proj env role before} :
    (serviceGrant caller proj env role before).project = proj := by
  unfold serviceGrant narrowest; cases before <;> rfl

/-- What `readsSensitive` takes: a service, on a credential with a grant in the project that reads them. -/
theorem readsSensitive_iff {h : Holdings} {proj : String} :
    readsSensitive h proj = true ↔ h.service = true ∧ ∃ s, h.cred = some s ∧
      ∃ g ∈ s, g.sensitive = some true ∧ g.project = proj := by
  unfold readsSensitive
  cases h.cred <;> simp

/--
**R32.** A request reads a project's sensitive values only as a service, on
a credential one of whose grants in that project an Owner of the project
issued: no person, and no Owner of another project, ever handed it them.
-/
theorem owner_issued_only {h : Holdings} {proj : String} {s : List ScopeGrant}
    (hcred : h.cred = some s)
    (hissued : ∀ g ∈ s, ∃ caller project env role before, g = serviceGrant caller project env role before)
    (hr : readsSensitive h proj = true) :
    h.service = true ∧ ∃ caller : Holdings, ownsProject caller proj = true := by
  obtain ⟨hs, s', hc', g, hg, hsens, hproj⟩ := readsSensitive_iff.mp hr
  rw [hcred] at hc'; cases hc'
  obtain ⟨caller, project, env, role, before, rfl⟩ := hissued g hg
  rw [serviceGrant_project] at hproj
  subst hproj
  exact ⟨hs, caller, serviceGrant_sensitive hsens⟩

end Coffre
