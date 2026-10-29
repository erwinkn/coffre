import Coffre.Decide

/-!
# A use, decided on sealed inputs (0.15)

A model of `decideChecked`, `useEnvironments` and `readerOf` in
`packages/vault/src/decide.ts`, and of the bulk cap's rule, `bulkRule` in
`packages/vault/src/bulk.ts` (docs/design/sealed-inputs.md). Every input
a use reads arrives with its seal checked: whether the seal is the vault's
over its row (`valid`), and whether it is its object's newest (`current`).
HMAC is the driver's to compute, as the audit chain's MACs are
(`verifyEntries`); the order the decision checks them in, what it weighs,
and everything after, are the model's.

The code throws on a view no use's statement reads (a credential read
without its principal or its bulk row, a reference without its source, an
environment it weighs left unread); the model answers `unread` there. The
comparison draws only views as `readUse` builds them, so code and model
are compared on those; the theorems hold for every view.

- `allowed_sealed`: an allowed use read every input it weighs as the log's
  newest, each validly sealed.
- `stale_credential_refused`: a credential row that is not the log's
  refuses the use `stale` or `tampered`, never another code the replay
  would not give (HotPathOne's `StaleFirst`).
- `allowed_keyread`: an allowed use is one the 0.14 rules allow, on the
  reader its inputs make.
- `allowed_within_cap`, `bulkRule_writes_admitted`: an allowed use's key
  is in the principal's set, or fewer than the cap's count of other keys
  counted; the rule writes a key's row only for a request it admits, at
  the start of the request's refresh period (`periodOf_lags`: less than a
  refresh before the request's time, never after it).
-/

namespace Coffre

/-- `Checked`: an input's row, if any, and its seal checked. -/
structure In (α : Type) where
  row : Option α
  valid : Bool
  current : Bool
  deriving Repr, Inhabited

/-- What refuses a use on this input's seal alone: an invalid seal, then one that is not the newest. -/
def In.refusal {α} (i : In α) : Code :=
  if i.row.isSome && !i.valid then some "tampered"
  else if !i.current then some "stale"
  else none

/-- `PrincipalInput`: status, generation, instance role and scope, and each grant with its end. -/
structure PrincipalIn where
  active : Bool
  generation : Int
  role : String
  scope : Scope
  grants : List (Grant × Option Int)
  deriving Repr, Inhabited

/-- `CredentialInput`, with its account's generation when it was issued. -/
structure CredentialIn where
  principal : String
  workload : Bool
  scope : Option (List ScopeGrant)
  expiresAt : Option Int
  revoked : Bool
  generation : Int
  deriving Repr, Inhabited

/-- `SecretInput`, as a decision reads it: where it is, whether it is sensitive, a reference's source. -/
structure SecretIn where
  id : String
  project : String
  env : String
  sensitive : Bool
  /-- Whether it holds a wrapped key: a plain value or a reference holds none. -/
  wrapped : Bool
  /-- A plain value: its text's digest, no key. The vault hands its text back, decided as any value, uncapped (T145). -/
  plain : Bool
  source : Option String
  /-- A reference whose end its row says: neither a version of its own nor a source (0.14's `reference.end`). -/
  ended : Bool
  deriving Repr, Inhabited

/-- `EnvironmentInput`. -/
structure EnvIn where
  id : String
  project : String
  slug : String
  owner : Option String
  parent : Option String
  prot : Bool
  deleted : Bool
  archived : Bool
  /-- Its project's archival, apart from its own. -/
  projectArchived : Bool
  deriving Repr, Inhabited

/-- `RolesInput`: an Owner's edits, over the release's own tables. -/
structure RolesIn where
  roles : Table RoleDef
  instanceRoles : Table RoleDef
  deriving Repr, Inhabited

/-- `BulkRead`. -/
structure BulkIn where
  inSet : Bool
  others : Nat
  deriving Repr, Inhabited

/-- `CheckedView`; the policy's row, its cap's count. -/
structure UseView where
  credential : In CredentialIn
  principal : Option (In PrincipalIn)
  roles : In RolesIn
  policy : In Nat
  secret : In SecretIn
  source : Option (In SecretIn)
  envs : Table (In EnvIn)
  bulk : Option BulkIn
  deriving Repr, Inhabited

/-- `UseRequest`, but its credential and key, which the view was read by; `place`, 0.14's `through`. -/
structure UseReq where
  place : Option String
  purpose : String
  keepsSensitive : Bool
  time : Int
  deriving Repr, Inhabited

/-- The first of a list of refusals. -/
def firstSome : List Code → Code
  | [] => none
  | some c :: _ => some c
  | none :: rest => firstSome rest

/-- `[...new Set(ids)]`: each id once, where it first comes. -/
def dedup : List String → List String
  | [] => []
  | x :: xs => x :: (dedup xs).filter (· != x)

/-- `useEnvironments`. -/
def useEnvs (v : UseView) (place : Option String) : List String :=
  match v.secret.row with
  -- A key the place does not hold: the place it was sought in, where the caller's standing decides (T145).
  | none => place.toList
  | some s =>
    let value := match s.source with
      | none => some s
      | some _ => v.source.bind (·.row)
    let more := match value with
      | none => []
      | some x =>
        let personalParent := match (v.envs.get? x.env).bind (·.row) with
          | some e => if e.owner.isSome then e.parent.toList else []
          | none => []
        x.env :: personalParent
    dedup (place.toList ++ [s.env] ++ more)

/-- Each input's seal refusal, in the order the decision reaches them. -/
def sealRefusals (v : UseView) (envs : List (In EnvIn)) : List Code :=
  [v.credential.refusal] ++ (v.principal.map (·.refusal)).toList ++ [v.roles.refusal, v.policy.refusal, v.secret.refusal] ++
    (v.source.map (·.refusal)).toList ++ envs.map (·.refusal)

/-- JavaScript's `\s`, for `PRINCIPAL`. -/
def jsSpace (c : Char) : Bool :=
  [9, 10, 11, 12, 13, 32, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff].contains c.toNat ||
    (0x2000 ≤ c.toNat && c.toNat ≤ 0x200a)

/-- `PRINCIPAL`: `user:` or `token:`, then a first character that is neither space nor `:`, then no space. -/
def isPrincipal (s : String) : Bool :=
  let rest := if s.startsWith "user:" then some (s.drop 5).toString else if s.startsWith "token:" then some (s.drop 6).toString else none
  match rest with
  | none => false
  | some r => match r.toList with
    | [] => false
    | c :: cs => !jsSpace c && c != ':' && !cs.any jsSpace

/-- `live`: a grant with no end, or one after `at`. -/
def liveAt (time : Int) (e : Option Int) : Bool := match e with | none => true | some t => t > time

/-- The protected environments by project, in the order they come (`protectedIn`'s reduce). -/
def protectedInOf : List EnvIn → Table (List (String × Option String))
  | [] => []
  | e :: es =>
    let rest := protectedInOf es
    -- Built from the end, each project's list kept in order, at its first place.
    match rest.find? (·.1 == e.project) with
    | some _ => rest.map fun (p, xs) => if p == e.project then (p, (e.id, some e.slug) :: xs) else (p, xs)
    | none => (e.project, [(e.id, some e.slug)]) :: rest

/-- `readerOf`. -/
def readerOf (p : Option PrincipalIn) (c : CredentialIn) (roles : RolesIn) (envs : List EnvIn) (time : Int) : Reader :=
  let none' : Holdings := { NOTHING defaultPolicy with cred := c.scope, workload := c.workload }
  match p with
  | none => ⟨.unknown, none', none'⟩
  | some m =>
    if !isPrincipal c.principal then ⟨.unknown, none', none'⟩
    else if !m.active then ⟨.removed, none', none'⟩
    else
      let guarded := envs.filter fun e => e.prot && !e.deleted
      let pol : Policy := ⟨roles.roles ++ builtinRoles, roles.instanceRoles ++ builtinInstanceRoles, guarded.map (·.id), protectedInOf guarded⟩
      let person := c.principal.startsWith "user:"
      let role := if person then m.role else "member"
      let scope := if person then m.scope else EVERYWHERE
      let holdings (gs : List Grant) : Holdings := ⟨role, scope, gs, c.scope, pol, !person, c.workload⟩
      ⟨.active, holdings ((m.grants.filter fun (_, e) => liveAt time e).map (·.1)), holdings (m.grants.map (·.1))⟩

/-- Whether the cap refuses what a use read: a key not in the set, with `count` others counted. -/
def capRefusal (count : Nat) (b : BulkIn) : Code :=
  if !b.inSet && b.others ≥ count then some "bulk_limit" else none

/-- No edits, when the log has no roles object. -/
def noEdits : RolesIn := ⟨[], []⟩

/-- What its rows say before 0.14's rules: its credential, its key, where it is read; then the key's read, as `KeyRead`. -/
def keyOf (v : UseView) (r : UseReq) (ids : List String) : Except String KeyRead :=
  match v.credential.row with
  | none => .error "credential"
  | some c =>
    -- Of an earlier generation than its account's: a removal ended it, before its sweep revokes it.
    if c.revoked || (match c.expiresAt with | some e => r.time ≥ e | none => false)
      || (match v.principal.bind (·.row) with | some m => m.active && m.generation != c.generation | none => false) then .error "credential"
    else match v.secret.row with
    | none =>
      -- A key the place does not hold (T145; Probing.tla, MissingByStanding): refused as the caller stands where it
      -- was sought, and `missing` only to one who may act there, so that nobody it refuses learns whether it is held.
      let rows : Table EnvIn := ids.filterMap fun id => ((v.envs.get? id).bind (·.row)).map (id, ·)
      match r.place with
      | none => .error "missing"
      | some p => match rows.get? p with
        | none => .error "missing"
        | some e =>
          let reader := readerOf (v.principal.bind (·.row)) c (v.roles.row.getD noEdits) (rows.map (·.2)) r.time
          let envRows : Table EnvRow := rows.map fun (id, e) => (id, ⟨e.project, e.slug, e.owner, e.parent, e.deleted⟩)
          let perm : Permission := if r.purpose == "use" then .use else .read
          match keyRefusal reader c.principal perm ⟨e.project, p⟩ ⟨e.project, p⟩ envRows none false with
          | some code => .error code
          | none => .error "missing"
    | some s =>
      let value := match s.source with
        | none => some s
        | some _ => v.source.bind (·.row)
      match value with
      | none => .error "ended"
      | some x =>
        if s.ended then .error "ended" else
        if x.source.isSome && s.source.isSome then .error "bad_claim" else
        if !x.wrapped && !x.plain then .error "bad_claim" else
        -- The rows read, by the id each was read by.
        let rows : Table EnvIn := ids.filterMap fun id => ((v.envs.get? id).bind (·.row)).map (id, ·)
        -- Through a fork, as 0.14's `throughOk`: a live, unarchived environment of the key's project, unarchived too, not its own.
        let throughOk := match r.place with
          | none => true
          | some p => p != s.env && match rows.get? p with
            | some f => f.project == s.project && !f.deleted && !f.archived && !f.projectArchived
            | none => false
        if !throughOk then .error "bad_claim"
        else if v.policy.row.isNone then .error "no_policy"
        else
          let reader := readerOf (v.principal.bind (·.row)) c (v.roles.row.getD noEdits) (rows.map (·.2)) r.time
          let envRows : Table EnvRow := rows.map fun (id, e) => (id, ⟨e.project, e.slug, e.owner, e.parent, e.deleted⟩)
          .ok ⟨reader, c.principal, some r.purpose, r.keepsSensitive, ⟨x.project, x.env⟩, x.id, ⟨s.project, s.env⟩, envRows,
            x.sensitive, s.source.isSome⟩

/-- What refuses a use by its rows: before the rules, or by them. -/
def rowsRefusal (v : UseView) (r : UseReq) (ids : List String) : Code :=
  match keyOf v r ids with
  | .error c => some c
  | .ok k => k.decide none

/-- Whether the value a use reads is plain: its key's own, or its reference's source's. -/
def plainValue (v : UseView) : Bool :=
  match v.secret.row with
  | none => false
  | some s => match s.source with
    | none => s.plain
    | some _ => (v.source.bind (·.row)).any (·.plain)

/-- The cap, on the policy's count and what the use read of it: none for a plain value, which counts toward nothing. -/
def capOf (v : UseView) : Code :=
  if plainValue v then none else
  match v.policy.row, v.bulk with
  | some count, some b => capRefusal count b
  | none, _ => some "no_policy"
  | _, none => some "unread"

/-- `decideChecked`: every environment it weighs read, then every seal, then its rows and 0.14's rules, then the cap. -/
def decideUse (v : UseView) (r : UseReq) : Code :=
  match (useEnvs v r.place).mapM (v.envs.get? ·) with
  | none => some "unread"
  | some envs => ((firstSome (sealRefusals v envs)).orElse fun _ => rowsRefusal v r (useEnvs v r.place)).orElse fun _ => capOf v

/-! ## The bulk cap's rule -/

structure Limit where
  count : Nat
  window : Int
  deriving Repr, Inhabited

/-- `USE_DEADLINE_MS`. -/
def useDeadline : Int := 3000

/-- `USE_AHEAD_MS`: how far past the database's clock a use may be stamped. -/
def useAhead : Int := 60000

/-- `refreshMs`: a minute, or a tenth of a shorter window, at least 1 ms. -/
def refreshOf (l : Limit) : Int := max 1 (min 60000 (l.window / 10))

/-- `periodOf`: the start of `time`'s refresh period. -/
def periodOf (time refresh : Int) : Int := time - time % refresh

/-- What the rule writes: the request's period, for a request it admits whose key's row is from an earlier one, or missing. -/
def bulkWrite (inSet : Bool) (others count : Nat) (stale : Bool) (period : Int) : Option Int :=
  if (inSet || decide (others < count)) && stale then some period else none

/-- `bulkRule`: whether the key is in the set, how many others count (up to `count`), and what it writes. -/
def bulkRule (rows : Table Int) (key : String) (time : Int) (l : Limit) : Bool × Nat × Option Int :=
  let refresh := refreshOf l
  let last := rows.get? key
  let inSet := match last with | some t => decide (t > time - l.window - refresh) | none => false
  let others := if inSet then 0 else min l.count (rows.filter fun (k, t) => k != key && decide (t > time - l.window - refresh - useDeadline - useAhead)).length
  let period := periodOf time refresh
  let stale := match last with | some t => decide (t < period) | none => true
  (inSet, others, bulkWrite inSet others l.count stale period)

/-! ## What it promises -/

theorem firstSome_none {l : List Code} (h : firstSome l = none) : ∀ c ∈ l, c = none := by
  induction l with
  | nil => simp
  | cons x xs ih =>
    cases x with
    | some _ => simp [firstSome] at h
    | none =>
      simp only [firstSome] at h
      intro c hc
      rcases List.mem_cons.mp hc with rfl | hc
      · rfl
      · exact ih h c hc

theorem In.refusal_none {α} {i : In α} (h : i.refusal = none) : i.current = true ∧ (i.row.isSome → i.valid = true) := by
  unfold In.refusal at h
  by_cases hv : i.row.isSome && !i.valid <;> by_cases hc : i.current <;> simp_all

/--
**Sealed before it is allowed.** A use is allowed only if every input it
weighs, its credential, principal, roles, policy, key, a reference's
source and each environment, was read as its object's newest change left
it, under the vault's seal.
-/
theorem allowed_sealed {v : UseView} {r : UseReq} (h : decideUse v r = none) :
    ∃ envs, (useEnvs v r.place).mapM (v.envs.get? ·) = some envs ∧
      ∀ c ∈ sealRefusals v envs, c = none := by
  unfold decideUse at h
  split at h
  · cases h
  · rename_i envs henvs
    exact ⟨envs, henvs, firstSome_none (orElse_none (orElse_none h).1).1⟩

/-- In particular its credential: current, and validly sealed. -/
theorem allowed_credential_sealed {v : UseView} {r : UseReq} (h : decideUse v r = none) :
    v.credential.current = true ∧ (v.credential.row.isSome → v.credential.valid = true) := by
  obtain ⟨envs, _, hall⟩ := allowed_sealed h
  exact In.refusal_none (hall _ (by simp [sealRefusals]))

/--
**A row put back is `stale` first.** A credential whose row is not the
log's newest refuses the use as `tampered` or `stale`, whatever its rows
say: never a refusal the replay of the log would give too.
-/
theorem stale_credential_refused {v : UseView} {r : UseReq}
    (hread : ((useEnvs v r.place).mapM (v.envs.get? ·)).isSome = true) (hc : v.credential.current = false) :
    decideUse v r = some "tampered" ∨ decideUse v r = some "stale" := by
  have hr : v.credential.refusal = some "tampered" ∨ v.credential.refusal = some "stale" := by
    unfold In.refusal
    by_cases ht : (v.credential.row.isSome && !v.credential.valid) = true <;> simp [ht, hc]
  unfold decideUse
  split
  · rename_i heq; simp [heq] at hread
  · rcases hr with hr | hr <;> simp [sealRefusals, firstSome, hr, Option.orElse]

/-- **0.14's rules, unchanged.** An allowed use is one `KeyRead.decide` allows, on the reader its sealed inputs make. -/
theorem allowed_keyread {v : UseView} {r : UseReq} (h : decideUse v r = none) :
    ∃ k, keyOf v r (useEnvs v r.place) = .ok k ∧ k.decide none = none := by
  unfold decideUse at h
  split at h
  · cases h
  · have hrows := (orElse_none (orElse_none h).1).2
    unfold rowsRefusal at hrows
    split at hrows
    · cases hrows
    · rename_i k hk
      exact ⟨k, hk, hrows⟩

/--
**Of its account's generation.** An allowed use's credential, of an active
account, was issued at the generation the account holds: one a removal moved
past, which its sweep has yet to revoke, is refused (formal/Credentials.tla,
UseDecidesGeneration).
-/
theorem allowed_same_generation {v : UseView} {r : UseReq} (h : decideUse v r = none) :
    ∀ c m, v.credential.row = some c → v.principal.bind (·.row) = some m → m.active = true → m.generation = c.generation := by
  intro c m hc hm ha
  obtain ⟨k, hk, _⟩ := allowed_keyread h
  cases hb : (m.generation != c.generation)
  · simpa using hb
  · unfold keyOf at hk
    simp [hc, hm, ha, hb] at hk

/--
**Within the cap.** An allowed use's key, of a value that is not plain, is in its principal's set, or fewer than the
log's count of other keys count. A plain value counts toward nothing (T145).
-/
theorem allowed_within_cap {v : UseView} {r : UseReq} (h : decideUse v r = none) (hplain : plainValue v = false) :
    ∃ count b, v.policy.row = some count ∧ v.bulk = some b ∧ (b.inSet = true ∨ b.others < count) := by
  unfold decideUse at h
  split at h
  · cases h
  · have hcap := (orElse_none h).2
    unfold capOf at hcap
    simp only [hplain, Bool.false_eq_true, ↓reduceIte] at hcap
    split at hcap
    · rename_i count b hp hb
      refine ⟨count, b, hp, hb, ?_⟩
      unfold capRefusal at hcap
      by_cases hi : b.inSet <;> simp_all
    · cases hcap
    · cases hcap

theorem bulkWrite_admitted {i : Bool} {o c : Nat} {st : Bool} {period t : Int} (h : bulkWrite i o c st period = some t) :
    t = period ∧ (i = true ∨ o < c) := by
  unfold bulkWrite at h
  split at h
  · rename_i hadm
    refine ⟨(Option.some.inj h).symm, ?_⟩
    simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at hadm
    exact hadm.1
  · cases h

/-- A period starts less than a refresh before its time, and never after it: so `last` lags a key's newest
use by less than `refresh`, which the set's bound adds back. -/
theorem periodOf_lags {time refresh : Int} (h : 0 < refresh) : periodOf time refresh ≤ time ∧ time - refresh < periodOf time refresh := by
  unfold periodOf
  have h1 := Int.emod_nonneg time (Int.ne_of_gt h)
  have h2 := Int.emod_lt_of_pos time h
  omega

/-- **The rule writes only for what it admits,** at the start of the request's refresh period. -/
theorem bulkRule_writes_admitted {rows : Table Int} {key : String} {time t : Int} {l : Limit} {i : Bool} {o : Nat}
    (h : bulkRule rows key time l = (i, o, some t)) : t = periodOf time (refreshOf l) ∧ (i = true ∨ o < l.count) := by
  unfold bulkRule at h
  simp only [Prod.mk.injEq] at h
  obtain ⟨rfl, rfl, hw⟩ := h
  exact bulkWrite_admitted hw

end Coffre
