import Coffre.AccessProofs

/-!
# How the vault decides each key

A model of `packages/vault/src/decide.ts`: what refuses each key of one call
to the vault, by where it is (`keyRefusals`), then by its sensitivity
(`sensitiveRefusals`). Between the two, the vault asks `vet` about keys
nothing refused yet, so every theorem here holds whatever it answers.

- `no_person_reads_sensitive`: no person, Owner or not, on a session or any
  token of theirs, is handed back a sensitive value: read directly, through a
  reference, in a fork or a personal config.
- `service_reads_sensitive_only_owner_issued`: a service is handed one back
  only on a credential an Owner of the value's own project issued it for
  (R32), the source's project for a reference.
- `copy_keeps_sensitive`, `copy_never_through_reference`: a fork copies a
  sensitive value, for anyone, only where it keeps it sensitive, and never
  one read through a reference.
- `personal_owner_only`: a personal config's key opens for its owner alone,
  and never through a reference.
- `reference_made_by_reader`: making a reference takes reading its source,
  and using it too if it is sensitive (R24).
- `reference_shares_by_design`: a reference does let someone read what they
  could not at its source: that is what it is for (R20), and the theorem
  shows it, so the model cannot be read as promising otherwise.
-/

namespace Coffre

inductive Status where
  | active | removed | unknown | tampered
  deriving DecidableEq, Repr, Inhabited

/-- `Reader`: whether they are a member, what they hold now, and with their lapsed grants. -/
structure Reader where
  status : Status
  live : Holdings
  all : Holdings
  deriving Repr, Inhabited

/-- `EnvironmentRow`, by its id. -/
structure EnvRow where
  project : String
  slug : String
  owner : Option String
  parent : Option String
  deleted : Bool
  deriving Repr, Inhabited, DecidableEq

/-- `SecretPlace`. -/
structure SecretPlace where
  project : String
  env : String
  deriving Repr, Inhabited, DecidableEq

abbrev Code := Option String

def placeIn (s : SecretPlace) (envs : Table EnvRow) : Place :=
  let slug := match envs.get? s.env with
    | some e => if e.project == s.project then some e.slug else none
    | none => none
  ⟨s.project, some (s.env, slug)⟩

def refuses (r : Reader) (p : Permission) (x : Place) (deleted : Bool) : Code :=
  match r.status with
  | .tampered => some "tampered"
  | .removed => some "removed"
  | .unknown => some "not_a_member"
  | .active =>
    if deleted then some "deleted"
    else if allows r.live p x then none
    else if allows r.all p x then some "expired"
    else some "no_grant"

/-- `personalRefusal`: none for a key of no personal config, decided as ever. -/
def personalRefusal (r : Reader) (principal : String) (p : Permission) (secret held : SecretPlace)
    (envs : Table EnvRow) : Option Code :=
  let own := envs.get? secret.env
  let heldAt := if held.env == secret.env then own else envs.get? held.env
  if (own.bind (·.owner)).isNone && (heldAt.bind (·.owner)).isNone then none
  else
    match own with
    | none => some (some "personal")
    | some o =>
      if held.env != secret.env || some principal != o.owner then some (some "personal")
      else match o.parent with
        | none => some (some "personal")
        | some parentId =>
          let parent := placeIn ⟨secret.project, parentId⟩ envs
          let gone := o.deleted || ((envs.get? parentId).map (·.deleted)).getD true
          let refused := if (refuses r .use parent gone).isNone then none else refuses r .read parent gone
          if refused.isSome then some refused
          else if withinCredential r.live (if p == .read then .use else p) parent then some none
          else some (some "no_grant")

def gone (envs : Table EnvRow) (s : SecretPlace) : Bool := ((envs.get? s.env).map (·.deleted)).getD false

/-- `keyRefusals`, for one key: `need`, any one of which it takes besides `p`; `owns`, whether it takes owning its project. -/
def keyRefusal (r : Reader) (principal : String) (p : Permission) (secret held : SecretPlace)
    (envs : Table EnvRow) (need : Option (List Permission)) (owns : Bool) : Code :=
  let code : Code :=
    match personalRefusal r principal p secret held envs with
    | some c => c
    | none =>
      let place := placeIn held envs
      let deleted := gone envs secret || gone envs held
      let alsoRefused : Option Code := need.bind fun also =>
        let refused := also.map fun q => refuses r q place deleted
        if refused.all (·.isSome) then some ((refused.head?.join).orElse fun _ => some "no_grant") else none
      match alsoRefused with
      | some c => c
      | none => refuses r p place deleted
  if code.isNone && owns && !ownsProject r.live secret.project then some "not_allowed" else code

inductive Action where
  | read | wrap | rewrap
  deriving DecidableEq, Repr, Inhabited

/-- `sensitiveRefusals`, for one key. -/
def sensitiveRefusal (code : Code) (r : Reader) (action : Action) (principal : String)
    (purpose : Option String) (keepsSensitive : Bool) (project : String) (sensitive : Bool) (viaReference : Bool) : Code :=
  let copying := action == .read && purpose == some "copy"
  let handedBack := action == .read && handsBack (purpose.getD "") keepsSensitive
  let person := principal.startsWith "user:"
  if code.isSome || !sensitive then code
  else if (copying && !keepsSensitive) || (copying && viaReference) || (handedBack && person) then some "sensitive"
  else if handedBack && !readsSensitive r.live project then some "not_owner_issued"
  else none

/-- One key of a read, decided: by where it is, by `vet`, which the vault asks only when nothing refused it yet, and by its sensitivity. -/
structure KeyRead where
  reader : Reader
  principal : String
  purpose : Option String
  keepsSensitive : Bool
  secret : SecretPlace
  /-- Where the permission is checked: a reference's holder, or the secret itself. -/
  held : SecretPlace
  envs : Table EnvRow
  /-- The secret's nature, as the version read says: a reference's, its source's now (R23). -/
  sensitive : Bool
  /-- Whether it is read through a reference. -/
  viaReference : Bool

/-- The permission a read checks: the proxy's use, or read (`unwrap`). -/
def KeyRead.permission (k : KeyRead) : Permission := if k.purpose == some "use" then .use else .read

def KeyRead.decide (k : KeyRead) (vet : Code) : Code :=
  sensitiveRefusal ((keyRefusal k.reader k.principal k.permission k.secret k.held k.envs none false).orElse fun _ => vet)
    k.reader .read k.principal k.purpose k.keepsSensitive k.secret.project k.sensitive k.viaReference

/-! ## Sensitive values -/

theorem sensitiveRefusal_some {code r a pr pu ks proj s via} (h : code.isSome = true) :
    (sensitiveRefusal code r a pr pu ks proj s via).isSome = true := by
  simp [sensitiveRefusal, h]

theorem sensitiveRefusal_person {c r pr pu ks proj via} (hperson : pr.startsWith "user:" = true)
    (hb : handsBack (pu.getD "") ks = true) : (sensitiveRefusal c r .read pr pu ks proj true via).isSome = true := by
  cases c <;> simp [sensitiveRefusal, hperson, hb]

theorem sensitiveRefusal_service {c r pr pu ks proj via} (hb : handsBack (pu.getD "") ks = true)
    (h : sensitiveRefusal c r .read pr pu ks proj true via = none) : readsSensitive r.live proj = true := by
  cases c with
  | some c => simp [sensitiveRefusal] at h
  | none =>
    cases hr : readsSensitive r.live proj
    · unfold sensitiveRefusal at h
      simp [hb, hr] at h
      split at h <;> simp at h
    · rfl

theorem sensitiveRefusal_copy {c r pr ks proj via} (hkeep : ks = false) :
    (sensitiveRefusal c r .read pr (some "copy") ks proj true via).isSome = true := by
  cases c <;> simp [sensitiveRefusal, hkeep]

theorem sensitiveRefusal_copy_reference {c r pr ks proj} :
    (sensitiveRefusal c r .read pr (some "copy") ks proj true true).isSome = true := by
  cases c <;> simp [sensitiveRefusal]

/--
**No person reads a sensitive value.** A read whose principal is a person
(`user:`) and that would hand the value back (`handsBack`: every purpose but
the proxy's use and a copy that keeps it sensitive) is refused, whoever they
are, on whatever credential, wherever the value is read from.
-/
theorem no_person_reads_sensitive (k : KeyRead) (vet : Code)
    (hperson : k.principal.startsWith "user:" = true) (hs : k.sensitive = true)
    (hb : handsBack (k.purpose.getD "") k.keepsSensitive = true) :
    (k.decide vet).isSome = true := by
  unfold KeyRead.decide; rw [hs]; exact sensitiveRefusal_person hperson hb

/--
**R32, at the read.** A service is handed back a sensitive value only if its
credential reads the sensitive values of the value's own project: the
source's, through a reference, wherever the reference lives.
-/
theorem service_reads_sensitive_only_owner_issued (k : KeyRead) (vet : Code)
    (hs : k.sensitive = true) (hb : handsBack (k.purpose.getD "") k.keepsSensitive = true)
    (hallowed : k.decide vet = none) : readsSensitive k.reader.live k.secret.project = true := by
  unfold KeyRead.decide at hallowed; rw [hs] at hallowed; exact sensitiveRefusal_service hb hallowed

/-- And so, with `owner_issued_only`, only on a grant in that project whose issuer owns it. -/
theorem service_sensitive_from_owner (k : KeyRead) (vet : Code) {s : List ScopeGrant} (issuerOf : ScopeGrant → Holdings)
    (hs : k.sensitive = true) (hb : handsBack (k.purpose.getD "") k.keepsSensitive = true)
    (hcred : k.reader.live.cred = some s)
    (hissued : ∀ g ∈ s, ∃ project env role before, g = serviceGrant (issuerOf g) project env role before)
    (hallowed : k.decide vet = none) :
    k.reader.live.service = true ∧ ∃ g ∈ s, g.project = some k.secret.project ∧ g.sensitive = some true ∧
      ownsProject (issuerOf g) k.secret.project = true :=
  owner_issued_only issuerOf hcred hissued (service_reads_sensitive_only_owner_issued k vet hs hb hallowed)

/-- A fork copies a sensitive value only where its app keeps it sensitive, for anyone, a service too. -/
theorem copy_keeps_sensitive (k : KeyRead) (vet : Code) (hs : k.sensitive = true)
    (hcopy : k.purpose = some "copy") (hkeep : k.keepsSensitive = false) : (k.decide vet).isSome = true := by
  unfold KeyRead.decide; rw [hs, hcopy]; exact sensitiveRefusal_copy hkeep

/-- Nor does a fork ever copy a sensitive value read through a reference, kept sensitive or not: it keeps a reference, so the value stays in its own project. -/
theorem copy_never_through_reference (k : KeyRead) (vet : Code) (hs : k.sensitive = true)
    (hcopy : k.purpose = some "copy") (hvia : k.viaReference = true) : (k.decide vet).isSome = true := by
  unfold KeyRead.decide; rw [hs, hcopy, hvia]; exact sensitiveRefusal_copy_reference

/-! ## Personal configs -/

theorem keyRefusal_of_personal {r principal p secret held envs need owns c}
    (h : personalRefusal r principal p secret held envs = some (some c)) :
    keyRefusal r principal p secret held envs need owns = some c := by
  simp [keyRefusal, h]

/--
**A personal config's key is its owner's alone.** A key in an environment
with an owner opens for nobody else, whatever their grants or role, and
through no reference: not one held elsewhere reading it, nor one held in it.
-/
theorem personal_owner_only {r principal p secret held envs need owns} {o : EnvRow}
    (hown : envs.get? secret.env = some o) (howner : o.owner.isSome = true)
    (hnot : some principal ≠ o.owner ∨ held.env ≠ secret.env) :
    keyRefusal r principal p secret held envs need owns = some "personal" := by
  apply keyRefusal_of_personal
  obtain ⟨v, hv⟩ := Option.isSome_iff_exists.mp howner
  unfold personalRefusal
  rcases hnot with h | h
  · rw [hv] at h
    have : principal ≠ v := fun e => h (e ▸ rfl)
    simp [hown, hv, this]
  · simp [hown, hv, h]

/-- Nor does a reference held in a personal config read anything. -/
theorem personal_holds_no_reference {r principal p secret held envs need owns} {o : EnvRow}
    (hheld : envs.get? held.env = some o) (howner : o.owner.isSome = true) (hdiff : held.env ≠ secret.env) :
    keyRefusal r principal p secret held envs need owns = some "personal" := by
  apply keyRefusal_of_personal
  obtain ⟨v, hv⟩ := Option.isSome_iff_exists.mp howner
  unfold personalRefusal
  cases envs.get? secret.env <;> simp [hheld, hv, hdiff]

/-! ## References

Making a reference (`reference` in `vault.ts`, its check `referenceRefusal`) takes writing where it is
held, reading its source, and using it there too if it is sensitive (R24). A
read through it is decided where it is held, by its source's nature (R20,
R23): a share, by someone who could read the value, to whoever reads where
it lands. -/

/-- `referenceRefusal`: `reference`'s check of one reference, past what only the database settles (`bad_claim`, `invalid`). -/
def referenceRefusal (r : Reader) (holder source : SecretPlace) (envs : Table EnvRow)
    (sourceSensitive : Bool) : Code :=
  let ownerOf (s : SecretPlace) := (envs.get? s.env).bind (·.owner)
  if (ownerOf holder).isSome || (ownerOf source).isSome then some "personal"
  else
    let src := placeIn source envs
    (refuses r .write (placeIn holder envs) (gone envs holder)).orElse fun _ =>
      (refuses r .read src (gone envs source)).orElse fun _ =>
        if sourceSensitive then refuses r .use src (gone envs source) else none

theorem refuses_none {r p x d} (h : refuses r p x d = none) : allows r.live p x = true := by
  unfold refuses at h
  cases hs : r.status <;> simp [hs] at h
  by_cases hd : d <;> simp [hd] at h
  by_cases ha : allows r.live p x <;> simp_all
  split at h <;> simp at h

/--
**Whoever makes a reference reads its source.** A reference is made only by
someone who reads the source's value there, uses it there too if it is
sensitive, and writes where it is held.
-/
theorem orElse_none {a b : Code} (h : (a.orElse fun _ => b) = none) : a = none ∧ b = none := by
  cases a <;> simp_all [Option.orElse]

theorem reference_made_by_reader {r holder source envs sens}
    (h : referenceRefusal r holder source envs sens = none) :
    allows r.live .write (placeIn holder envs) = true ∧ allows r.live .read (placeIn source envs) = true ∧
      (sens = true → allows r.live .use (placeIn source envs) = true) := by
  unfold referenceRefusal at h
  dsimp only at h
  split at h
  · cases h
  · obtain ⟨hw, h⟩ := orElse_none h
    obtain ⟨hr, hu⟩ := orElse_none h
    refine ⟨refuses_none hw, refuses_none hr, fun hs => ?_⟩
    simp only [hs, ↓reduceIte] at hu
    exact refuses_none hu

/--
**A reference shares, by design.** Bo, a Viewer of `web/dev` alone, reads
`web/dev/API`, a reference Ada made to `api/dev/KEY`, which Bo cannot read
at its source. R20: a reference takes its value and nature from its source
and its permissions from where it lives. The guarantee is
`reference_made_by_reader`: whoever made it could read it.
-/
theorem reference_shares_by_design :
    let envs : Table EnvRow := [("web-dev", ⟨"web", "dev", none, none, false⟩), ("api-dev", ⟨"api", "dev", none, none, false⟩)]
    let bo : Holdings := ⟨"member", EVERYWHERE, [⟨⟨some "web", some "web-dev"⟩, "viewer"⟩], none, defaultPolicy, false⟩
    let r : Reader := ⟨.active, bo, bo⟩
    let read : KeyRead := ⟨r, "user:bo", some "reveal", false, ⟨"api", "api-dev"⟩, ⟨"web", "web-dev"⟩, envs, false, true⟩
    read.decide none = none ∧ refuses r .read (placeIn (⟨"api", "api-dev"⟩ : SecretPlace) envs) false = some "no_grant" := by
  decide

end Coffre
