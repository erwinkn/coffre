import Coffre.Decide

/-!
# Envelope encryption: what a ciphertext is bound to

`packages/core/src/envelope.ts` and `context.ts`: each version's value is
sealed under a fresh data key (DEK) with AES-256-GCM, its AAD the secret's
ids; the vault wraps the DEK under the KEK, its AAD the whole context: the
ids, a personal config's owner (hashed), and whether it is sensitive, then
the KEK's identity (`kek/local.ts`).

We do not prove AES-GCM secure. We take the standard property of an AEAD,
integrity of ciphertexts, as an assumption about the world (`Assumptions`):
whoever does not hold a key makes no ciphertext that opens under it, except
those its holder made. Under it, and with the AAD encoding injective, which
we do prove (`encodeAad_injective`), a ciphertext that opens for a context
is one the vault made for exactly that context.

- `encodeAad_injective`: no two contexts encode to the same AAD.
- `open_only_as_sealed`: what opens as `ctx` is a value whose key the vault
  wrapped as exactly `ctx`, and the value it encrypted under that key: no
  swap across projects, environments, keys, owners or sensitivity.
- `versions_not_bound`: what is not bound. Two versions of one key share a
  context, so either's row opens as the other's: a rollback, which needs a
  write to the database and is the limit coffre accepts everywhere
  (docs/design/oidc.md, "Rollback is the accepted limit").
- `no_person_opens_sensitive`: the decision and the binding together. Even
  when an attacker rewrites the database's sensitivity, owner or place
  columns, a person is handed back only a value whose key the vault wrapped
  not sensitive for that place, and no personal config's value but their own;
  `sensitive_value_never_reaches_a_person`: so never a value whose key it
  only ever wrapped sensitive.
-/

namespace Coffre.Envelope

/-- `SecretContext`: the ids, a personal config's owner as `ownerKey` hashes them, and whether it is sensitive. -/
structure Ctx where
  project : String
  env : String
  secret : String
  owner : Option String
  sensitive : Bool
  deriving DecidableEq, Repr, Inhabited

/-! ## The AAD encoding is injective -/

def SEP : Char := '|'

/-- Fields joined with `|`. -/
def joinSep : List (List Char) → List Char
  | [] => []
  | [w] => w
  | w :: ws => w ++ SEP :: joinSep ws

/-- Bytes split at each `|`. -/
def splitSep : List Char → List (List Char)
  | [] => [[]]
  | x :: xs =>
    if x = SEP then [] :: splitSep xs
    else match splitSep xs with
      | [] => [[x]]
      | w :: ws => (x :: w) :: ws

theorem splitSep_plain {w : List Char} (h : SEP ∉ w) : splitSep w = [w] := by
  induction w with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.mem_cons, not_or] at h
    simp [splitSep, Ne.symm h.1, ih h.2]

theorem splitSep_append {w rest : List Char} (h : SEP ∉ w) :
    splitSep (w ++ SEP :: rest) = w :: splitSep rest := by
  induction w with
  | nil => simp [splitSep]
  | cons x xs ih =>
    simp only [List.mem_cons, not_or] at h
    have hr := ih h.2
    simp only [List.cons_append, splitSep, Ne.symm h.1, ite_false, hr]

theorem splitSep_joinSep {ws : List (List Char)} (hne : ws ≠ []) (h : ∀ w ∈ ws, SEP ∉ w) :
    splitSep (joinSep ws) = ws := by
  induction ws with
  | nil => exact absurd rfl hne
  | cons w ws ih =>
    cases ws with
    | nil => simp [joinSep, splitSep_plain (h w (by simp))]
    | cons v vs =>
      simp only [joinSep]
      rw [splitSep_append (h w (by simp)), ih (by simp) (fun u hu => h u (by simp [hu]))]

theorem joinSep_injective {ws vs : List (List Char)} (hw : ws ≠ []) (hv : vs ≠ [])
    (h₁ : ∀ w ∈ ws, SEP ∉ w) (h₂ : ∀ v ∈ vs, SEP ∉ v) (h : joinSep ws = joinSep vs) : ws = vs := by
  rw [← splitSep_joinSep hw h₁, ← splitSep_joinSep hv h₂, h]

def AAD_VERSION : String := "coffre.aad.v1"

/-- `encodeAad`'s fields, in order. -/
def fields (c : Ctx) : List (List Char) :=
  [AAD_VERSION.toList, c.project.toList, c.env.toList, c.secret.toList] ++
    ((c.owner.map fun o => ["owner:".toList ++ o.toList]).getD []) ++
    (if c.sensitive then ["sensitive".toList] else [])

/-- `encodeAad`: `coffre.aad.v1|<project>|<environment>|<secret>[|owner:<hash>][|sensitive]`. -/
def encodeAad (c : Ctx) : List Char := joinSep (fields c)

/-- What `checkContext` ensures, and all injectivity needs: no field holds the separator (a UUID, a hex hash). -/
def Wellformed (c : Ctx) : Prop :=
  SEP ∉ c.project.toList ∧ SEP ∉ c.env.toList ∧ SEP ∉ c.secret.toList ∧ ∀ o, c.owner = some o → SEP ∉ o.toList

theorem fields_sep {c : Ctx} (h : Wellformed c) : ∀ w ∈ fields c, SEP ∉ w := by
  obtain ⟨hp, he, hs, ho⟩ := h
  intro w hw
  simp only [fields, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hw
  rcases hw with ((hw | hw | hw | hw) | hw) | hw
  · subst hw; decide
  · subst hw; exact hp
  · subst hw; exact he
  · subst hw; exact hs
  · cases hc : c.owner with
    | none => simp [hc] at hw
    | some o =>
      simp only [hc, Option.map_some, Option.getD_some, List.mem_cons, List.not_mem_nil, or_false] at hw
      subst hw
      simp only [List.mem_append, not_or]
      exact ⟨by decide, ho o hc⟩
  · split at hw
    · simp at hw; subst hw; decide
    · simp at hw

/-- **The AAD names one context.** Two well-formed contexts with the same AAD are the same context. -/
theorem encodeAad_injective {c d : Ctx} (hc : Wellformed c) (hd : Wellformed d)
    (h : encodeAad c = encodeAad d) : c = d := by
  have := joinSep_injective (by simp [fields]) (by simp [fields]) (fields_sep hc) (fields_sep hd) h
  obtain ⟨p, e, s, o, sens⟩ := c
  obtain ⟨p', e', s', o', sens'⟩ := d
  simp only [fields, List.cons_append, List.cons.injEq, String.toList_inj] at this
  obtain ⟨-, rfl, rfl, rfl, rest⟩ := this
  cases o <;> cases o' <;> cases sens <;> cases sens' <;> simp_all [String.toList_inj]

/-- The wrap's AAD: the context's, then the KEK's identity (`|local|<id>|<version>`), the same for every key one KEK wraps. -/
def wrapAad (kekId : List Char) (c : Ctx) : List Char := encodeAad c ++ kekId

theorem wrapAad_injective {k : List Char} {c d : Ctx} (hc : Wellformed c) (hd : Wellformed d)
    (h : wrapAad k c = wrapAad k d) : c = d :=
  encodeAad_injective hc hd (List.append_cancel_right h)

/-- The value's own AAD: the ids alone, so that a version made sensitive keeps its ciphertext. -/
def valueAad (c : Ctx) : List Char := encodeAad { c with owner := none, sensitive := false }

/-! ## An ideal AEAD, and what the vault sealed

`dec k a c` opens ciphertext `c` under key `k` with AAD `a`. The vault's
history is two lists. Each `Value` is one value it encrypted (`encrypt`,
`seal`): a fresh DEK, and the value under it with its ids. Each `Wrap` is one
wrap of a DEK under the KEK, as a context (`keks.wrap`): one for each version
written, and one more for each version a rewrap makes of an old one's key
(`key.rewrap`: a version restored, a value made sensitive or, by an Owner, a
secret), so a DEK may have several. -/

variable {Key Cipher Plain : Type}

structure Value (Key Cipher Plain : Type) where
  /-- The secret's context; only its ids bind the value (`valueAad`). -/
  ids : Ctx
  dek : Key
  plain : Plain
  sealed : Cipher

structure Wrap (Key Cipher : Type) where
  ctx : Ctx
  dek : Key
  wrapped : Cipher

/-- What the database holds for a version: the wrapped DEK and the value's ciphertext, either of which an attacker may replace. -/
structure Row (Cipher : Type) where
  wrapped : Cipher
  sealed : Cipher

/--
The assumptions, stated rather than proved:

- `kekIntegrity`: integrity of ciphertexts for the KEK, which never leaves
  the vault or the KMS: whatever opens under it is a wrap the vault made, of
  its DEK, with its AAD.
- `dekIntegrity`: the same for each DEK the vault wrapped, against anyone who
  never held it: whatever opens under it is the value the vault encrypted
  under it, with its ids. (Whoever was handed the DEK read the value already.)
- `fresh`: each DEK encrypts one value (`freshDek`, 32 random bytes); a
  rewrap wraps a key again, and never encrypts another value under it.
- `correct`: what the vault wrapped and encrypted opens as it did.
- `wellformed`: the vault wraps and encrypts only contexts `checkContext` accepts.
-/
structure Assumptions (dec : Key → List Char → Cipher → Option Key) (decValue : Key → List Char → Cipher → Option Plain)
    (kek : Key) (kekId : List Char) (values : List (Value Key Cipher Plain)) (wraps : List (Wrap Key Cipher)) : Prop where
  kekIntegrity : ∀ a c m, dec kek a c = some m → ∃ w ∈ wraps, w.wrapped = c ∧ wrapAad kekId w.ctx = a ∧ w.dek = m
  dekIntegrity : ∀ w ∈ wraps, ∀ a c m, decValue w.dek a c = some m →
    ∃ v ∈ values, v.dek = w.dek ∧ v.sealed = c ∧ valueAad v.ids = a ∧ v.plain = m
  fresh : ∀ v ∈ values, ∀ v' ∈ values, v.dek = v'.dek → v = v'
  correctWrap : ∀ w ∈ wraps, dec kek (wrapAad kekId w.ctx) w.wrapped = some w.dek
  correctValue : ∀ v ∈ values, decValue v.dek (valueAad v.ids) v.sealed = some v.plain
  wellformedWraps : ∀ w ∈ wraps, Wellformed w.ctx
  wellformedValues : ∀ v ∈ values, Wellformed v.ids

/-- `open` and then `decrypt`: the vault unwraps the DEK as `ctx`, and the value opens under it with `ctx`'s ids. -/
def openRow (dec : Key → List Char → Cipher → Option Key) (decValue : Key → List Char → Cipher → Option Plain)
    (kek : Key) (kekId : List Char) (ctx : Ctx) (row : Row Cipher) : Option Plain :=
  (dec kek (wrapAad kekId ctx) row.wrapped).bind fun dek => decValue dek (valueAad ctx) row.sealed

/-- The ids alone: what `valueAad` binds. -/
def Ctx.ids (c : Ctx) : String × String × String := (c.project, c.env, c.secret)

theorem valueAad_injective {c d : Ctx} (hc : Wellformed c) (hd : Wellformed d) (h : valueAad c = valueAad d) :
    c.ids = d.ids := by
  have := encodeAad_injective (c := { c with owner := none, sensitive := false }) (d := { d with owner := none, sensitive := false })
    ⟨hc.1, hc.2.1, hc.2.2.1, by simp⟩ ⟨hd.1, hd.2.1, hd.2.2.1, by simp⟩ h
  simp only [Ctx.mk.injEq] at this
  simp [Ctx.ids, this]

variable {dec : Key → List Char → Cipher → Option Key} {decValue : Key → List Char → Cipher → Option Plain}
  {kek : Key} {kekId : List Char} {values : List (Value Key Cipher Plain)} {wraps : List (Wrap Key Cipher)}

/--
**A row opens only as it was sealed.** Whatever the database holds, if it
opens as `ctx`, the vault wrapped its key as exactly `ctx` (its project,
environment, key, owner and sensitivity), and what opens is the value the
vault encrypted under that key, for those ids.
-/
theorem open_only_as_sealed (A : Assumptions dec decValue kek kekId values wraps) {ctx : Ctx} (hctx : Wellformed ctx)
    {row : Row Cipher} {m : Plain} (h : openRow dec decValue kek kekId ctx row = some m) :
    ∃ w ∈ wraps, w.ctx = ctx ∧ w.wrapped = row.wrapped ∧
      ∃ v ∈ values, v.dek = w.dek ∧ v.plain = m ∧ v.sealed = row.sealed ∧ v.ids.ids = ctx.ids := by
  unfold openRow at h
  cases hw : dec kek (wrapAad kekId ctx) row.wrapped with
  | none => simp [hw] at h
  | some dek =>
    simp only [hw, Option.bind_some] at h
    obtain ⟨w, hwm, hww, hwa, hwd⟩ := A.kekIntegrity _ _ _ hw
    have hctxw : w.ctx = ctx := wrapAad_injective (A.wellformedWraps w hwm) hctx hwa
    subst hwd
    obtain ⟨v, hv, hdek, hsealed, haad, hplain⟩ := A.dekIntegrity w hwm _ _ _ h
    exact ⟨w, hwm, hctxw, hww, v, hv, hdek, hplain, hsealed, valueAad_injective (A.wellformedValues v hv) hctx haad⟩

/--
**What is not bound: the version.** Two versions of one key share its
context, so either one's row opens in the other's place: putting back an
older version's row reads its older value. That takes a write to the
database, which could as well point the key at its older version: the
rollback coffre accepts everywhere.
-/
theorem versions_not_bound (A : Assumptions dec decValue kek kekId values wraps) {w : Wrap Key Cipher}
    {v : Value Key Cipher Plain} (hw : w ∈ wraps) (hv : v ∈ values) (hdek : v.dek = w.dek)
    (hids : valueAad v.ids = valueAad w.ctx) {ctx : Ctx} (hsame : w.ctx = ctx) :
    openRow dec decValue kek kekId ctx ⟨w.wrapped, v.sealed⟩ = some v.plain := by
  have h₁ := A.correctWrap w hw
  have h₂ := A.correctValue v hv
  subst hsame
  simp [openRow, h₁, ← hdek, ← hids, h₂]

/-! ## The decision and the binding together

The vault opens a key with the context its decision read (`context` in
`vault.ts`): the ids, its environment's owner, hashed, and whether the
version is sensitive, all as the database says. An attacker who writes to
the database can change any of them. The decision then decides on what they
wrote, and the binding refuses to open what they lied about. -/

/-- The context a read opens with: its environment's owner as `ownerKey` hashes them, and the sensitivity the decision read. -/
def readCtx (ownerKey : String → String) (k : KeyRead) (secretId : String) : Ctx :=
  { project := k.secret.project, env := k.secret.env, secret := secretId,
    owner := ((k.envs.get? k.secret.env).bind (·.owner)).map ownerKey,
    sensitive := k.sensitive }

theorem allowed_not_sensitive {k : KeyRead} {vet : Code} (hperson : k.principal.startsWith "user:" = true)
    (hb : handsBack (k.purpose.getD "") k.keepsSensitive = true) (h : k.decide vet = none) : k.sensitive = false := by
  cases hs : k.sensitive
  · rfl
  · have := no_person_reads_sensitive k vet hperson hs hb
    rw [h] at this; cases this

theorem allowed_own_config {k : KeyRead} {vet : Code} (h : k.decide vet = none) :
    ∀ o, k.envs.get? k.secret.env = some o → o.owner = none ∨ o.owner = some k.principal := by
  intro o ho
  cases hown : o.owner with
  | none => exact Or.inl rfl
  | some v =>
    refine Or.inr ?_
    cases hv : decide (v = k.principal) with
    | true => simp at hv; rw [hv]
    | false =>
    have hne : v ≠ k.principal := by simpa using hv
    have hp : some k.principal ≠ o.owner := by rw [hown]; exact fun e => hne (Option.some.inj e).symm
    have := personal_owner_only (r := k.reader) (p := k.permission) (held := k.held) (need := none) (owns := false)
      ho (by simp [hown]) (Or.inl hp)
    unfold KeyRead.decide at h
    rw [this] at h
    simp [sensitiveRefusal, Option.orElse] at h

/--
**No person opens a sensitive value, nor another's personal config, whatever
the database says.** Take any read the vault allows a person, to be handed
back, with any row: the sensitivity, owner and place it was decided on as an
attacker may have rewritten them. If the row opens, the vault once wrapped
that value's key not sensitive, for that place, and, if in a personal config,
in the reader's own (as `ownerKey` names them).
-/
theorem no_person_opens_sensitive (A : Assumptions dec decValue kek kekId values wraps) (ownerKey : String → String)
    {k : KeyRead} {vet : Code} {secretId : String} (hctx : Wellformed (readCtx ownerKey k secretId))
    (hperson : k.principal.startsWith "user:" = true)
    (hb : handsBack (k.purpose.getD "") k.keepsSensitive = true) (hallowed : k.decide vet = none)
    {row : Row Cipher} {m : Plain} (hopen : openRow dec decValue kek kekId (readCtx ownerKey k secretId) row = some m) :
    ∃ v ∈ values, v.plain = m ∧ ∃ w ∈ wraps, w.dek = v.dek ∧ w.ctx.sensitive = false ∧
      (w.ctx.owner = none ∨ w.ctx.owner = some (ownerKey k.principal)) := by
  obtain ⟨w, hw, hctxw, -, v, hv, hdek, hplain, -, -⟩ := open_only_as_sealed A hctx hopen
  refine ⟨v, hv, hplain, w, hw, hdek.symm, ?_, ?_⟩
  · rw [hctxw]; exact allowed_not_sensitive hperson hb hallowed
  · rw [hctxw]
    simp only [readCtx]
    cases hrow : k.envs.get? k.secret.env with
    | none => simp
    | some o =>
      rcases allowed_own_config hallowed o hrow with h | h <;> simp [h]

/--
So a value whose key the vault only ever wrapped sensitive, as it wraps a
sensitive version's key again (`LOOSER` in `vault.ts`: only an Owner of its
project makes one a secret), never reaches a person, whatever the database
says.
-/
theorem sensitive_value_never_reaches_a_person (A : Assumptions dec decValue kek kekId values wraps)
    (ownerKey : String → String) {v : Value Key Cipher Plain} (hv : v ∈ values)
    (honly : ∀ w ∈ wraps, w.dek = v.dek → w.ctx.sensitive = true)
    {k : KeyRead} {vet : Code} {secretId : String} (hctx : Wellformed (readCtx ownerKey k secretId))
    (hperson : k.principal.startsWith "user:" = true)
    (hb : handsBack (k.purpose.getD "") k.keepsSensitive = true) (hallowed : k.decide vet = none)
    {row : Row Cipher} {m : Plain} (hopen : openRow dec decValue kek kekId (readCtx ownerKey k secretId) row = some m) :
    ∃ v' ∈ values, v'.plain = m ∧ v' ≠ v := by
  obtain ⟨v', hv', hplain, w, hw, hdek, hns, -⟩ := no_person_opens_sensitive A ownerKey hctx hperson hb hallowed hopen
  refine ⟨v', hv', hplain, fun heq => ?_⟩
  subst heq
  have := honly w hw hdek
  rw [hns] at this; cases this

end Coffre.Envelope
