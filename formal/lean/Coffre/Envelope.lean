import Std.Data.String.ToNat

/-!
# Envelope encryption: what a ciphertext is bound to

`packages/core/src/envelope.ts` and `context.ts`: each version's value is
sealed under a fresh data key (DEK) with AES-256-GCM, its AAD the secret's
ids; the vault wraps the DEK under the KEK, its AAD the whole context: the
ids, a personal config's owner (hashed), whether it is sensitive or plain,
and, from envelope format 2, the version's number, then the KEK's identity
(`kek/local.ts`).

We do not prove AES-GCM secure. We take the standard property of an AEAD,
integrity of ciphertexts, as an assumption about the world (`Assumptions`):
whoever does not hold a key makes no ciphertext that opens under it, except
those its holder made. Under it, and with the AAD encoding injective, which
we do prove (`encodeAad_injective`), a ciphertext that opens for a context
is one the vault made for exactly that context.

- `encodeAad_injective`: no two contexts encode to the same AAD.
- `open_only_as_sealed`: what opens as `ctx` is a value whose key the vault
  wrapped as exactly `ctx`, and the value encrypted under that key: no
  swap across projects, environments, keys, owners, sensitivity, plainness
  or versions.
- `versions_bound`: a row whose key the vault never wrapped as the version
  asked for does not open: an older version's row put back over the newer,
  or a wrap of before format 2, which names no version. A write to the
  database can still make the older version the current one, which then
  opens as itself: the rollback coffre accepts everywhere
  (docs/design/oidc.md, "Rollback is the accepted limit").
-/

namespace Coffre.Envelope

/-- `SecretContext`: the ids, a personal config's owner as `ownerKey` hashes them, whether it is sensitive or plain, and
the version's number, none in a wrap of before envelope format 2. -/
structure Ctx where
  project : String
  env : String
  secret : String
  owner : Option String
  sensitive : Bool
  plain : Bool
  version : Option Nat
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
    (if c.sensitive then ["sensitive".toList] else []) ++
    (if c.plain then ["plain".toList] else []) ++
    ((c.version.map fun n => ["version:".toList ++ (Nat.repr n).toList]).getD [])

/-- `encodeAad`: `coffre.aad.v1|<project>|<environment>|<secret>[|owner:<hash>][|sensitive][|plain][|version:<n>]`. -/
def encodeAad (c : Ctx) : List Char := joinSep (fields c)

/-- What `checkContext` ensures that injectivity needs: no field holds the separator (a UUID, a hex hash; a version's
decimal digits never do, which `fields_sep` proves). It needs none of `checkContext`'s other rules (never `plain` with
`sensitive`, a version from 1). -/
def Wellformed (c : Ctx) : Prop :=
  SEP ∉ c.project.toList ∧ SEP ∉ c.env.toList ∧ SEP ∉ c.secret.toList ∧ ∀ o, c.owner = some o → SEP ∉ o.toList

theorem fields_sep {c : Ctx} (h : Wellformed c) : ∀ w ∈ fields c, SEP ∉ w := by
  obtain ⟨hp, he, hs, ho⟩ := h
  intro w hw
  simp only [fields, List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at hw
  rcases hw with ((((hw | hw | hw | hw) | hw) | hw) | hw) | hw
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
  · split at hw
    · simp at hw; subst hw; decide
    · simp at hw
  · cases hc : c.version with
    | none => simp [hc] at hw
    | some n =>
      simp only [hc, Option.map_some, Option.getD_some, List.mem_cons, List.not_mem_nil, or_false] at hw
      subst hw
      simp only [List.mem_append, not_or]
      refine ⟨by decide, fun h => ?_⟩
      rw [Nat.toList_repr] at h
      exact absurd (Nat.isDigit_of_mem_toDigits (by decide) (by decide) h) (by decide)

/-- A version's decimal digits name one number. -/
theorem toDigits_ten_inj {n m : Nat} : Nat.toDigits 10 n = Nat.toDigits 10 m ↔ n = m :=
  ⟨fun h => Nat.repr_injective (by rw [Nat.repr_eq_ofList_toDigits, Nat.repr_eq_ofList_toDigits, h]), (· ▸ rfl)⟩

/-- **The AAD names one context.** Two well-formed contexts with the same AAD are the same context. -/
theorem encodeAad_injective {c d : Ctx} (hc : Wellformed c) (hd : Wellformed d)
    (h : encodeAad c = encodeAad d) : c = d := by
  have := joinSep_injective (by simp [fields]) (by simp [fields]) (fields_sep hc) (fields_sep hd) h
  obtain ⟨p, e, s, o, sens, pl, v⟩ := c
  obtain ⟨p', e', s', o', sens', pl', v'⟩ := d
  simp only [fields, List.cons_append, List.cons.injEq, String.toList_inj] at this
  obtain ⟨-, rfl, rfl, rfl, rest⟩ := this
  cases o <;> cases o' <;> cases sens <;> cases sens' <;> cases pl <;> cases pl' <;> cases v <;> cases v' <;>
    simp_all [String.toList_inj, toDigits_ten_inj]

/-- The wrap's AAD: the context's, then the KEK's identity (`|local|<id>|<version>`), the same for every key one KEK wraps. -/
def wrapAad (kekId : List Char) (c : Ctx) : List Char := encodeAad c ++ kekId

theorem wrapAad_injective {k : List Char} {c d : Ctx} (hc : Wellformed c) (hd : Wellformed d)
    (h : wrapAad k c = wrapAad k d) : c = d :=
  encodeAad_injective hc hd (List.append_cancel_right h)

/-- The value's own AAD: the ids alone, so that a version made sensitive keeps its ciphertext. -/
def valueAad (c : Ctx) : List Char := encodeAad { c with owner := none, sensitive := false, plain := false, version := none }

/-! ## An ideal AEAD, and what was sealed

`dec k a c` opens ciphertext `c` under key `k` with AAD `a`. The history is
two lists. Each `Value` is one value the app encrypted (`encrypt`, in
`packages/server/src/api/keys.ts`): a fresh DEK, and the value under it with
its ids. Each `Wrap` is one wrap of a DEK under the KEK, as a context, which
only the vault makes (`keks.wrap`): one for each version
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
  never held it: whatever opens under it is the value the app encrypted
  under it, with its ids. (Whoever was handed the DEK read the value already.)
  The app holds every DEK it encrypts with, so this assumes it too: that it
  encrypts under a key only the value it was made for.
- `fresh`: each DEK encrypts one value (`freshDek`, 32 random bytes); a
  rewrap wraps a key again, and never encrypts another value under it.
- `correct`: what was wrapped and encrypted opens as it was.
- `wellformed`: only contexts `checkContext` accepts are wrapped and encrypted.
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
  have := encodeAad_injective (c := { c with owner := none, sensitive := false, plain := false, version := none })
    (d := { d with owner := none, sensitive := false, plain := false, version := none })
    ⟨hc.1, hc.2.1, hc.2.2.1, by simp⟩ ⟨hd.1, hd.2.1, hd.2.2.1, by simp⟩ h
  simp only [Ctx.mk.injEq] at this
  simp [Ctx.ids, this]

variable {dec : Key → List Char → Cipher → Option Key} {decValue : Key → List Char → Cipher → Option Plain}
  {kek : Key} {kekId : List Char} {values : List (Value Key Cipher Plain)} {wraps : List (Wrap Key Cipher)}

/--
**A row opens only as it was sealed.** Whatever the database holds, if it
opens as `ctx`, the vault wrapped its key as exactly `ctx` (its project,
environment, key, owner, sensitivity, plainness and version), and what opens is the value the
app encrypted under that key, for those ids.
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
**The version is bound.** A row opens as version `n` of a key only if the
vault wrapped its data key as version `n` of that key: an older version's
row put back over the newer one does not open, nor does a wrap of before
envelope format 2, which names no version, as every `open` of 0.16 names
one. A write to the database can still make the older version the current
one, which opens as itself: the rollback coffre accepts everywhere.
-/
theorem versions_bound (A : Assumptions dec decValue kek kekId values wraps) {ctx : Ctx} (hctx : Wellformed ctx)
    {row : Row Cipher} (hother : ∀ w ∈ wraps, w.wrapped = row.wrapped → w.ctx.version ≠ ctx.version) :
    openRow dec decValue kek kekId ctx row = none := by
  cases h : openRow dec decValue kek kekId ctx row with
  | none => rfl
  | some m =>
    obtain ⟨w, hw, hctxw, hww, -⟩ := open_only_as_sealed A hctx h
    exact absurd (congrArg Ctx.version hctxw) (hother w hw hww)

end Coffre.Envelope
