/-!
# The audit chain: tamper-evidence and the bounded walk

`packages/core/src/audit/chain.ts`: each entry's hash covers the one before,
its fields and its MAC; `verifyEntries` checks a run of entries from a
starting point. The app walks the chain from where it last verified
(`walkChain` in `packages/server/src/db/audit.ts`), a batch at a time, each
starting where the last one stopped (R25), and the vault signs checkpoints:
a sequence number and the hash of the entry there.

We do not prove SHA-256 or Ed25519 secure. We assume, as an idealisation of
collision resistance, that the entry hash is injective and never the genesis
hash (`Injective`), and of unforgeability, that a checkpoint that verifies
is one the vault signed, over a prefix of the log as it was (`Signed`).

- `verify_append`: verifying `xs ++ ys` is verifying `xs`, then `ys` from
  where `xs` stopped. So a walk cut into batches, or resumed from a point it
  reached before, decides as one walk from the start would.
- `head_determines_chain`: two chains from genesis with the same head are
  the same chain.
- `checkpoint_pins_prefix`: a valid checkpoint pins the log's prefix: every
  stored log that verifies from genesis through the checkpoint is the true
  log up to there, byte for byte.
- `walk_from_checkpoint_extends`: what a walk from a valid checkpoint
  accepts is an extension of the true log: its prefix, then entries that
  chain on from it, each with a MAC that verifies.

What is not covered: freshness. Rolling back the log and all its
checkpoints together needs no key (chain.ts says so, and so do we).
-/

namespace Coffre.Audit

variable {Fields Hash Mac : Type} [DecidableEq Hash]

/-- `StoredEntry`: its fields (which carry `seq` too), the hash before it, its MAC and its hash. -/
structure Entry (Fields Hash Mac : Type) where
  seq : Nat
  fields : Fields
  prev : Hash
  mac : Mac
  hash : Hash

/-- `verifyEntries`' verdict: where it stopped (the head and the next number), or the entry it failed at. -/
inductive Verdict (Hash : Type) where
  | ok (head : Hash) (next : Nat)
  | fail (seq : Nat)

/--
`verifyEntries`: numbers without a gap from `seq`, each entry linked to the
hash before, its hash its own (`H`), and its MAC verified (`macOk`, which
holds the authors' keys; an author checked for its place only, `chainOnly`,
passes it).
-/
def verify (H : Hash → Fields → Mac → Hash) (macOk : Entry Fields Hash Mac → Bool) :
    List (Entry Fields Hash Mac) → Nat → Hash → Verdict Hash
  | [], seq, prev => .ok prev seq
  | e :: es, seq, prev =>
    if e.seq = seq ∧ e.prev = prev ∧ H e.prev e.fields e.mac = e.hash ∧ macOk e = true then
      verify H macOk es (e.seq + 1) e.hash
    else .fail e.seq

variable {H : Hash → Fields → Mac → Hash} {macOk : Entry Fields Hash Mac → Bool}

/-- **The walk composes.** Verifying `xs ++ ys` is verifying `xs`, then `ys` from where it stopped. -/
theorem verify_append (xs ys : List (Entry Fields Hash Mac)) (seq : Nat) (prev : Hash) :
    verify H macOk (xs ++ ys) seq prev =
      match verify H macOk xs seq prev with
      | .ok head next => verify H macOk ys next head
      | .fail seq => .fail seq := by
  induction xs generalizing seq prev with
  | nil => rfl
  | cons e es ih =>
    simp only [List.cons_append, verify]
    split
    · exact ih _ _
    · rfl

/-- The chain's head over `es` from `prev`, as each entry's hash recomputed. -/
def headOf (H : Hash → Fields → Mac → Hash) : List (Entry Fields Hash Mac) → Hash → Hash
  | [], prev => prev
  | e :: es, _ => headOf H es e.hash

/-- A chain that verifies stops at its last entry's hash. -/
theorem verify_ok_head {es : List (Entry Fields Hash Mac)} {seq prev head next}
    (h : verify H macOk es seq prev = .ok head next) : headOf H es prev = head ∧ next = seq + es.length := by
  induction es generalizing seq prev with
  | nil => simp [verify] at h; obtain ⟨rfl, rfl⟩ := h; simp [headOf]
  | cons e es ih =>
    simp only [verify] at h
    split at h
    · next hc =>
      obtain ⟨hs, -, -, -⟩ := hc
      obtain ⟨h1, h2⟩ := ih h
      refine ⟨h1, ?_⟩
      simp [h2, hs]; omega
    · cases h

/-- What an entry is, as stored: two entries with the same key are the same row. -/
def Entry.key (e : Entry Fields Hash Mac) : Nat × Fields × Hash × Mac × Hash := (e.seq, e.fields, e.prev, e.mac, e.hash)

/--
The idealisation of collision resistance: the entry hash is injective, and
never the genesis hash (`GENESIS_HASH`, 32 zero bytes, which no one finds a
SHA-256 preimage of).
-/
structure Injective (H : Hash → Fields → Mac → Hash) (genesis : Hash) : Prop where
  inj : ∀ p f m p' f' m', H p f m = H p' f' m' → p = p' ∧ f = f' ∧ m = m'
  notGenesis : ∀ p f m, H p f m ≠ genesis

theorem verify_cons_ok {e : Entry Fields Hash Mac} {es seq prev head next}
    (h : verify H macOk (e :: es) seq prev = .ok head next) :
    e.seq = seq ∧ e.prev = prev ∧ H e.prev e.fields e.mac = e.hash ∧ macOk e = true ∧
      verify H macOk es (e.seq + 1) e.hash = .ok head next := by
  simp only [verify] at h
  split at h
  · next hc => exact ⟨hc.1, hc.2.1, hc.2.2.1, hc.2.2.2, h⟩
  · cases h

/-- Every entry of a run that verifies is its own hash, with a MAC that verifies. -/
theorem verify_ok_entries {es : List (Entry Fields Hash Mac)} {seq prev head next}
    (h : verify H macOk es seq prev = .ok head next) :
    ∀ e ∈ es, H e.prev e.fields e.mac = e.hash ∧ macOk e = true := by
  induction es generalizing seq prev with
  | nil => simp
  | cons e es ih =>
    obtain ⟨-, -, hh, hm, hrest⟩ := verify_cons_ok h
    intro x hx
    simp only [List.mem_cons] at hx
    rcases hx with rfl | hx
    · exact ⟨hh, hm⟩
    · exact ih hrest x hx

/-- Induction from the end of a list, which `head_determines_chain` walks back along. -/
theorem snoc_induction {α : Type} {motive : List α → Prop} (nil : motive [])
    (snoc : ∀ xs x, motive xs → motive (xs ++ [x])) (l : List α) : motive l := by
  have : ∀ r : List α, motive r.reverse := by
    intro r
    induction r with
    | nil => exact nil
    | cons x r ih => simpa using snoc r.reverse x ih
  simpa using this l.reverse

/-- The last entry of a run that verifies, and the run before it. -/
theorem verify_snoc {es : List (Entry Fields Hash Mac)} {e seq prev head next}
    (h : verify H macOk (es ++ [e]) seq prev = .ok head next) :
    ∃ head' next', verify H macOk es seq prev = .ok head' next' ∧ e.seq = next' ∧ e.prev = head' ∧
      e.hash = head ∧ H e.prev e.fields e.mac = e.hash := by
  rw [verify_append] at h
  split at h
  · next head' next' hv =>
    obtain ⟨hs, hp, hh, _, hrest⟩ := verify_cons_ok h
    simp [verify] at hrest
    exact ⟨head', next', hv, hs, hp, hrest.1, hh⟩
  · cases h

/--
**The head names the chain.** Two runs that verify from genesis to the same
head are the same entries: a log rewritten anywhere before its head has
another head.
-/
theorem head_determines_chain {genesis : Hash} (hI : Injective H genesis) :
    ∀ (xs ys : List (Entry Fields Hash Mac)) {head next next'},
      verify H macOk xs 0 genesis = .ok head next → verify H macOk ys 0 genesis = .ok head next' →
      xs.map Entry.key = ys.map Entry.key := by
  intro xs
  induction xs using snoc_induction with
  | nil =>
    intro ys head next next' hx hy
    simp [verify] at hx
    obtain ⟨rfl, -⟩ := hx
    cases ys using snoc_induction with
    | nil => rfl
    | snoc ys y _ =>
      obtain ⟨_, _, _, _, _, hyh, hyH⟩ := verify_snoc hy
      exact absurd (hyh ▸ hyH) (hI.notGenesis _ _ _)
  | snoc xs x ih =>
    intro ys head next next' hx hy
    obtain ⟨hx', nx', hxv, hxs, hxp, hxh, hxH⟩ := verify_snoc hx
    cases ys using snoc_induction with
    | nil =>
      simp [verify] at hy
      obtain ⟨rfl, -⟩ := hy
      exact absurd (hxh ▸ hxH) (hI.notGenesis _ _ _)
    | snoc ys y _ =>
      obtain ⟨hy', ny', hyv, hys, hyp, hyh, hyH⟩ := verify_snoc hy
      have hH : H x.prev x.fields x.mac = H y.prev y.fields y.mac := by rw [hxH, hyH, hxh, hyh]
      obtain ⟨hp, hf, hm⟩ := hI.inj _ _ _ _ _ _ hH
      have hrest := ih ys hxv (by rw [← hxp, hp, hyp]; exact hyv)
      have hseq : x.seq = y.seq := by
        rw [hxs, hys, (verify_ok_head hxv).2, (verify_ok_head hyv).2]
        have := congrArg List.length hrest
        simp only [List.length_map] at this
        rw [this]
      simp only [List.map_append, List.map_cons, List.map_nil, hrest, Entry.key, hseq, hf, hp, hm, hxh, hyh]

/-! ## Checkpoints -/

/-- A checkpoint: the entry it names, and that entry's hash. -/
structure Checkpoint (Hash : Type) where
  seq : Nat
  hash : Hash

/--
The idealisation of unforgeability: a checkpoint whose signature verifies is
one the vault signed, and the vault signs only a prefix of the true log: the
entries as their authors wrote them, which the chain commits to, not whatever
the table holds when it signs (the vault checks the stretch since its last
checkpoint before it signs the next, and its scrub finds a row edited behind
one). Its first `seq + 1` entries, `pre`, are the true log's, and verify from
genesis to the checkpoint's hash.
-/
def Signed (H : Hash → Fields → Mac → Hash) (macOk : Entry Fields Hash Mac → Bool) (genesis : Hash)
    (trueLog : List (Entry Fields Hash Mac)) (c : Checkpoint Hash) (pre : List (Entry Fields Hash Mac)) : Prop :=
  pre <+: trueLog ∧ pre.length = c.seq + 1 ∧ verify H macOk pre 0 genesis = .ok c.hash (c.seq + 1)

/--
**A checkpoint pins the prefix.** Any stored log whose first entries verify
from genesis to a valid checkpoint's hash holds the true log's entries there,
every field and MAC.
-/
theorem checkpoint_pins_prefix {genesis : Hash} (hI : Injective H genesis) {trueLog pre stored : List (Entry Fields Hash Mac)}
    {c : Checkpoint Hash} (hc : Signed H macOk genesis trueLog c pre) {next}
    (hs : verify H macOk stored 0 genesis = .ok c.hash next) : stored.map Entry.key = pre.map Entry.key :=
  head_determines_chain hI stored pre hs hc.2.2

/--
**A walk from a checkpoint accepts only an extension of the true log.**
What `walkChain` reads after a valid checkpoint and accepts, with the true
log up to the checkpoint before it, is a chain that verifies from genesis:
the true log's prefix, then entries that each chain on from the one before,
are their own hash, and pass the walk's MAC check (`macOk`: the app's walk
checks its own entries' MACs and the vault's by place only, the vault's the
other way round, each author checking its own over the same stretch). A walk
that stops and goes on from where it reached (`verify_append`) accepts the
same.
-/
theorem walk_from_checkpoint_extends {genesis : Hash} {trueLog pre rest : List (Entry Fields Hash Mac)}
    {c : Checkpoint Hash} (hc : Signed H macOk genesis trueLog c pre) {head next}
    (hw : verify H macOk rest (c.seq + 1) c.hash = .ok head next) :
    verify H macOk (pre ++ rest) 0 genesis = .ok head next ∧ pre <+: trueLog ∧
      ∀ e ∈ rest, H e.prev e.fields e.mac = e.hash ∧ macOk e = true := by
  refine ⟨?_, hc.1, verify_ok_entries hw⟩
  rw [verify_append, hc.2.2]
  exact hw

/--
**Resuming is sound.** A walk that verified `done` from genesis and later
goes on from where it stopped over `rest` has verified `done ++ rest`, the
entries it read, from genesis, and, under `Injective`, nothing else reaches
the head it stops at. A row edited behind where it resumes is not one it
reads again: the vault's scrub's to find, as R25 means.
-/
theorem resume_sound {genesis : Hash} (hI : Injective H genesis) {done rest : List (Entry Fields Hash Mac)}
    {at₁ : Hash} {n₁ head next} (h₁ : verify H macOk done 0 genesis = .ok at₁ n₁)
    (h₂ : verify H macOk rest n₁ at₁ = .ok head next) :
    verify H macOk (done ++ rest) 0 genesis = .ok head next ∧
      ∀ other : List (Entry Fields Hash Mac), ∀ {n}, verify H macOk other 0 genesis = .ok head n →
        other.map Entry.key = (done ++ rest).map Entry.key := by
  have hall : verify H macOk (done ++ rest) 0 genesis = .ok head next := by rw [verify_append, h₁]; exact h₂
  exact ⟨hall, fun other _ ho => head_determines_chain hI other _ ho hall⟩

end Coffre.Audit
