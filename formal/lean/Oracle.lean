import Lean.Data.Json
import Coffre

/-!
# The oracle

Reads one JSON case a line on stdin, as `scripts/formal-lean.ts` writes them,
answers each with the model, one JSON line on stdout. A case names the
function it asks about (`op`) and its arguments in the TypeScript's own
shapes, so the driver passes them as the code takes them.
-/

open Lean Coffre

abbrev Parse := Except String

/-! A field the code reads as optional may be absent or null; one it needs is an error when absent, as the code would
fail on it, so a case the code could not take never passes for one the model answers. -/

/-- An optional field: null when absent. -/
def field (j : Json) (k : String) : Json := (j.getObjVal? k).toOption.getD Json.null

/-- A field the code needs: present and not null. -/
def req (j : Json) (k : String) : Parse Json :=
  match j.getObjVal? k with
  | .ok v => if v.isNull then throw s!"{k} is null" else pure v
  | .error _ => throw s!"{k} is missing"

/-- A field the code reads null or not, but never absent (an absent `environmentId` is neither kind of grant). -/
def present (j : Json) (k : String) : Parse Json :=
  match j.getObjVal? k with
  | .ok v => pure v
  | .error _ => throw s!"{k} is missing"

def str (j : Json) : Parse String := j.getStr?

def optStr (j : Json) : Parse (Option String) :=
  if j.isNull then pure none else some <$> j.getStr?

/-- An optional flag: false when absent, as `=== true` reads it. -/
def flag (j : Json) : Parse Bool := if j.isNull then pure false else j.getBool?

def list (j : Json) : Parse (List Json) := (·.toList) <$> j.getArr?

def entries (j : Json) : Parse (List (String × Json)) :=
  match j with
  | .obj kvs => pure (kvs.toList.map fun ⟨k, v⟩ => (k, v))
  | _ => throw "expected an object"

def permission (j : Json) : Parse Permission := do
  let s ← str j
  match Permission.ofName? s with
  | some p => pure p
  | none => throw s!"no permission {s}"

def permissions (j : Json) : Parse (List Permission) := do (← list j).mapM permission

def roleDef (j : Json) : Parse RoleDef := do
  pure ⟨← permissions (← req j "permissions"), ← permissions (← req j "protected")⟩

def columns (j : Json) : Parse RoleDef := do
  pure ⟨← permissions (← req j "normal"), ← permissions (← req j "protected")⟩

def table {α} (f : Json → Parse α) (j : Json) : Parse (Table α) := do
  (← entries j).mapM fun (k, v) => do pure (k, ← f v)

/-- A holder's policy: `DEFAULT_POLICY` when it has none, as `holder.policy ?? DEFAULT_POLICY` reads it. -/
def policy (j : Json) : Parse Policy := do
  if j.isNull then return defaultPolicy
  let protectedIn ← table (fun v => do
    (← list v).mapM fun e => do pure (← str (← req e "environmentId"), ← optStr (field e "slug"))) (← req j "protectedIn")
  pure ⟨← table roleDef (← req j "roles"), ← table roleDef (← req j "instanceRoles"),
    ← (← list (← req j "protected")).mapM str, protectedIn⟩

def filter (j : Json) : Parse Filter :=
  if j == Json.str "all" then pure .all
  else match j.getObjVal? "only", j.getObjVal? "except" with
    | .ok xs, _ => do pure (.only (← (← list xs).mapM str))
    | _, .ok xs => do pure (.except (← (← list xs).mapM str))
    | _, _ => throw "a filter is all, only or except"

def scope (j : Json) : Parse Scope := do pure ⟨← filter (← req j "projects"), ← filter (← req j "environments")⟩

def place (j : Json) : Parse Place := do
  let project ← str (← req j "projectId")
  match ← optStr (field j "environmentId") with
  | none => pure ⟨project, none⟩
  | some env => pure ⟨project, some (env, ← optStr (field j "environmentSlug"))⟩

def grant (j : Json) : Parse Grant := do
  pure ⟨⟨← optStr (← present j "projectId"), ← optStr (← present j "environmentId")⟩, ← str (← req j "role")⟩

def scopeGrant (j : Json) : Parse ScopeGrant := do
  let perms := field j "permissions"
  let sens := field j "sensitive"
  pure { project := ← optStr (← present j "projectId"), env := ← optStr (← present j "environmentId"), role := ← str (← req j "role"),
         cols := ← if perms.isNull then pure none else some <$> columns perms,
         sensitive := ← if sens.isNull then pure none else some <$> sens.getBool? }

def holdings (j : Json) : Parse Holdings := do
  let cred := field j "credentialScope"
  pure { role := ← str (← req j "role"), scope := ← scope (← req j "scope"), grants := ← (← list (← req j "grants")).mapM grant,
         cred := ← if cred.isNull then pure none else some <$> (← list cred).mapM scopeGrant,
         policy := ← policy (field j "policy"), service := ← flag (field j "service") }

def optScope (j : Json) : Parse (Option Scope) := if j.isNull then pure none else some <$> scope j

def optDef (j : Json) : Parse (Option RoleDef) := if j.isNull then pure none else some <$> roleDef j

def account (j : Json) : Parse ServiceAccount := do
  let grants ← (← list (← req j "grants")).mapM fun g => do pure (← str (← req g "role"), ← place (← req g "place"))
  pure ⟨grants, ← optStr (field j "admittedBy")⟩

def status (j : Json) : Parse Status := do
  match ← str j with
  | "active" => pure .active
  | "removed" => pure .removed
  | "unknown" => pure .unknown
  | "tampered" => pure .tampered
  | s => throw s!"no status {s}"

def reader (j : Json) : Parse Reader := do
  pure ⟨← status (← req j "status"), ← holdings (← req j "live"), ← holdings (← req j "all")⟩

def secretPlace (j : Json) : Parse SecretPlace := do pure ⟨← str (← req j "projectId"), ← str (← req j "environmentId")⟩

def envRows (j : Json) : Parse (Table EnvRow) := do
  (← list j).mapM fun pair => do
    let id ← str (← req pair "id")
    let e ← req pair "row"
    pure (id, ⟨← str (← req e "projectId"), ← str (← req e "slug"), ← optStr (field e "owner"),
      ← optStr (← present e "parentId"), ← (← req e "deleted").getBool?⟩)

def code (c : Code) : Json := match c with | some s => Json.str s | none => Json.null

def jsonPerms (ps : List Permission) : Json := Json.arr (ps.map (Json.str ·.name)).toArray

def jsonGrant (g : ScopeGrant) : Json :=
  Json.mkObj ([("projectId", match g.project with | some p => Json.str p | none => Json.null), ("environmentId", match g.env with | some e => Json.str e | none => Json.null),
    ("role", Json.str g.role)] ++
    (match g.cols with
      | some c => [("permissions", Json.mkObj [("normal", jsonPerms c.normal), ("protected", jsonPerms c.prot)])]
      | none => []) ++
    (match g.sensitive with | some b => [("sensitive", Json.bool b)] | none => []))

def action (j : Json) : Parse Action := do
  match ← str j with
  | "secret.read" => pure .read
  | "key.wrap" => pure .wrap
  | "key.rewrap" => pure .rewrap
  | s => throw s!"no action {s}"

def aadCtx (j : Json) : Parse Envelope.Ctx := do
  pure ⟨← str (field j "projectId"), ← str (field j "environmentId"), ← str (field j "secretId"),
    ← optStr (field j "owner"), ← flag (field j "sensitive")⟩

/-- `verifyEntries`' control, each entry's hash and MAC checked by the driver, which holds the keys. -/
def verifyCase (j : Json) : Parse Json := do
  let es ← (← list (← req j "entries")).mapM fun e => do
    pure (← (field e "seq").getNat?, ← str (field e "prev"), ← str (field e "hash"), ← flag (field e "hashOk"), ← flag (field e "macOk"))
  let nth (i : Nat) := es.getD i (0, "", "", false, false)
  let H (p : String) (i : Nat) (_ : Unit) : String :=
    let (_, prev, hash, ok, _) := nth i
    if p == prev && ok then hash else "≠" ++ hash
  let entries : List (Audit.Entry Nat String Unit) := (List.range es.length).map fun i =>
    let (seq, prev, hash, _, _) := nth i
    ⟨seq, i, prev, (), hash⟩
  let macOk (e : Audit.Entry Nat String Unit) : Bool := (nth e.fields).2.2.2.2
  match Audit.verify H macOk entries (← (field j "startSeq").getNat?) (← str (field j "startPrev")) with
  | .ok head next => pure (Json.mkObj [("ok", true), ("head", Json.str head), ("nextSeq", Json.num next)])
  | .fail seq => pure (Json.mkObj [("ok", false), ("failedAtSeq", Json.num seq)])

def answer (j : Json) : Parse Json := do
  let op ← str (field j "op")
  match op with
  | "allows" => pure (Json.bool (allows (← holdings (field j "holder")) (← permission (field j "permission")) (← place (field j "place"))))
  | "heldColumns" =>
    let c := heldColumns (← holdings (field j "holder")) (← place (field j "place"))
    pure (Json.mkObj [("normal", jsonPerms c.normal), ("protected", jsonPerms c.prot)])
  | "issuedGrant" =>
    let g := field j "grant"
    let held := field j "held"
    pure (jsonGrant (issuedGrant (← optStr (← present g "projectId")) (← optStr (← present g "environmentId")) (← str (← req g "role"))
      (← policy (field j "policy")) (← if held.isNull then pure none else some <$> columns held)))
  | "readsSensitive" => pure (Json.bool (readsSensitive (← holdings (field j "holder")) (← str (field j "projectId"))))
  | "ownsProject" => pure (Json.bool (ownsProject (← holdings (field j "holder")) (← str (field j "projectId"))))
  | "mayManageAccess" => pure (Json.bool (mayManageAccess (← holdings (field j "holder")) (← place (field j "place"))))
  | "runsInstance" => pure (Json.bool (runsInstance (← holdings (field j "holder"))))
  | "readsWholeLog" => pure (Json.bool (readsWholeLog (← holdings (field j "holder"))))
  | "makesProjects" => pure (Json.bool (makesProjects (← holdings (field j "holder"))))
  | "withinCredential" => pure (Json.bool (withinCredential (← holdings (field j "holder")) (← permission (field j "permission")) (← place (field j "place"))))
  | "givesService" =>
    pure (Json.bool (givesService (← holdings (field j "holder")) (← optScope (field j "setting")) (← str (field j "role"))
      (← place (field j "place")) (← optDef (field j "kept"))))
  | "managesService" =>
    pure (Json.bool (managesService (← holdings (field j "holder")) (← optScope (field j "setting")) (← str (field j "actor"))
      (← account (field j "account"))))
  | "issuesCredential" =>
    let sc ← (← list (← req j "scope")).mapM fun g => do pure (← str (← req g "role"), ← place (← req g "place"), ← optDef (field g "kept"))
    pure (Json.bool (issuesCredential (← holdings (field j "holder")) (← optScope (field j "setting")) (← str (field j "actor"))
      (← account (field j "account")) sc))
  | "handsBack" => pure (Json.bool (handsBack (← str (field j "purpose")) (← flag (field j "keepsSensitive"))))
  | "keyRefusals" =>
    let r ← reader (field j "reader")
    let principal ← str (field j "principal")
    let p ← permission (field j "permission")
    let secrets ← (← list (← req j "secrets")).mapM secretPlace
    let held ← (← list (← req j "at")).mapM secretPlace
    if held.length < secrets.length then throw "a place for each secret"
    let envs ← envRows (← req j "environments")
    let needs ← (← list (← req j "needs")).mapM fun n => if n.isNull then pure none else some <$> permissions n
    let owns ← (if (field j "owns").isNull then pure [] else list (field j "owns")) >>= (·.mapM flag)
    let codes := (List.range secrets.length).map fun i =>
      keyRefusal r principal p (secrets.getD i default) (held.getD i default) envs (needs.getD i none) (owns.getD i false)
    pure (Json.arr (codes.map code).toArray)
  | "sensitiveRefusals" =>
    let r ← reader (field j "reader")
    let a ← action (field j "action")
    let principal ← str (field j "principal")
    let purpose ← optStr (field j "purpose")
    let keeps ← flag (field j "keepsSensitive")
    let codes ← (← list (← req j "codes")).mapM optStr
    let secrets ← (← list (← req j "secrets")).mapM fun s => do pure (← str (field s "projectId"), ← flag (field s "sensitive"))
    let out := (List.range secrets.length).map fun i =>
      let (project, sensitive) := secrets.getD i ("", false)
      sensitiveRefusal (codes.getD i none) r a principal purpose keeps project sensitive
    pure (Json.arr (out.map code).toArray)
  | "encodeAad" => pure (Json.str (String.ofList (Envelope.encodeAad (← aadCtx (field j "ctx")))))
  | "verifyEntries" => verifyCase j
  | _ => throw s!"no op {op}"

partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  let line := String.ofList (line.toList.filter (fun c => c != (Char.ofNat 10) && c != (Char.ofNat 13)))
  if !line.isEmpty then
    match Json.parse line >>= answer with
    | .ok j => stdout.putStrLn j.compress
    | .error e => stdout.putStrLn (Json.mkObj [("error", Json.str e)]).compress
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
