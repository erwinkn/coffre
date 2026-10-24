/-!
# Who may do what

An executable model of `packages/core/src/access.ts`: one definition per
function there, under the same name, deciding the same way. The oracle
(`Oracle.lean`) runs these on the cases `scripts/formal-lean.ts` generates
and compares every answer with the TypeScript's, so a drift between the
two fails `pnpm formal:lean`. `AccessProofs.lean` proves what they promise.

Everything is `Bool`, as the code is, so that the oracle runs it as it is
proved. Names and ids are strings, as the code has them; an environment's
id is never the empty string (`Wellformed`), the one assumption the proofs
make about them.
-/

namespace Coffre

inductive Permission where
  | read | use | write | archive | auditRead | envManage | grantManage | projectManage
  deriving DecidableEq, Repr, Inhabited

namespace Permission

/-- `PERMISSIONS`, in catalogue order: `heldColumns` lists them in it. -/
def all : List Permission :=
  [.read, .use, .write, .archive, .auditRead, .envManage, .grantManage, .projectManage]

theorem mem_all (p : Permission) : p ∈ all := by cases p <;> simp [all]

/-- `PROJECT_ONLY_PERMISSIONS`. -/
def projectOnly : Permission → Bool
  | .envManage | .grantManage | .projectManage => true
  | _ => false

def name : Permission → String
  | .read => "secret.read" | .use => "secret.use" | .write => "secret.write"
  | .archive => "secret.archive" | .auditRead => "audit.read"
  | .envManage => "environment.manage" | .grantManage => "grant.manage"
  | .projectManage => "project.manage"

def ofName? (s : String) : Option Permission := all.find? (·.name == s)

end Permission

/-- `RoleDefinition`'s two columns: where nothing is protected, and in a protected environment. -/
structure RoleDef where
  normal : List Permission
  prot : List Permission
  deriving Repr, Inhabited, DecidableEq

/-- A record keyed by name, as a JSON object is: the first entry of a name decides. -/
abbrev Table (α : Type) := List (String × α)

def Table.get? {α} (t : Table α) (k : String) : Option α := (t.find? (·.1 == k)).map (·.2)

/-- `ROLES`, as coffre ships them: what a credential kept before 0.10 holds. -/
def builtinRoles : Table RoleDef :=
  [ ("viewer", ⟨[.read, .use], [.use]⟩),
    ("contributor", ⟨[.use, .write], [.use, .write]⟩),
    ("developer", ⟨[.read, .use, .write], [.use, .write]⟩),
    ("maintainer", ⟨[.read, .use, .write, .archive, .envManage], [.use, .write, .archive]⟩),
    ("access-manager", ⟨[.grantManage], []⟩),
    ("auditor", ⟨[.auditRead], [.auditRead]⟩),
    ("owner", ⟨Permission.all, Permission.all.filter (!·.projectOnly)⟩) ]

/-- `Filter`: every one, only those listed, or all but those listed. -/
inductive Filter where
  | all
  | only (xs : List String)
  | except (xs : List String)
  deriving Repr, Inhabited, DecidableEq

def Filter.isAll : Filter → Bool
  | .all => true
  | _ => false

/-- `admits`: a value not read (none) is in no filter that lists. -/
def admits : Filter → Option String → Bool
  | .all, _ => true
  | _, none => false
  | .only xs, some v => xs.contains v
  | .except xs, some v => !xs.contains v

structure Scope where
  projects : Filter
  environments : Filter
  deriving Repr, Inhabited, DecidableEq

def EVERYWHERE : Scope := ⟨.all, .all⟩

def unscoped (s : Scope) : Bool := s.projects.isAll && s.environments.isAll

/-- `Place`: a project, or one of its environments by id, with its slug, which may be unread. -/
structure Place where
  project : String
  env : Option (String × Option String)
  deriving Repr, Inhabited, DecidableEq

def Place.envId (x : Place) : Option String := x.env.map (·.1)

def inScope (s : Scope) (x : Place) : Bool :=
  admits s.projects (some x.project) &&
    match x.env with
    | none => s.environments.isAll
    | some (_, slug) => admits s.environments slug

/-- `GrantPlace`: a project, or one of its environments; a project of none covers nothing. -/
structure GrantPlace where
  project : Option String
  env : Option String
  deriving Repr, Inhabited, DecidableEq

def covers (g : GrantPlace) (x : Place) : Bool :=
  match g.project, g.env with
  | none, _ => false
  | some p, none => p == x.project
  | some p, some e => p == x.project && x.envId == some e

structure Grant where
  place : GrantPlace
  role : String
  deriving Repr, Inhabited, DecidableEq

/-- `ScopeGrant`'s `reads`: the keys there a workload is handed back, by ID, or every one. -/
inductive Reads where
  | all
  | keys (ids : List String)
  deriving Repr, Inhabited, DecidableEq

/-- Whether a grant's `reads` lists a key: none lists nothing. -/
def Reads.lists : Option Reads → String → Bool
  | some .all, _ => true
  | some (.keys ids), k => ids.contains k
  | none, _ => false

/-- `ScopeGrant`: a credential's grant, with the columns it kept when issued, or a built-in role's name alone. -/
structure ScopeGrant where
  project : Option String
  env : Option String
  role : String
  cols : Option RoleDef
  sensitive : Option Bool
  reads : Option Reads := none
  deriving Repr, Inhabited, DecidableEq

def ScopeGrant.place (g : ScopeGrant) : GrantPlace := ⟨g.project, g.env⟩

/-- `scopeDefinition`: what it kept, which no edit of the policy changes. -/
def scopeDef (g : ScopeGrant) : RoleDef :=
  match g.cols with
  | some c => c
  | none => (builtinRoles.get? g.role).getD ⟨[], []⟩

/-- `Policy`: its roles, its instance roles, and the environments it protects (`"*"`, every one). -/
structure Policy where
  roles : Table RoleDef
  instanceRoles : Table RoleDef
  protectedEnvs : List String
  protectedIn : Table (List (String × Option String))
  deriving Repr, Inhabited

def EVERY_ENVIRONMENT : String := "*"

/-- `INSTANCE_ROLES`, as coffre ships them. -/
def builtinInstanceRoles : Table RoleDef :=
  [ ("member", ⟨[], []⟩),
    ("auditor", ⟨[.auditRead], [.auditRead]⟩),
    ("developer", ⟨[.read, .use, .write], [.use, .write]⟩),
    ("admin", ⟨[.auditRead, .envManage, .grantManage, .projectManage], [.auditRead]⟩),
    ("owner", ⟨Permission.all, Permission.all.filter (!·.projectOnly)⟩) ]

/-- `DEFAULT_POLICY`: what a holder with no policy holds under. -/
def defaultPolicy : Policy := ⟨builtinRoles, builtinInstanceRoles, [], []⟩

def protects (pol : Policy) (envId : String) : Bool :=
  pol.protectedEnvs.contains envId || pol.protectedEnvs.contains EVERY_ENVIRONMENT

structure Holdings where
  role : String
  scope : Scope
  grants : List Grant
  cred : Option (List ScopeGrant)
  policy : Policy
  service : Bool
  /-- `kind`, whether it is `workload`. -/
  workload : Bool := false
  deriving Repr, Inhabited

def Holdings.withProtected (h : Holdings) (ps : List String) : Holdings :=
  { h with policy := { h.policy with protectedEnvs := ps } }

/-- `guarded`: a person, in an environment the policy protects, holds a role's protected column. -/
def guarded (h : Holdings) (x : Place) : Bool :=
  !h.service && match x.env with
    | none => false
    | some (id, _) => protects h.policy id

def holds (d : Option RoleDef) (p : Permission) (x : Place) (h : Holdings) : Bool :=
  match d with
  | none => false
  | some d =>
    if p.projectOnly then d.normal.contains p
    else (if guarded h x then d.prot else d.normal).contains p

/-- `scopeHolds`: the credential's scope covers the place with a grant that held the permission there. -/
def scopeHolds (h : Holdings) (p : Permission) (x : Place) : Bool :=
  (h.cred.getD []).any fun g => covers g.place x && holds (some (scopeDef g)) p x h

/-- What the instance role and the grants give, before any credential caps it. -/
def held (h : Holdings) (p : Permission) (x : Place) : Bool :=
  (inScope h.scope x && holds (h.policy.instanceRoles.get? h.role) p x h) ||
    h.grants.any fun g => covers g.place x && holds (h.policy.roles.get? g.role) p x h

/-- `allows`. -/
def allows (h : Holdings) (p : Permission) (x : Place) : Bool :=
  (h.cred.isNone || scopeHolds h p x) && held h p x

def withinCredential (h : Holdings) (p : Permission) (x : Place) : Bool :=
  h.cred.isNone || scopeHolds h p x

def within (col : List Permission) (cap : Option (List Permission)) : List Permission :=
  match cap with
  | none => col
  | some c => col.filter (c.contains ·)

/-- `issuedGrant`: the role's columns now, each no more than its issuer holds there (`heldColumns`). -/
def issuedGrant (project : Option String) (env : Option String) (role : String) (pol : Policy)
    (cap : Option RoleDef) : ScopeGrant :=
  let d := pol.roles.get? role
  { project, env, role, sensitive := none,
    cols := some ⟨within ((d.map (·.normal)).getD []) (cap.map (·.normal)),
                  within ((d.map (·.prot)).getD []) (cap.map (·.prot))⟩ }

/-- `heldColumns`'s place for the protected column: an environment of the project no grant names. -/
def anyOf (x : Place) : Place := if x.env.isSome then x else ⟨x.project, some ("", none)⟩

/-- `heldColumns`. -/
def heldColumns (h : Holdings) (x : Place) : RoleDef :=
  ⟨Permission.all.filter (allows (h.withProtected []) · x),
   Permission.all.filter (allows (h.withProtected [EVERY_ENVIRONMENT]) · (anyOf x))⟩

def readsSensitive (h : Holdings) (project : String) : Bool :=
  h.service && (h.cred.getD []).any fun g => g.sensitive == some true && g.project == some project

/--
`useOnly`: a workload's value that no grant of its scope covering where the
value is held lists, by key ID. Nobody else's.
-/
def useOnly (h : Holdings) (project env secret : String) : Bool :=
  h.workload && !(h.cred.getD []).any fun g => covers g.place ⟨project, some (env, none)⟩ && Reads.lists g.reads secret

def ownsProject (h : Holdings) (project : String) : Bool :=
  h.cred.isNone && !h.service &&
    ((h.role == "owner" && inScope h.scope ⟨project, none⟩) ||
      h.grants.any fun g => g.role == "owner" && covers g.place ⟨project, none⟩)

def ownsInstance (role : String) (s : Scope) : Bool := role == "owner" && unscoped s

def protectedWithin (pol : Policy) (x : Place) : List Place :=
  match x.env with
  | some _ => []
  | none => ((pol.protectedIn.get? x.project).getD []).map fun (id, slug) => ⟨x.project, some (id, slug)⟩

def administers (role : String) : Bool := role == "admin" || role == "owner"

def mayManageAccess (h : Holdings) (x : Place) : Bool := allows h .grantManage x

def runsInstance (h : Holdings) : Bool := h.cred.isNone && administers h.role && unscoped h.scope

/-- `givesService`. `setting` is none for a service account, which sets none up. -/
def givesService (h : Holdings) (setting : Option Scope) (role : String) (x : Place)
    (kept : Option RoleDef) : Bool :=
  mayManageAccess h x ||
    match kept <|> h.policy.roles.get? role, setting with
    | none, _ => false
    | some _, none => false
    | some d, some s =>
      !d.normal.isEmpty && h.cred.isNone && inScope s x &&
        d.normal.all (allows h · x) &&
        (protectedWithin h.policy x).all fun t =>
          (d.normal.filter (!·.projectOnly)).all (allows h · t)

structure ServiceAccount where
  grants : List (String × Place)
  admittedBy : Option String
  deriving Repr, Inhabited

def NOTHING (pol : Policy) : Holdings := ⟨"member", EVERYWHERE, [], none, pol, false, false⟩

def managesService (h : Holdings) (setting : Option Scope) (actor : String) (a : ServiceAccount) : Bool :=
  runsInstance h ||
    if a.grants.isEmpty then setting.isSome && a.admittedBy == some actor
    else a.grants.all fun (role, x) => givesService h setting role x none

def Place.asGrant (x : Place) : GrantPlace := ⟨some x.project, x.envId⟩

/-- `issuesCredential`. -/
def issuesCredential (h : Holdings) (setting : Option Scope) (actor : String) (a : ServiceAccount)
    (scope : List (String × Place × Option RoleDef)) : Bool :=
  managesService h setting actor a &&
    let heldBy : Holdings :=
      { NOTHING h.policy with service := true, grants := a.grants.map fun (role, x) => ⟨x.asGrant, role⟩ }
    scope.all fun (role, x, kept) =>
      givesService h setting role x kept &&
        (((kept <|> h.policy.roles.get? role).map fun d => d.normal.all (allows heldBy · x)).getD false)

def readsWholeLog (h : Holdings) : Bool :=
  h.cred.isNone && unscoped h.scope &&
    match h.policy.instanceRoles.get? h.role with
    | none => false
    | some d => d.normal.contains .auditRead && d.prot.contains .auditRead

def makesProjects (h : Holdings) : Bool :=
  h.cred.isNone && administers h.role && h.scope.environments.isAll &&
    match h.scope.projects with
    | .all | .except _ => true
    | .only _ => false

/-- `handsBack` (`@coffre/core/vault`): every purpose but the proxy's use and a copy that keeps values sensitive. -/
def handsBack (purpose : String) (keepsSensitive : Bool) : Bool :=
  purpose != "use" && !(purpose == "copy" && keepsSensitive)

end Coffre
