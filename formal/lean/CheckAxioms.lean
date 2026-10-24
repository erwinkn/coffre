import Lean
import Coffre

/-!
Fails unless every declaration of the `Coffre` modules rests on Lean's own
axioms alone: no `sorry` (`sorryAx`), no `axiom` of ours, no `native_decide`
(which adds an axiom trusting the compiler). Lean reports what each
elaborated declaration depends on, so nothing written a way a text search
would miss gets through. `scripts/formal-lean.sh` runs it:
`lake env lean CheckAxioms.lean`.
-/

open Lean Elab Command

/-- Lean's standard axioms, which every proof in core may use. -/
def allowed : List Name := [``propext, ``Classical.choice, ``Quot.sound]

#eval show CommandElabM Unit from do
  let env ← getEnv
  let ours (n : Name) : Bool := match env.getModuleIdxFor? n with
    | some idx => (`Coffre).isPrefixOf env.header.moduleNames[idx.toNat]!
    | none => false
  let names := env.constants.toList.filterMap fun (n, _) => if ours n then some n else none
  let mut bad : Array (Name × Name) := #[]
  for n in names do
    for a in ← liftCoreM (collectAxioms n) do
      if !allowed.contains a then bad := bad.push (n, a)
  if bad.isEmpty then
    logInfo m!"{names.length} declarations of formal/lean rest on Lean's axioms alone"
  else
    throwError m!"formal/lean proves nothing it assumes outside Lean's axioms:\n{bad.toList.map fun (n, a) => m!"{n} uses {a}"}"
