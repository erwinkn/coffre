#!/usr/bin/env bash
# Model-checks coffre's locking protocol, formal/Coffre.tla, with TLC
# (docs/formal.md). Every scenario in formal/ must hold. Then each one runs
# again with one of the code's protections turned off, and must fail on the
# invariant that protection keeps: so the model cannot quietly stop seeing a
# race it once caught. Each such counterexample is printed, a step a line.
#
#   scripts/formal.sh                 every scenario
#   scripts/formal.sh Deletion        one, and its runs without a protection
#   scripts/formal.sh --workers 4     TLC's worker threads (default 2)
set -euo pipefail

# TLA+ tools 1.7.4 (2024-08-05), the latest stable release. Not 1.8.0, a
# prerelease rebuilt nightly under the same tag.
TLA_VERSION=1.7.4
TLA_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
TLA_URL="https://github.com/tlaplus/tlaplus/releases/download/v$TLA_VERSION/tla2tools.jar"

# Each scenario, a protection the code has, and the invariant TLC must find
# broken without it.
REMOVALS=(
  "Deletion GrantRereadInDeletion EveryGrantRevocable"
  "Deletion PlaceReadUnderHead EveryGrantRevocable"
  "Deletion ArchivedRecheckInDeletion DeletedOnlyWhenArchived"
  "Deletion PatchRecheckUnderHead TombstonesKeepTheirSlug"
  "Deletion PatchRecheckUnderHead TombstonesStayArchived"
  "Reading KeyPlaceRecheckUnderHead NothingReleasedAfterDeletion"
  "Reading KeyPlaceRecheckUnderHead DeletedStaysUnreachable"
  "Reading EnvCreateRecheckUnderHead DeletedStaysUnreachable"
  "Reading SecretPatchRecheckUnderHead DeletedStaysUnreachable"
  "Members MemberRecheckInSignin CredentialsAtCurrentGeneration"
  "Locks SortedMemberLocks NoWaitCycle"
)

root="$(cd "$(dirname "$0")/.." && pwd)"
workers=2
only=""
while [ $# -gt 0 ]; do
  case "$1" in
    --workers) workers="$2"; shift 2 ;;
    *) only="$1"; shift ;;
  esac
done

jar="${XDG_CACHE_HOME:-$HOME/.cache}/coffre/tla2tools-$TLA_VERSION.jar"
if ! echo "$TLA_SHA256  $jar" | sha256sum -c --status 2>/dev/null; then
  mkdir -p "$(dirname "$jar")"
  curl -fsSL --retry 3 -o "$jar.part" "$TLA_URL"
  echo "$TLA_SHA256  $jar.part" | sha256sum -c --quiet
  mv "$jar.part" "$jar"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$root"/formal/*.tla "$root"/formal/*.cfg "$work"/

tlc() {
  (cd "$work" && java -XX:+UseParallelGC -Xmx1g -cp "$jar" tlc2.TLC -nowarning -difftrace \
    -workers "$workers" -metadir "$work/states" -config "$1" MC.tla) >"$work/out.txt" 2>&1 || true
}

failed=0
scenarios=()
for cfg in "$root"/formal/*.cfg; do scenarios+=("$(basename "$cfg" .cfg)"); done

for scenario in "${scenarios[@]}"; do
  [ -n "$only" ] && [ "$only" != "$scenario" ] && continue
  started=$SECONDS
  tlc "$scenario.cfg"
  if grep -q '^Model checking completed. No error has been found.' "$work/out.txt"; then
    states="$(grep -o '[0-9,]* distinct states found' "$work/out.txt" | tail -1)"
    echo "ok    $scenario holds: $states, $((SECONDS - started))s"
  else
    echo "FAIL  $scenario"
    cat "$work/out.txt"
    node "$root/scripts/formal-trace.mjs" <"$work/out.txt" || true
    failed=1
  fi
done

for removal in "${REMOVALS[@]}"; do
  read -r scenario protection invariant <<<"$removal"
  [ -n "$only" ] && [ "$only" != "$scenario" ] && continue
  # The scenario with the protection off, holding to the one invariant it keeps.
  sed -e "s/^\(    $protection\) = TRUE/\1 = FALSE/" \
      -e '/^INVARIANTS/,/^CHECK_DEADLOCK/{/^    /d}' \
      -e "s/^INVARIANTS/INVARIANTS\n    $invariant/" \
      "$work/$scenario.cfg" >"$work/without.cfg"
  grep -q "^    $protection = FALSE" "$work/without.cfg" || { echo "FAIL  $scenario has no $protection"; failed=1; continue; }
  started=$SECONDS
  tlc without.cfg
  if grep -q "^Error: Invariant $invariant is violated" "$work/out.txt"; then
    echo "ok    $scenario without $protection breaks $invariant ($((SECONDS - started))s):"
    node "$root/scripts/formal-trace.mjs" <"$work/out.txt" | tail -n +2 | sed 's/^/        /'
  else
    echo "FAIL  $scenario without $protection should break $invariant"
    cat "$work/out.txt"
    failed=1
  fi
done

exit $failed
