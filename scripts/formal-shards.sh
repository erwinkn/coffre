#!/usr/bin/env bash
# Model-checks 0.15's hot path, formal/Shards*.tla, with TLC (formal/Shards.md):
# the shards and the changes that fence them, their lanes of the audit log,
# the token exchange, and the cutover from 0.14. As scripts/formal.sh, whose
# TLC, checksum and output it shares: every scenario must hold, then each
# runs again with one of the design's protections turned off, or two that
# each cover for the other, and must fail on the invariant they keep.
#
#   scripts/formal-shards.sh                  every scenario
#   scripts/formal-shards.sh ShardsRevoking   one, and its runs without a protection
#   scripts/formal-shards.sh --workers 4      TLC's worker threads (default 2)
#   scripts/formal-shards.sh --long           the long scenarios too (LONG)
set -euo pipefail

# TLA+ tools 1.7.4 (2024-08-05), as scripts/formal.sh.
TLA_VERSION=1.7.4
TLA_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
TLA_URL="https://github.com/tlaplus/tlaplus/releases/download/v$TLA_VERSION/tla2tools.jar"

# Each scenario, a protection the design has, or two joined by `+` that
# cover for each other, and the invariant TLC must find broken without it.
REMOVALS=(
  "ShardsRevoking FloorChecked NothingReleasedAfterRevocation"
  "ShardsRevoking NowaitProbe NothingReleasedAfterRevocation"
  "ShardsRevoking ProbeKeepsFence NothingReleasedAfterRevocation"
  "ShardsRevoking UnfenceProbes NothingReleasedAfterRevocation"
  "ShardsRollback UnfenceProbes NothingReleasedAfterRevocation"
  "ShardsRollback ProbeKeepsFence NothingReleasedAfterRevocation"
  "ShardsRevoking OneSnapshot NothingReleasedAfterRevocation"
  "ShardsRevoking FencedWritesOnly NothingReleasedAfterRevocation"
  "ShardsRevoking FenceBeforeCommit UsesOrderedAgainstChanges"
  "ShardsRestore EpochChecked NothingReleasedAfterRevocation"
  "ShardsRestore EpochChecked UsesOrderedAgainstChanges"
  "ShardsFanout AllAcked NothingReleasedAfterRevocation"
  "ShardsRestarting FencePersisted NothingReleasedAfterRevocation"
  "ShardsRestarting StorageArbiter NothingReleasedAfterRevocation"
  "ShardsRestarting DurableBeforeReply EveryReplyAudited"
  "ShardsCombined FencePersisted NothingReleasedAfterRevocation"
  "ShardsCombined ProbeKeepsFence NothingReleasedAfterRevocation"
  "ShardsLanes HeadCAS LanesHold"
  "ShardsLanes RewindChecked RewindStops"
  "ShardsLanes FlushGated RewindStops"
  "ShardsLanesLost AdoptOnlyOwnPrefix LanesHold"
  "ShardsLanesLost CasComparesHash LanesHold"
  "ShardsCredentials CredentialRevokeFenced NoUseAfterCredentialRevoked"
  "ShardsCredentialsLive UnknownCredentialRereads IssuedUsable"
  "ShardsExchange JtiSpentInShard SingleUseExchange"
  "ShardsExchange JtiAtHome SingleUseExchange"
  "ShardsCutover OldLoginRevoked NothingAfterClose"
  "ShardsCutover AppLoginRevoked NothingAfterClose"
  "ShardsCutover CutoverInOneTransaction NothingAfterClose"
  "ShardsCutover CutoverInOneTransaction EveryReleaseAudited"
  "ShardsCutover CutoverInOneTransaction+FencedWritesOnly RevocationCarried"
  "ShardsContinue TriggerInstalledWithRevision NothingReleasedAfterRevocation"
  "ShardsContinue FencedWritesOnly NothingReleasedAfterRevocation"
  "ShardsContinue ChangeTakesHead LanesHold"
  "ShardsContinue ChangeTakesHead+FencedWritesOnly RevocationCarried"
)

# Scenarios of several minutes, checked with --long or by name.
LONG=(ShardsCombined)

root="$(cd "$(dirname "$0")/.." && pwd)"
workers=2
only=""
long=0
while [ $# -gt 0 ]; do
  case "$1" in
    --workers) workers="$2"; shift 2 ;;
    --long) long=1; shift ;;
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
cp "$root"/formal/Shards*.tla "$root"/formal/Shards*.cfg "$work"/

# The module of a configuration's scenarios.
model() { sed -n '2s/^\\\* model \([A-Za-z]*\)$/\1/p' "$work/$1"; }

tlc() {
  local module
  module="$(model "$1")"
  # TLC names its states directory by the second it starts: two runs in one
  # second would share it, and the second fail.
  rm -rf "$work/states"
  (cd "$work" && java -XX:+UseParallelGC -Xmx1g -cp "$jar" tlc2.TLC -nowarning -difftrace \
    -workers "$workers" -metadir "$work/states" -config "$1" "${module:-MC}.tla") >"$work/out.txt" 2>&1 || true
}

failed=0
scenarios=()
for cfg in "$root"/formal/Shards*.cfg; do scenarios+=("$(basename "$cfg" .cfg)"); done

for scenario in "${scenarios[@]}"; do
  [ -n "$only" ] && [ "$only" != "$scenario" ] && continue
  [ -z "$only" ] && [ "$long" = 0 ] && [[ " ${LONG[*]} " == *" $scenario "* ]] && { echo "skip  $scenario (--long)"; continue; }
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
  # The scenario with the protections off, holding to the one invariant they keep.
  cp "$work/$scenario.cfg" "$work/without.cfg"
  missing=""
  for off in ${protection//+/ }; do
    sed -i -e "s/^\(    $off\) = TRUE/\1 = FALSE/" "$work/without.cfg"
    grep -q "^    $off = FALSE" "$work/without.cfg" || missing="$off"
  done
  [ -z "$missing" ] || { echo "FAIL  $scenario has no $missing"; failed=1; continue; }
  if sed -n '/^PROPERTIES/,$p' "$work/without.cfg" | grep -q "^    $invariant$"; then
    # A property: checked alone, without the scenario's invariants.
    sed -i -e '/^INVARIANTS/,/^CHECK_DEADLOCK/{/^INVARIANTS/d;/^    /d}' -e '/^PROPERTIES/,${/^    /d}' \
      -e "s/^PROPERTIES/PROPERTIES\n    $invariant/" "$work/without.cfg"
    broken="^Error: Temporal properties were violated"
  else
    sed -i -e '/^INVARIANTS/,/^CHECK_DEADLOCK/{/^    /d}' -e "s/^INVARIANTS/INVARIANTS\n    $invariant/" "$work/without.cfg"
    broken="^Error: Invariant $invariant is violated"
  fi
  started=$SECONDS
  tlc without.cfg
  if grep -q "$broken" "$work/out.txt"; then
    echo "ok    $scenario without ${protection//+/ and } breaks $invariant ($((SECONDS - started))s):"
    sed 's/^Error: The following behavior constitutes a counter-example:/Error: The behavior up to this point is:/' "$work/out.txt" |
      node "$root/scripts/formal-trace.mjs" | tail -n +2 | sed 's/^/        /'
  else
    echo "FAIL  $scenario without ${protection//+/ and } should break $invariant"
    cat "$work/out.txt"
    failed=1
  fi
done

exit $failed
