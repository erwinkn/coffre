#!/usr/bin/env bash
# Model-checks coffre's protocols, formal/*.tla, with TLC (docs/formal.md).
# Every scenario in formal/ must hold. Then each one runs again with one of
# the code's protections turned off, or two that each cover for the other,
# and must fail on the invariant they keep: so a model cannot quietly stop
# seeing a race it once caught. Each such counterexample is printed, a step
# a line. A scenario's configuration names the module of its scenarios on
# its second line (`\* model MCCredentials`); MC.tla's, Coffre.tla's, by default.
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

# Each scenario, a protection the code has, or two joined by `+` that
# cover for each other, and the invariant TLC must find broken without it.
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
  "Members ReaderRowLocked NothingReleasedAfterRevocation"
  "References EndRecheckUnderHead NothingReleasedThroughEndedReference"
  "Referencing SourceRecheckInReference ReferencedSourcesStayLive"
  "Referencing ArchiveRefusedWhileRead ReferencedSourcesStayLive"
  "Referencing ReferenceRereadInDeletion EveryReferenceBreakable"
  "Owners LastOwnerCheckUnderHead OwnerStays"
  "Regenerating InheritedRecheckUnderHead RegeneratesReplaceWhatTheyListed"
  "Exchanging SpentTokenInsertedWithCredential SingleUse"
  "Exchanging BindingRecheckUnderHead NoExchangeAfterUnbind"
  "Exchanging MemberRecheckInExchange ExchangedAtCurrentGeneration"
  "Exchanging RateCountUnderHead RateHeld"
  "Revoking CredentialFenceUnderHead NoReleaseAfterEnd"
  "Revoking CredentialFenceUnlocked NoReleaseAfterEnd"
  "Revoking RevokeIssuedCredentials NoReleaseAfterEnd"
  "Revoking KeptAnswerChecked NoReadOnStaleAnswer"
  "Revoking RevokeIssuedCredentials+BindingCheckedAtUse UnboundStayUnusable"
  "Issuing IssuerFence SensitiveOnlyFromOwners"
  "Issuing SealIssuerFence SensitiveOnlyFromOwners"
  "Issuing ServiceRecheckInIssue TokensAtCurrentGeneration"
  "Issuing SealCompareAndSet SealedOnce"
  "Issuing IssuerGenerationKept+IssuerStandsUnderHead IssuedAsAuthenticated"
  "Bulk ReaderRowLocked+BulkRecountUnderHead CapHolds"
  "Bulk CountsTheRequest CapHolds"
  "Bulk PerPrincipal CapHolds"
  "Bulk StampedWhenCounted CapHolds"
  "WorkloadReplay KeyCheckedAgainstRow CopyIsUseless"
  "WorkloadReplay RequestDigestChecked ForwardedIsSigned"
  "WorkloadReplay OnlySignedHeadersForwarded ForwardedIsSigned"
  "WorkloadReplay NonceEpochs ProofOnce"
  "WorkloadEnding LiveCheckBeforeCache FreezeBound"
  "WorkloadEnding TunnelRecheckSeesFreezes FreezeBound"
  "WorkloadEnding GenerationInStatement RevokeBound"
  "WorkloadEnding RenewCappedAtNotAfter NotAfter"
  "WorkloadFreezing LiveCheckBeforeCache FreezeBound"
  "WorkloadNarrow AncestorsChecked NarrowSubset"
  "WorkloadNarrow AncestorExpiryChecked NarrowSubset"
  "WorkloadNarrow TargetResolvedBeforeConstraints+EncodedSegmentsRefused NarrowSubset"
  "WorkloadNarrow EncodedSegmentsRefused NarrowSubset"
  "WorkloadNarrow ChildOpsRefused NarrowSubset"
  "WorkloadCapacity CountUnderHead Capacity"
  "WorkloadCapacity RenewOnlyLive Capacity"
  "WorkloadCapacity SupersedeCheckedAtExchange Superseded"
  "WorkloadCapacity SupersedeCheckedAtRenewal Superseded"
  "WorkloadCapacity SupersedeCheckInUpdate Superseded"
  "WorkloadMinting ScopeFromCode MinterBound"
  "WorkloadMinting SensitiveNeedsOwnerMinter MinterBound"
  "WorkloadMinting MinterFence MinterBound"
  "WorkloadMinting MintRefusesEnrollment+MintedByNotSelf MinterBound"
  "WorkloadMinting MintRefusesChildren MinterBound"
  "WorkloadDeploys RootsOnly NoFalseContention"
  "WorkloadDeploys RefusesWhenFull NoFalseContention"
  "WorkloadDeploys BusyIsNoSignal NoFalseContention"
  "WorkloadReenroll ExcessIntegral TripwireFires"
  "WorkloadThief ChurnCounted TripwireFires"
  "WorkloadLifting TripFencedOnLift LiftHolds"
  "WorkloadLifting EntryReadFirst LiftHolds"
  "WorkloadCopy ReplicasFull CopyCaught"
  "WorkloadReads CheckWhereHeld NoLaundering"
  "WorkloadReads ReadsByID NoLaundering"
  "WorkloadReads RefusesUnreadableSources NoLaundering"
  "Tampering WalkChecksAppMacs GreenIsReal"
  "Tampering CheckpointChecksVault SignsNoForgedVault"
  "Tampering CheckpointLinksWalk SignsNoForgedVault"
  "Tampering SeenRecheckUnderHead StaysUnsignedOnceFound"
  "Tampering Scrubs EditFoundByNextScrub"
  "Tampering ReadinessChecksHeld GreenIsReal"
  "Tampering AnchorCas AnchorNeverBack"
  "Overtaking AnchorCas FoundEditStaysRed"
  "Walking AnchorCas AnchorNeverBack"
  "AppKeyRotation StateUnderHead OneRotate"
  "AppKeyRotation StateUnderHead NoLaunderingAfterRotate"
  "AppKeyRotation RetiredCheck OldKeyWritesNothingAfter"
  "AppKeyRotation RetiredCheck RotationComplete"
  "AppKeyRotation WalkCutoff NothingForgedAccepted"
  "Tunnel Watchdog+DeadlineCountsAsNo EndsWithinBound"
  "TunnelShort DeadlineCountsAsNo StandingStaysOpen"
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
# Scenarios of several minutes run only by their own runner's --long (scripts/formal-shards.sh).
for cfg in "$root"/formal/*.cfg; do
  case "$(basename "$cfg" .cfg)" in ShardsCombined) continue ;; esac
  scenarios+=("$(basename "$cfg" .cfg)")
done

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
  # The scenario with the protections off, holding to the one invariant they keep.
  cp "$work/$scenario.cfg" "$work/without.cfg"
  missing=""
  for off in ${protection//+/ }; do
    sed -i -e "s/^\(    $off\) = TRUE/\1 = FALSE/" "$work/without.cfg"
    grep -q "^    $off = FALSE" "$work/without.cfg" || missing="$off"
  done
  [ -z "$missing" ] || { echo "FAIL  $scenario has no $missing"; failed=1; continue; }
  sed -i -e '/^INVARIANTS/,/^CHECK_DEADLOCK/{/^    /d}' -e "s/^INVARIANTS/INVARIANTS\n    $invariant/" "$work/without.cfg"
  started=$SECONDS
  tlc without.cfg
  if grep -q "^Error: Invariant $invariant is violated" "$work/out.txt"; then
    echo "ok    $scenario without ${protection//+/ and } breaks $invariant ($((SECONDS - started))s):"
    node "$root/scripts/formal-trace.mjs" <"$work/out.txt" | tail -n +2 | sed 's/^/        /'
  else
    echo "FAIL  $scenario without ${protection//+/ and } should break $invariant"
    cat "$work/out.txt"
    failed=1
  fi
done

exit $failed
