#!/usr/bin/env bash
# Model-checks coffre's protocols, formal/*.tla, with TLC (docs/formal.md).
# Every scenario in formal/ must hold. Then each one runs again with one of
# the code's protections turned off, or two that each cover for the other,
# and must fail on the invariant they keep: so a model cannot quietly stop
# seeing a race it once caught. Each such counterexample is printed, a step
# a line. A scenario's configuration names the module of its scenarios on
# its second line (`\* model MCCredentials`); MC.tla's, Coffre.tla's, by default.
#
# A protection is a BOOLEAN constant, turned from TRUE to FALSE; or, written
# `Name=Value` (no spaces), a constant set to that value, as `Unsealed={"credential"}`
# leaves one input of HotPathOne unsealed. The invariant may be a temporal
# property the scenario lists under PROPERTIES: then it is checked alone, and
# TLC must report it violated. Last, EXPECTED: what a design leaves open, which
# TLC must find broken with every protection on (the window it documents).
#
#   scripts/formal.sh                 every scenario
#   scripts/formal.sh Deletion        one, and its runs without a protection
#   scripts/formal.sh Deletion Locks  several
#   scripts/formal.sh --shard rest    one of CI's shards (shard_of): tampering,
#                                     large, rest, hotpath, hotpath-bulk,
#                                     hotpath-skew or seal
#   scripts/formal.sh --workers 4     TLC's worker threads (default 2)
#   scripts/formal.sh --heap 4g       TLC's JVM heap (default 1g)
#   scripts/formal.sh --list          what would run, not running TLC
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
  "Sharing ReaderRowLocked NothingReleasedAfterRevocation"
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
  "Proxying CredentialFenceUnderHead NoReleaseAfterEnd"
  "Proxying CredentialFenceUnlocked NoReleaseAfterEnd"
  "Revoking RevokeIssuedCredentials+BindingCheckedAtUse UnboundStayUnusable"
  "Issuing IssuerFence SensitiveOnlyFromOwners"
  "Issuing SealIssuerFence SensitiveOnlyFromOwners"
  "Issuing ServiceRecheckInIssue TokensAtCurrentGeneration"
  "Issuing SealCompareAndSet SealedOnce"
  "Issuing IssuerGenerationKept+IssuerStandsUnderHead IssuedAsAuthenticated"
  "Bulk BulkRecountUnderHead CapHolds"
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
  "Overtaking RefusalRecheckedUnderHead StaysUnsignedOnceFound"
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
  # 0.15's hot path (HotPathOne.tla; W208, W211; the plan's PRs 3 to 5): one call per use, every input sealed.
  "HotPathOne UseLocks TotalOrder"
  "HotPathOne UseLocks NothingAllowedAfterAnswer"
  "HotPathOne StatementSnapshot TotalOrder"
  "HotPathOne StatementSnapshot ReplayAgrees"
  "HotPathOne StatementSnapshot NothingAllowedAfterAnswer"
  "HotPathOne UseNumberUnderLock TotalOrder"
  "HotPathOne UseNumberUnderLock CheckpointsHold"
  "HotPathOne ChangeLocks TotalOrder"
  "HotPathOne ChangeLocks NothingAllowedAfterAnswer"
  "HotPathOne ChangeNumberUnderLock TotalOrder"
  "HotPathOne LockToCommit TotalOrder"
  "HotPathOne LockToCommit NothingAllowedAfterAnswer"
  "HotPathOne CommitBeforeAnswer NothingAllowedAfterAnswer"
  "HotPathOne ReleaseAfterCommit DurableBeforeRelease"
  "HotPathOne SyncCommit DurableBeforeRelease"
  "HotPathOne SyncCommit NothingAllowedAfterAnswer"
  "HotPathOne CheckpointLocks CheckpointsHold"
  "HotPathOneCovers CoverChecksChanges RepeatsAreTheirCover"
  "HotPathOneCovers CoverChecksAllInputs RepeatsAreTheirCover"
  "HotPathOneCovers UseLocks RepeatsAreTheirCover"
  "HotPathOneCovers CacheChecked RepeatsAreTheirCover"
  "HotPathOneSeals Unsealed={\"member\"} ReplaySound"
  "HotPathOneSeals Unsealed={\"credential\"} ReplaySound"
  "HotPathOneSeals Unsealed={\"secret\"} ReplaySound"
  "HotPathOneSeals Unsealed={\"environment\"} ReplaySound"
  "HotPathOneSeals StaleFirst TamperVisible"
  "HotPathOneSeals CacheChecked ReplaySound"
  "HotPathOneRestore CacheSameChange ReplaySound"
  "HotPathOneCAS ChangeCAS EachChangeFlips"
  "HotPathOneRestoreCovers CoverExists RepeatsAreTheirCover"
  "HotPathOneRestoreCovers CoverExists DurableBeforeRelease"
  "HotPathOneClock FloorChecked CheckpointsHold"
  "HotPathOneClock DeadlineChecked NoLateWork"
  "HotPathOneClock WorkerHonoursDeadline ReleaseByDeadline"
  "HotPathOneBulk PrincipalLocks BulkCapHolds"
  "HotPathOneBulk PrincipalLocks BulkReplayAgrees"
  "HotPathOneBulk RefreshOnUse BulkCapHolds"
  "HotPathOneBulk CoverFresh BulkCapHolds"
  "HotPathOneBulk DeadlineSlack BulkCapHolds"
  "HotPathOneBulkSlack Slack BulkCapHolds"
  "HotPathOnePolicy CapFromPolicy BulkReplayAgrees"
  "HotPathOnePolicy CapSealed BulkReplayAgrees"
  "HotPathOnePolicyWindow CapFromPolicy BulkReplayAgrees"
  "HotPathOnePolicyWindow CapSealed BulkReplayAgrees"
  # Liveness, under weak fairness (HotPathOneLive's PROPERTIES).
  "HotPathOneLive WorkerHonoursDeadline UseAnswered"
  "HotPathOneLive ChangeRereads ChangeAnswered"
  # 0.15's sealing into Merkle checkpoints, two trees as one pair (Seal.tla; W209, W212; the plan's PR 6).
  "Seal NumberUnderLock Complete"
  "Seal CloseLocks Complete"
  "Seal RememberFirst SealedDeletionDetected"
  "Seal RememberFirst SplitViewDetected"
  "Seal MacChecked NoForgerySealed"
  "Seal RequestIdChecked NoUndetectedReplay"
  "Seal WaitForSeal AnsweredChangeKept"
  # The witness alone does not stand in for the signer's memory (SealPlugin's expected failures, below).
  "Seal SignerMemory SealedDeletionDetected"
  # Core, R40 without the plugin: the signer's memory is what holds.
  "SealCore SignerMemory SealedDeletionDetected"
  "SealCore SignerMemory SplitViewDetected"
  "SealCore SignerMemory AnsweredChangeKept"
  # A newest row deleted with nothing new to seal: seen at the next tick only if the signer checks the row.
  "SealCore RowChecked SealedDeletionDetected"
  # The plugin alone: the witness is what holds an answered change.
  "SealPlugin Witness AnsweredChangeKept"
  # The two heads, changes' and uses', as one pair (W212).
  "Seal PairWrittenTogether PairConsistent"
  "Seal PairWrittenTogether NoFalseAlarm"
  "Seal PairRemembered PairConsistent"
  "SealCore PairChecked+PairVerified SealedDeletionDetected"
  "Seal KindInMac KindKept"
  # 0.15's cutover from 0.14 (Migration015.tla; docs/design/0.15-plan.md, PR 9).
  "Migration015 CutoverHeadLock+CutoverFence OneCutover"
  "Migration015 CutoverHeadLock+VerifyRows+OldWritesFence NewLogFollowsOld"
  "Migration015 Marker OneCutover"
  "Migration015 DualFence NothingAllowedAfterAnswer"
  "Migration015 OldWritesFence NothingAllowedAfterAnswer"
  "Migration015 ChangeHeadFirst NoWaitCycle"
  "Migration015 Adopt EveryOldWriteAdopted"
  "Migration015 AdoptRepeats EveryOldWriteAdopted"
  "Migration015Tamper VerifyChain AnchorHolds"
  "Migration015Tamper VerifyRows AllowedOnlyWhenGranted"
  "Migration015Tamper AdoptVerifies NewLogFollowsOld"
  "Migration015Tamper AdoptSealsEntry AllowedOnlyWhenGranted"
  "Migration015Tamper UsesSeeOldWrites AllowedOnlyWhenGranted"
  "Migration015Drops AdoptAfterSeal NewChangesStand"
  # The marker PR 5 did not take (the plan's PR 5): it holds only while the writer leaves it alone.
  "Migration015Marker OldWriteMarksRow AllowedOnlyWhenGranted"
  # … and a writer who clears it (MaxClears=1) breaks it with every protection on: why PR 5 keeps the probe.
  "Migration015Marker MaxClears=1 AllowedOnlyWhenGranted"
)

# What a design does not protect, with every protection of the scenario on: TLC must find it broken.
EXPECTED=(
  # Deleting or moving an entry before it is sealed: the ~1-tick window R51 accepts for uses (Seal.tla).
  "Seal UnsealedDeletionDetected"
  "Seal UnsealedReorderDetected"
  # The witness without the signer's memory: a crash between writing a head and publishing it.
  "SealPlugin SealedDeletionDetected"
  "SealPlugin SplitViewDetected"
)

# CI's shards, balanced by what each scenario took on a runner (seconds,
# `--workers 4 --heap 4g`): Tampering alone about 410, `large` about 400, and
# `rest`, every other scenario, about 260. 0.15's models (HotPathOne, Seal,
# Migration015) have four of their own, by user CPU on a shared host (CI's
# 4 cores take about a quarter of it, Tampering's 31 minutes of CPU running
# in its 7 to 11): hotpath (34 minutes of CPU), hotpath-bulk (the bulk cap's
# main scenario), hotpath-skew (its slack and clock-skew scenarios; the two
# together took 62) and seal (Seal and Migration015, 50). A scenario in no case below is in `rest`.
SHARDS="tampering large rest hotpath hotpath-bulk hotpath-skew seal"
shard_of() {
  case "$1" in
    Tampering) echo tampering ;;
    Overtaking|Walking|Sharing|Rows|Mixed) echo large ;;
    HotPathOneBulkSkew|HotPathOneBulkSlack) echo hotpath-skew ;;
    HotPathOneBulk) echo hotpath-bulk ;;
    HotPathOne*) echo hotpath ;;
    Seal*|Migration015*) echo seal ;;
    *) echo rest ;;
  esac
}

root="$(cd "$(dirname "$0")/.." && pwd)"
workers=2
heap=1g
list=""
shard=""
only=" "
while [ $# -gt 0 ]; do
  case "$1" in --workers|--heap|--shard) [ $# -ge 2 ] || { echo "$1 takes a value" >&2; exit 2; } ;; esac
  case "$1" in
    --workers) workers="$2"; shift 2 ;;
    --heap)
      [[ "$2" =~ ^[0-9]+[kKmMgG]$ ]] || { echo "--heap $2: expected a size such as 4g" >&2; exit 2; }
      heap="$2"; shift 2 ;;
    --list) list=1; shift ;;
    --shard)
      case " $SHARDS " in *" $2 "*) shard="$2" ;; *) echo "no shard $2 ($SHARDS)" >&2; exit 2 ;; esac
      shift 2 ;;
    *) only="$only$1 "; shift ;;
  esac
done

jar="${XDG_CACHE_HOME:-$HOME/.cache}/coffre/tla2tools-$TLA_VERSION.jar"
if [ -z "$list" ] && ! echo "$TLA_SHA256  $jar" | sha256sum -c --status 2>/dev/null; then
  mkdir -p "$(dirname "$jar")"
  curl -fsSL --retry 3 -o "$jar.part" "$TLA_URL"
  echo "$TLA_SHA256  $jar.part" | sha256sum -c --quiet
  mv "$jar.part" "$jar"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$root"/formal/*.tla "$root"/formal/*.cfg "$work"/

# The module of a configuration's scenarios.
model() { sed -n '2s/^\\\* model \([A-Za-z0-9]*\)$/\1/p' "$work/$1"; }

tlc() {
  local module
  module="$(model "$1")"
  # TLC names its states directory by the second it starts: two runs in one
  # second would share it, and the second fail.
  rm -rf "$work/states"
  (cd "$work" && java -XX:+UseParallelGC -Xmx$heap -cp "$jar" tlc2.TLC -nowarning -difftrace \
    -workers "$workers" -metadir "$work/states" -config "$1" "${module:-MC}.tla") >"$work/out.txt" 2>&1 || true
}

failed=0
scenarios=()
for cfg in "$root"/formal/*.cfg; do scenarios+=("$(basename "$cfg" .cfg)"); done

for name in $only; do
  [ -f "$root/formal/$name.cfg" ] || { echo "no scenario $name: formal/$name.cfg" >&2; exit 2; }
done

# Whether this run covers a scenario: one named, one in the shard, or all.
wanted() {
  case "$only" in *" $1 "*) return 0 ;; esac
  if [ -n "$shard" ]; then [ "$(shard_of "$1")" = "$shard" ]; else [ "$only" = " " ]; fi
}

for scenario in "${scenarios[@]}"; do
  wanted "$scenario" || continue
  [ -z "$list" ] || { echo "holds    $scenario"; continue; }
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

# The scenario's copy with its invariants replaced by one, or, for a property it lists, that property alone.
only_check() {
  if sed -n '/^PROPERTIES/,$p' "$work/without.cfg" | grep -q "^    $1$"; then
    sed -i -e '/^INVARIANTS/,/^\(PROPERTIES\|CHECK_DEADLOCK\)/{/^INVARIANTS/d;/^    /d}' -e '/^PROPERTIES/,${/^    /d}' \
      -e "s/^PROPERTIES/PROPERTIES\n    $1/" "$work/without.cfg"
    broken="^Error: Temporal properties were violated"
  else
    sed -i -e '/^INVARIANTS/,/^\(PROPERTIES\|CHECK_DEADLOCK\)/{/^    /d}' -e '/^PROPERTIES/,${/^PROPERTIES/d;/^    /d}' \
      -e "s/^INVARIANTS/INVARIANTS\n    $1/" "$work/without.cfg"
    broken="^Error: Invariant $1 is violated"
  fi
}

for removal in "${REMOVALS[@]}"; do
  read -r scenario protection invariant <<<"$removal"
  wanted "$scenario" || continue
  [ -z "$list" ] || { echo "without  $scenario $protection"; continue; }
  # The scenario with the protections off, holding to the one invariant they keep.
  cp "$work/$scenario.cfg" "$work/without.cfg"
  missing=""
  for off in ${protection//+/ }; do
    if [[ "$off" == *=* ]]; then
      name="${off%%=*}"
      value="${off#*=}"
      grep -q "^    $name = " "$work/without.cfg" || { missing="$name"; continue; }
      escaped="$(printf '%s' "$value" | sed -e 's/[\/&]/\\&/g')"
      sed -i -e "s/^\(    $name\) = .*/\1 = $escaped/" "$work/without.cfg"
    else
      sed -i -e "s/^\(    $off\) = TRUE/\1 = FALSE/" "$work/without.cfg"
      grep -q "^    $off = FALSE" "$work/without.cfg" || missing="$off"
    fi
  done
  [ -z "$missing" ] || { echo "FAIL  $scenario has no $missing"; failed=1; continue; }
  # How the run reads: "without A and B", or "with Name=Value" for a constant set.
  what="without ${protection//+/ and }"
  [[ "$protection" == *=* ]] && what="with ${protection//+/ and }"
  only_check "$invariant"
  started=$SECONDS
  tlc without.cfg
  if grep -q "$broken" "$work/out.txt"; then
    echo "ok    $scenario $what breaks $invariant ($((SECONDS - started))s):"
    node "$root/scripts/formal-trace.mjs" <"$work/out.txt" | tail -n +2 | sed 's/^/        /'
  else
    echo "FAIL  $scenario $what should break $invariant"
    cat "$work/out.txt"
    failed=1
  fi
done

for gap in ${EXPECTED[@]+"${EXPECTED[@]}"}; do
  read -r scenario invariant <<<"$gap"
  wanted "$scenario" || continue
  [ -z "$list" ] || { echo "open     $scenario $invariant"; continue; }
  cp "$work/$scenario.cfg" "$work/without.cfg"
  only_check "$invariant"
  started=$SECONDS
  tlc without.cfg
  if grep -q "$broken" "$work/out.txt"; then
    echo "ok    $scenario, every protection on, breaks $invariant as expected ($((SECONDS - started))s):"
    node "$root/scripts/formal-trace.mjs" <"$work/out.txt" | tail -n +2 | sed 's/^/        /'
  else
    echo "FAIL  $scenario should break $invariant (the window it documents)"
    cat "$work/out.txt"
    failed=1
  fi
done

exit $failed
