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
#                                     large, rest, hotpath, hotpath-policy,
#                                     hotpath-bulk, hotpath-skew, seal,
#                                     seal-plugin or seal-retention
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
  # 0.15's reads (PR 5b): the use decides on the rows as they are, and the app's unlocked check stays needed.
  "Revoking015 CredentialFenceUnlocked NoReleaseAfterEnd"
  "Revoking015 RevokeIssuedCredentials NoReleaseAfterEnd"
  # The check in the use itself (T145): it decides on the generations, sealed, and the app reads nothing after it.
  "Revoking015Folded UseDecidesGeneration NoReleaseAfterEnd"
  "Revoking015Folded RevokeIssuedCredentials NoReleaseAfterEnd"
  # PR B: the use is the vault's one call, nothing asked or kept about the account before it.
  "Revoking015Caller UseDecidesGeneration NoReleaseAfterEnd"
  "Revoking015Caller RevokeIssuedCredentials NoReleaseAfterEnd"
  # What a caller with no access learns of keys by asking (Probing.tla; T145 PR B, #406 r2, T158): nothing, under any load, nor from how long it takes.
  "Probing OneNo NoIsFixed"
  "Probing ResolveByName NoIsFixed"
  "Probing MissingByStanding NoIsFixed"
  # A plain value goes back only on the vault's standing (PR B), which W268's gate decides before the key is read: each covers the other.
  "Probing PlainByStanding+StandingFirst NoIsFixed"
  "Probing StandingSharesAdmission NoIsFixed"
  "Probing DecideBeforeLock NoIsFixed"
  "Probing DecideBeforeLock NoLockForNo"
  "Probing DecideEachLock NoIsFixed"
  "Probing DecideEachLock NoLockForNo"
  "Probing CoveredRefusalAnswered NoIsFixed"
  # Review r2 of D153: the route is the credential's and its account's; a use by ids decides before the lock too.
  "Probing RouteByCredential OneRoute"
  "Probing RouteByCredential NoIsFixed"
  "Probing RouteByCredential+DecideBeforeLockById NoLockForNo"
  # Review r4 of D153: a key that reads an archived place is the vault's refusal, by name, never the app's path.
  "Probing ArchivedByName NoIsFixed"
  "Probing ArchivedByName OneRoute"
  # Reviews r6 and r7 of D153: the vault holds the credential first to what the app's config accepts, for a provider removed and for a move to Access each.
  "Probing AcceptedFirst NoIsFixed"
  "ProbingProvider AcceptedFirst NoIsFixed"
  "ProbingAccess AcceptedFirst NoIsFixed"
  # Review r8 of D153: one clock, the app judging the credential's expiry at the request's `at`, as the vault does.
  "Probing OneClock NoIsFixed"
  "ProbingFloor AdmissionBeforeKey NoIsFixed"
  "ProbingArchived AdmissionBeforeKey NoIsFixed"
  "ProbingKept ConfirmOnBusy SameAnswer"
  # D150 (fallback D), W268: her standing decided from rows no key decides, before any of the key's is read.
  "Probing StandingFirst NoKeyBeforeStanding"
  "ProbingFloor StandingFirst NoKeyBeforeStanding"
  # B2 (Batching.tla, T167): a request's several keys, one vault call and one statement, two rounds as a use by ids.
  "Batching StrongestFirst NoWaitCycle"
  "Batching CountsOwnBatch CapHolds"
  "Batching DecideBeforeLock NoLockForRefused"
  "BatchingRefused DecideBeforeLock NoLockForRefused"
  "BatchingRefused DecideBeforeLock RefusedEntersNothing"
  "BatchingRefused AllDecidedFirst NoLockForRefused"
  "BatchingRefused AllDecidedFirst RefusedEntersNothing"
  "BatchingRefused AnswerWhole AllOrNothing"
  # A use by name holds its rows to the names (Naming.tla; review r2 of #412): an id kept is used only while it is still named so.
  "Naming HeldToNames UsedAsNamed"
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
  # A change on a row a writer put back: without the check of the base row against the newest change, it re-seals the rollback.
  "HotPathOneSeals ChangeChecksSeal EachChangeFlips"
  "HotPathOneRestore ChangeChecksSeal EachChangeFlips"
  "HotPathOneRestore ChangeChecksSeal ReplaySound"
  # A writer who lowers the floor of `at`: without the barrier's check, a use lands where no checkpoint reads.
  "HotPathOneFloor BarrierChecksFloor CheckpointsHold"
  "HotPathOneRestoreCovers CoverExists RepeatsAreTheirCover"
  "HotPathOneRestoreCovers CoverExists DurableBeforeRelease"
  "HotPathOneClock FloorChecked CheckpointsHold"
  "HotPathOneClock DeadlineChecked NoLateWork"
  "HotPathOneClock WorkerHonoursDeadline ReleaseByDeadline"
  # T158: the principal's lock only once the caller's standing is decided, before it (Probing.tla says why).
  "HotPathOneStaleBulk DecideBeforeLock NoLockWithoutStanding"
  "HotPathOneBulk PrincipalLocks BulkCapHolds"
  "HotPathOneBulk PrincipalLocks BulkReplayAgrees"
  "HotPathOneBulk RefreshOnUse BulkCapHolds"
  # One principal's hot keys: moves take its lock shared and write their period, so they never queue (T127, R44).
  "HotPathOneBulk RefreshShared RefreshesNeverQueue"
  "HotPathOneBulk RefreshLocks BulkReplayAgrees"
  "HotPathOneBulk RefreshPeriods BulkReplayAgrees"
  "HotPathOneBulk CoverFresh BulkCapHolds"
  "HotPathOneBulk DeadlineSlack BulkCapHolds"
  "HotPathOneBulkSlack Slack BulkCapHolds"
  # A use whose Worker's clock runs ahead is decided before one stamped earlier: other keys count that much longer (W228).
  "HotPathOneBulkSkew AheadSlack BulkCapHolds"
  "HotPathOnePolicy CapFromPolicy BulkReplayAgrees"
  "HotPathOnePolicy CapSealed BulkReplayAgrees"
  "HotPathOnePolicyWindow CapFromPolicy BulkReplayAgrees"
  "HotPathOnePolicyWindow CapSealed BulkReplayAgrees"
  # Sign-ins issue under a lock of their own, never the fence (T123, R58).
  "HotPathOneIssue IssueOwnLock UsesNeverWaitOnIssues"
  "HotPathOneIssue BarrierIssueFirst UsesNeverWaitOnIssues"
  "HotPathOneIssue BarrierWaitsIssues CheckpointsHold"
  "HotPathOneIssue IssueNumberUnderLock CheckpointsHold"
  "HotPathOneIssue NamedAfterIssue ReplayAgrees"
  # Liveness, under weak fairness (HotPathOneLive's PROPERTIES).
  "HotPathOneLive WorkerHonoursDeadline UseAnswered"
  "HotPathOneLive ChangeRereads ChangeAnswered"
  # What a 0.15 object's seal covers (SealedObjects.tla; T125, T126, T129): a reference's end, written with its entry; a
  # project's archival on its environments; a plain value's text.
  "SealedObjects EndInRow AllowedAsOld"
  "SealedObjects EndWithEntry AllowedAsOld"
  "SealedObjects ProjectInObject AllowedAsOld"
  "SealedObjects ArchivedApart AllowedAsOld"
  "SealedObjects DigestInSeal AllowedAsOld"
  "SealedObjects DigestInSeal UnrefusedReadsHonest"
  # What an end decides on: the holder's sealed object (its reference's id) and its log, never its rows (review r7).
  "SealedObjects ReferenceInObject AllowedAsOld"
  "SealedObjects LivenessFromLog AllowedAsOld"
  # An unarchive restores what the log last sealed, still so at its commit, and an end while archived changes that (T134).
  "SealedObjects RestoreFromLog AllowedAsOld"
  "SealedObjects RestorePinned AllowedAsOld"
  "SealedObjects EndWhileArchived AllowedAsOld"
  "SealedObjects EndWhileArchived HonestUnarchive"
  # A key archived before the cutover keeps its object in the log, which its unarchive restores (T144).
  "SealedObjectsCutover GenesisKeepsArchived HonestUnarchiveServes"
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
  # Retention (plan PR 7, W229): a cut drops a day of uses below a sealed retention change, keeps every change.
  "SealRetention CutFirst KeptNotLost"
  "SealRetention CutSealed KeptNotLost"
  "SealRetention KeepCutTiles NoFalseAlarm"
  "SealRetentionCrash FreshChecked DroppedNeverResealed"
  "SealRetentionCrash DropAfterSeal NoFalseAlarm"
  "SealRetentionCrash FreshBeforeDrop DroppedNeverResealed"
  "SealRetentionCrash CutUsesOnly ChangesUntouched"
  "SealRetentionCrash CutUsesOnly NoFalseAlarm"
  # 0.15's cutover from 0.14 (Migration015.tla; docs/design/0.15-plan.md, PR 9).
  "Migration015 CutoverHeadLock+CutoverFence+RowFirst OneCutover"
  "Migration015 CutoverHeadLock+VerifyRows+OldWritesFence+RowFirst NewLogFollowsOld"
  "Migration015 Marker OneCutover"
  "Migration015 DualFence NothingAllowedAfterAnswer"
  # A late 0.14 write across a 0.15 use: the trigger's fence makes it wait, its refusal (PR 9b) keeps it out.
  "Migration015 OldWritesFence+OldWritesRefused NothingAllowedAfterAnswer"
  "Migration015 ChangeHeadFirst NoWaitCycle"
  "Migration015 RowFirst NoWaitCycle"
  # An object of the app's rows, changed in the app's own transaction (plan PR 4b): head, row, fence.
  "Migration015App AppHeadFirst NoWaitCycle"
  "Migration015App DualFence NothingAllowedAfterAnswer"
  "Migration015App OldWritesFence+OldWritesRefused NothingAllowedAfterAnswer"
  # Sign-ins and the barrier: the issue lock in the order row, head, issue lock, fence (T123).
  "Migration015Issue IssueBeforeFence NoWaitCycle"
  "Migration015Issue BarrierIssueFirst NoWaitCycle"
  "Migration015Issue ExchangeOnlyIssues ExchangeChangesNoInput"
  "Migration015Issue ExchangeOnlyIssues+OldWritesRefused NothingAllowedAfterAnswer"
  # A policy change takes the issue lock before the fence (T149, review r3): the barrier holds it while it waits for the fence.
  "Migration015Policy PolicyIssueFirst NoWaitCycle"
  # The cutover's own 0.14 entry is fenced by the trigger: the issue lock before the fence, as everywhere (T132).
  "Migration015Issue CutoverIssueFirst NoWaitCycle"
  # A place 0.14 deleted is deleted as its chain says, never its slugs, which a writer renames either way (T130).
  "Migration015Deleted DeletedFromChain NoneInDeleted"
  "Migration015Deleted DeletedFromChain PlaceFollowsOld"
  # An app's row (a credential, a binding: T160) is checked by the app, under its key, and held to that by the vault.
  "Migration015AppTamper VerifyRows AllowedOnlyWhenGranted"
  "Migration015AppTamper VouchedHeld AllowedOnlyWhenGranted"
  # 0.14's code writes nothing after the cutover (PR 9b): its append is refused once the cutover is there.
  "Migration015 OldWritesRefused OldWritesBeforeAnchor"
  "Migration015App OldWritesRefused OldWritesBeforeAnchor"
  "Migration015Tamper VerifyChain AnchorHolds"
  "Migration015Tamper VerifyRows AllowedOnlyWhenGranted"
  # A row put back over a late write: the refusal keeps the write from landing, the probe reads past the row. The
  # refusal is a trigger the database's owner can drop; the probe needs the key.
  "Migration015Tamper UsesSeeOldWrites+OldWritesRefused AllowedOnlyWhenGranted"
  # A 0.15 change that writes no 0.14 entry (T149's revoke, an unbind) takes 0.14's head all the same (PR 9b).
  "Migration015EntryLess EntryLessHead NothingAllowedAfterAnswer"
  # The marker PR 5 did not take (the plan's PR 5): it holds only while the writer leaves it alone.
  "Migration015Marker OldWriteMarksRow AllowedOnlyWhenGranted"
  # … and a writer who clears it (MaxClears=1) breaks it with every protection on: why PR 5 keeps the probe.
  "Migration015Marker MaxClears=1 AllowedOnlyWhenGranted"
  # The vault owns a credential's life (Lifecycle.tla, T149): a sign-in, an issue and a revoke, each one vault call.
  # An issue's write holds the issuer's rows, and goes ahead only on the objects its read decided on: each is needed.
  "LifecycleIssue IssuerLocked SensitiveOnlyFromOwners"
  "LifecycleIssue IssuerLocked IssuedByLiveCredential"
  "LifecycleIssue IssuerCAS SensitiveOnlyFromOwners"
  "LifecycleIssue IssuerCAS IssuedByLiveCredential"
  "LifecycleIssue IssueOffFence UsesNeverWaitOnIssues"
  "LifecycleIssue RevokeTakesFence RevokeOrdersUses"
  # A revoke by a right the policy gives holds that policy to the newest under the fence (T149 r1).
  "LifecycleRevoke RevokePolicyHeld RevokesOnStandingRight"
  # An issue ordered against a policy change that narrows its issuer's role (review r3): held under the issue lock,
  # which the change takes before the fence, so no use waits behind an issue.
  "LifecyclePolicy IssuePolicyHeld SensitiveOnlyFromOwners"
  "LifecyclePolicy PolicyIssueFirst UsesNeverWaitOnIssues"
  # A binding is the vault's to make, as a token is (PR 3a): weighed on its maker's rows, held to them as read.
  "LifecycleBind IssuerLocked SensitiveOnlyFromOwners"
  "LifecycleBind IssuerCAS SensitiveOnlyFromOwners"
  # A sign-in's binding row holds its rate; the account's row, or W242's generation at use, its removal.
  "LifecycleSignIn BindingLocked RateHeld"
  "LifecycleSignIn MemberLocked+UseChecksGeneration AllowedAtCurrentGeneration"
  "LifecycleSignIn IssueOffFence UsesNeverWaitOnIssues"
  "LifecycleSignIn RevokeTakesFence RevokeOrdersUses"
  "LifecycleReplay SpentChecked SpentOnce"
  # An unbind sweeps what its binding issued: only all of it while the sign-in holds the row and the sweep follows its lock.
  "LifecycleUnbind BindingLocked EndedBindingEndsCredentials"
  "LifecycleUnbind SweepAfterLock EndedBindingEndsCredentials"
  # A database writer: what it puts back, forges or edits serves nothing while the use checks seals; a token's hash it
  # moves, nothing while the seal covers the hash (option (a)) or the app checks its MAC (option (b)), either one.
  "LifecycleForge SealChecked AllowedOnSealed"
  "LifecycleForge HashSealed+AppChecksMac AllowedAsPresented"
  # A compromised app: the vault weighs the issuer itself; it mints a run's credential only from a token the binding's
  # issuer signed (D148), and only through a binding the vault sealed.
  "LifecycleCompromised IssuerLocked SensitiveOnlyFromOwners"
  "LifecycleCompromised VaultVerifiesToken SignInsOnValidTokens"
  "LifecycleCompromised BindingSealed SignInsOnValidTokens"
  # The vault holds the token's audience to the sealed binding's, never to one the app names (PR 3b).
  "LifecycleCompromised AudienceSealed SignInsOnValidTokens"
  # A binding of fetched keys, whose tokens the app verifies: the vault still takes only one it sealed.
  "LifecycleFetched BindingSealed SignInsOnValidTokens"
  # A use through a way in with no credentials row (WaysIn.tla, T147): an MCP connection, a Cloudflare binding,
  # Cloudflare Access. The use reads the way in and its account in its own statement, under the fence their ends take.
  "WaysInRevoke WayReadInUse EndOrdersUses"
  "WaysInRevoke RevokeTakesFence EndOrdersUses"
  "WaysInUnbind WayReadInUse EndOrdersUses"
  "WaysInUnbind UnbindTakesFence EndOrdersUses"
  "WaysInRemove UseChecksGeneration AllowedAtCurrentGeneration"
  "WaysInRemove AccountReadInUse RemovalOrdersUses"
  "WaysInRemove RemovalTakesFence RemovalOrdersUses"
  "WaysInForge SealChecked AllowedOnSealed"
)

# What a design does not protect, with every protection of the scenario on: TLC must find it broken.
EXPECTED=(
  # Deleting or moving an entry before it is sealed: the ~1-tick window R51 accepts for uses (Seal.tla).
  "Seal UnsealedDeletionDetected"
  "Seal UnsealedReorderDetected"
  # The witness without the signer's memory: a crash between writing a head and publishing it.
  "SealPlugin SealedDeletionDetected"
  "SealPlugin SplitViewDetected"
  # Below a cut only changes are kept: a straggler (a next-day use numbered below it) deleted, or copied above it
  # and then deleted, once the cut is announced (Seal.tla, W229).
  "SealRetention BelowCutKept"
  "SealRetention ReplayAcrossCutSeen"
  # The vault asks no issuer for keys: a binding of keys its issuer publishes takes the app's word for its
  # tokens, so a compromised app signs a run in through it with a token nobody signed (Lifecycle.tla's Fetched).
  "LifecycleFetched EverySignInOnValidToken"
)

# CI's shards, balanced by what each scenario took on a runner (seconds,
# `--workers 4 --heap 4g`): Tampering alone about 410, `large` about 400, and
# `rest`, every other scenario, about 260. 0.15's models (HotPathOne, Seal,
# Migration015) have seven of their own, each about 5 minutes of TLC with 4
# workers on a shared host, which CI's runners took about twice as long to
# run: hotpath, hotpath-policy (the policy, liveness and stale-bulk
# scenarios), hotpath-bulk (the bulk cap's main scenario), hotpath-skew (its
# slack and clock-skew scenarios), seal (Seal and Migration015),
# seal-plugin (SealPlugin and SealCore) and seal-retention (SealRetention and
# SealRetentionCrash). A scenario in no case below is in `rest`.
SHARDS="tampering large rest hotpath hotpath-policy hotpath-bulk hotpath-skew seal seal-plugin seal-retention"
shard_of() {
  case "$1" in
    Tampering) echo tampering ;;
    Overtaking|Walking|Sharing|Rows|Mixed) echo large ;;
    HotPathOneBulkSkew|HotPathOneBulkSlack) echo hotpath-skew ;;
    HotPathOneBulk) echo hotpath-bulk ;;
    HotPathOneLive|HotPathOnePolicy|HotPathOnePolicyWindow|HotPathOneStaleBulk) echo hotpath-policy ;;
    HotPathOne*) echo hotpath ;;
    SealPlugin|SealCore) echo seal-plugin ;;
    SealRetention*) echo seal-retention ;;
    Seal|Migration015*) echo seal ;;
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
