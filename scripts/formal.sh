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
#                                     large, probing, routing, rest, hotpath,
#                                     hotpath-policy, hotpath-bulk, hotpath-phases,
#                                     hotpath-skew, seal, seal-plugin or
#                                     seal-retention
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
  # T165 (B2): a fork's request and `dev@me`'s, by name in the vault's one call, the chain resolved in it.
  "ProbingFork ForksByName NoIsFixed"
  "ProbingMine ForksByName NoIsFixed"
  "ProbingFallback ForksByName NoIsFixed"
  "ProbingFork ParentInDecision NoIsFixed"
  "ProbingFork CutByPlace NoIsFixed"
  "ProbingFork StandingFirst NoKeyBeforeStanding"
  "ProbingMine StandingFirst NoKeyBeforeStanding"
  "ProbingMine GateWeighsParent NoKeyBeforeStanding"
  # T165 (B2, PR 2): several keys by name, the vault's one call, the gate before any key (ProbingMany.tla).
  "ProbingMany ManyByName NoKeyBeforeStanding"
  "ProbingManyFork ManyByName NoKeyBeforeStanding"
  "ProbingMany GateBeforeKeys NoKeyBeforeStanding"
  "ProbingManyMine GateBeforeKeys NoKeyBeforeStanding"
  "ProbingManyFork CutByPlace OnlyUsable"
  "ProbingManyFork CutByPlace CutReadsNothing"
  "ProbingManyFork ParentInDecision OnlyUsable"
  "ProbingManyMine ParentInDecision OnlyUsable"
  "ProbingMany LeaveFirst LeftOutUnused"
  "ProbingMany LeaveFirst AnsweredAsApp"
  "ProbingMany DecideAllFirst NoLockForNo"
  "ProbingMany DecideAllFirst RefusedEntersNothing"
  "ProbingMany OneCall OneVaultCall"
  "ProbingManyFork IdsChecked OnlyUsable"
  "ProbingManyMine IdsChecked OnlyUsable"
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
  # A person's factor lock (Factor.tla, T176 PR 3): every issue of theirs and every change to their passkeys takes it, the issue first.
  "Factor IssueTakesFactor ChangeEndsAll"
  "Factor IssueTakesFactor LiveFromLive"
  "Factor ChangeTakesFactor ChangeEndsAll"
  "Factor FactorFirst NoWaitCycle"
  "Factor IssueChecksPasskey NamesItsSource"
  # The app's own issues (T176 PR 4): the head orders them against a change, which takes it after the factor lock; each
  # checks its source and the passkey rule under it; and every request refuses what the previous release issued past it.
  "FactorApp ChangeTakesHead ChangeEndsAll"
  "FactorApp AppIssueChecks IssuedBacked"
  "FactorApp AppIssueChecks LiveFromLive"
  "FactorApp RequestChecks ServedBacked"
  # A sign-in at the callback (T176 PR 4b, review r1 of #500): its transaction holds the vault's answer to the access it read, or a promotion meanwhile signs an Owner in by the provider alone.
  "FactorSignin SigninHoldsAccess OwnersEnroll"
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
  # A tunnel saved in the Proxy tab (T186 PR C2b3): an edit of its item ends it within a recheck, another item's edit ends nothing.
  "Tunnel DigestRecheck EditEndsWithinBound"
  "Tunnel ItemDigest StandingStaysOpen"
  # Its admission, whose answer may come late (review r1 of #485): the group's clock starts from the admission, and one past its bound lets nothing in.
  "Tunnel AdmitClock EditEndsWithinBound"
  "Tunnel LateAdmitRefused EditEndsWithinBound"
  # Proxy definitions edited in the UI (Routing.tla, T186): where a key may go when its route is a row an Owner edits.
  "Routing FencedRead EverySendAllowed"
  "Routing SealChecked EverySendAllowed"
  "Routing CopyFromVault EverySendAllowed"
  "Routing SentAsDecided EverySendAllowed"
  "Routing BoundToDefinition EverySendAllowed"
  # Decision 5(b): the frozen clearance against the key's nature now, and the editor's standing now (RoutingEditor).
  "RoutingEditor ClearanceAtUse EverySendAllowed"
  "RoutingEditor EditorStillHolds EverySendAllowed"
  "RoutingEditor FencedRead EverySendAllowed"
  "Routing KeptExpires WithinWindow"
  "Routing OneVersion EverySendAllowed"
  "RoutingCode ClearSuperseded NoRevival"
  "RoutingCode SaveChecksReserved NoRevival"
  "RoutingCode CodeGate NoRevival"
  # A call from an app on another release than the vault's, unrefused, reads and changes the route (Routing.tla).
  "RoutingVersion VersionGate MismatchInert"
  # A route's key by the name the row it reads gives, and the caller's standing first (T205, RoutingKeys): the map's
  # id, an earlier answer's, used whatever the route names now; the route read for a caller then refused; and both
  # read before the fence, the caller decided on a standing revoked since.
  "RoutingKeys KeyByItem EverySendAllowed"
  "RoutingKeys StandingFirst NoRouteBeforeStanding"
  "RoutingKeys FencedRead EverySendAllowed"
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
  # A writer who also writes a put-back row's seal into its newest change (T190): without the MAC check, a use serves it;
  # without keeping only checked seals, the cache serves it to the next; without the change path's, a change seals it.
  "HotPathOneForged ChangeMacChecked ReplaySound"
  "HotPathOneForged CacheVerified ReplaySound"
  "HotPathOneForged ChangeChecksMac EachChangeFlips"
  # ... and who forges that seal only once a sign-in has checked its MAC (T192): without its statement holding the
  # newest change to the one checked, it goes ahead on the writer's row all the same. That is also a write that pins
  # nothing (`app_change`, `issue_token` outside T179's two trips): the scenario without the pin is theirs. And with the pin by number and seal alone, an app hands
  # back an old, authentic change under the newest's number, whose seal the writer made the old one's (review r2).
  "HotPathOneForgedGap ChangePinsChecked EachChangeFlips"
  "HotPathOneForgedGap ChangePinsWhole EachChangeFlips"
  "HotPathOneRestore ChangeChecksSeal EachChangeFlips"
  "HotPathOneRestore ChangeChecksSeal ReplaySound"
  # A writer who lowers the floor of `at`: without the barrier's check, a use lands where no checkpoint reads.
  "HotPathOneFloor BarrierChecksFloor CheckpointsHold"
  # A barrier of a checkpointer given up on lands late (T169): the next one accepts the floor it raised, or none signs again.
  "HotPathOneStallLive BarrierAcceptsLate CheckpointsGoOn"
  # A tick's window capped (T169): a checkpoint sealing a prefix signs the floor of what is left above it.
  "HotPathOneChunks ChunkFloor CheckpointsHold"
  # ... whose uses sit within D + MaxSkew of it: both ends of their numbering held to Postgres's clock.
  "HotPathOneChunks AheadChecked CeilingHolds"
  "HotPathOneChunks DeadlineChecked CeilingHolds"
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
  # Each key's periods from a phase of its own (T204): the replay must start them where the statement does.
  "HotPathOneBulkPhases ReplayPhases BulkReplayAgrees"
  "HotPathOneBulkPhases RefreshPeriods BulkReplayAgrees"
  "HotPathOneBulkPhases CoverFresh BulkCapHolds"
  # Across 0074: the previous release's statement, beside the new one, phases no key; the replay phases a use only if its entry says its statement did.
  "HotPathOneBulkSwitch ReplayPhased BulkReplayAgrees"
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
  # A tick given up on (T169): another signer opens while its database write may still land; fenced, it starts nothing more.
  "SealStall Fenced NoFalseAlarm"
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
  # A change in two round trips (Writing.tla, T179): a key write as one vault statement and one app statement, a
  # member add as the vault's read and its write, each commit holding the whole read its decision weighed.
  # The read one statement under the fence: a change between two of its parts tears the request from the log.
  "WritingRevoke RequestUnderFence RequestsReplay"
  # No hold at all: every adversary commits past.
  "WritingRevoke ReadHeld WritesStandAtCommit"
  "WritingNames ReadHeld WritesStandAtCommit"
  "WritingProtect ReadHeld AddsStandAtCommit"
  # The hold skipping one part of the read, each in turn: a read function that missed it. Each review round's P1 is
  # one of these (rounds 1 and 2: the fork chain, the roles; round 3: the names; round 5: the protected set).
  'WritingRevoke Unheld={"cred"} WritesStandAtCommit'
  'WritingRevoke Unheld={"member"} WritesStandAtCommit'
  'WritingPlace Unheld={"roles"} WritesStandAtCommit'
  'WritingPlace Unheld={"policy"} WritesStandAtCommit'
  'WritingPlace Unheld={"env"} WritesStandAtCommit'
  'WritingFork Unheld={"parent"} WritesStandAtCommit'
  'WritingFork Unheld={"parentKey"} WritesStandAtCommit'
  'WritingRevoke Unheld={"key"} KeyChangesFlip'
  'WritingNames Unheld={"keyName"} WritesStandAtCommit'
  'WritingNames Unheld={"chain"} WritesStandAtCommit'
  'WritingNames Unheld={"me"} WritesStandAtCommit'
  'WritingAdd Unheld={"bob"} AddsStandAtCommit'
  'WritingAdd Unheld={"policy"} AddsStandAtCommit'
  'WritingSetUp Unheld={"roles"} AddsStandAtCommit'
  'WritingSetUp Unheld={"settings"} AddsStandAtCommit'
  'WritingSetUp Unheld={"place"} AddsStandAtCommit'
  'WritingProtect Unheld={"prot"} AddsStandAtCommit'
  'WritingProtect Unheld={"envs"} AddsStandAtCommit'
  'WritingProtect Unheld={"slug"} AddsStandAtCommit'
  'WritingProtect Unheld={"scope"} AddsStandAtCommit'
  'WritingAdd Unheld={"svc"} AddsFlip'
  # The add's read holding the adder's session (PR 5): revoked between the read and the write, the add still commits.
  'WritingAdd Unheld={"cred"} AddsStandAtCommit'
  # The add's session not held to its membership's generation (review r1 of #474): Bob removed and restored before
  # his session's row is revoked, the retry's read finds it live and him an admin again, and adds with it.
  "WritingRejoin GenerationChecked AddsStandAtCommit"
  # The decision weighing anything but the read (the roles from its isolate's cache): the hold holds the read, and
  # the role redefined before both is missed.
  "WritingPlace DecideOnRead WritesStandAtCommit"
  # The hold before the fence: a session's revoke, which takes the fence and not the head, between it and the write.
  "WritingRevoke HoldAfterFence WritesStandAtCommit"
  # The read's numbers from the row's own seal column: a database writer puts a revoked session back, live.
  "WritingTamper ReadOnLog WritesStandAtCommit"
  # The hold by value alone: a grant taken and given back passes, and the log no longer shows the read at the commit.
  "WritingABA ReadByNumber CommitsReplay"
  "WritingAdd WaitForSeal AnsweredSealed"
  # The app's auth_mac check left out (round 6): a database writer copies a token hash onto an Owner's credential;
  # the vault resolves the token to the Owner, its read and its hold agree, and the write or the add commits as them.
  "WritingTamper AuthChecked CommitsAuthentic"
  "WritingAdd AuthChecked CommitsAuthentic"
  # The actor taken from what the token resolves to at the commit, not from the checked read (round 7): a database
  # writer takes no lock, and copies the hash after the hold, before the COMMIT.
  "WritingTamper ActorFromRead CommitsAuthentic"
  "WritingAdd ActorFromRead CommitsAuthentic"
  # The newest change's MAC left unchecked (T190): a database writer puts a revoked session's row, or a demoted
  # adder's, back and writes its seal into the log's newest change of it; row and log agree, and only that change's
  # MAC says the vault never wrote it.
  "WritingForge ChangeMacChecked WritesStandAtCommit"
  "WritingForge ChangeMacChecked AddsStandAtCommit"
  # Today's path without T190 (PR 3's fallback): a request the two-trip path refused for its forged grant goes down a
  # path that trusts the forged seal, and decides on the grant the log took away.
  "WritingForge TodayChangeMacChecked TodayStandsAtDecision"
  # A key write's credential touch after the hold (WriteLocks.tla, review r1 of #469): it holds the issue lock and the
  # fence and waits for an issue's shared hold on its credential, that issue queued behind the barrier, which waits
  # for the write's issue lock.
  "WriteLocks TouchFirst NoWaitCycle"
  # A member add taking 0.14's head before the members' rows (AddLocks, T179 PR 5): a demotion holds the row and
  # waits for the head, which the add holds while it waits for the row.
  "AddLocks MembersFirst NoWaitCycle"
  # A finding about a member weighed by 0.14's rule (Findings.tla, T179 PR 4a): under 0.16 no access entry follows a
  # change, and a change above the finding settles nothing.
  "Findings WeighsChanges Settles"
  # The newest finding alone, not any naming the newest change: a check that read before a change commits after one
  # that read past it, and hides it.
  "Findings EveryFinding StandsUnchanged"
  # A finding naming its change by number, which no MAC covers (review r1 of #476): the writer renumbers the newest
  # change up, and the finding about it settles with no change since.
  "Findings NamesChange StandsUnchanged"
  # The same, renumbered before the check and back after: the finding names a number no later change reaches.
  "Findings NamesChange Settles"
  # A request down today's path after a try that committed (its seal wait failing taken for `served: false`): it writes twice.
  "WritingFallBack FallBackUncommitted OneWritePerRequest"
  # Today's commit not holding to the policy the caller was loaded with (`policyStill`): a roles change after its
  # decision does not stop it (review r3 of #469).
  "WritingFallBack TodayPolicyHeld TodayPolicyStandsAtCommit"
  # A refusal down today's path, as before PR 6: a try the vault served, abandoned at its hold, then refused, goes on
  # there with the caller the first try checked, and writes once the grant is back, the session revoked since (review
  # r2 of #469). The refusal's record ends the request instead.
  "WritingCaller RefusalLogged TodayCallerStandsAtDecision"
  # The record written, and the request still sent down today's path after it: a refusal, and then a write.
  "WritingCaller RefusalEnds RefusedOrWritten"
  # The refusal recorded at the vault's decision, before the app checks the caller's rows: a token hash copied onto
  # an Owner's credential puts a refusal in the Owner's name (round 6, for the record a refusal writes).
  "WritingAdd RefusalAfterAuth RefusalsAuthentic"
  # A refusal's record copied, MAC and all, as the newest change of Ada's member object, her row put back: its MAC is
  # over its own object, the request's, so only the change's MAC check refuses it (T190's check, which PR 6 relies on).
  "WritingRefuse ChangeMacChecked WritesStandAtCommit"
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
  # The projection of the uses for the audit pages (Reads.tla, T166): each row the replay's, from sealed changes, at a
  # number the MAC covers; the cursor only past rows written, the vault's, and the signer never waiting for it.
  "Reads DeriveFromSealed+InputsInUseMac ProjectionMatchesReplay"
  "Reads InputsInUseMac ProjectionMatchesReplay"
  "Reads ProjectSealedOnly LagShown"
  "ReadsLive ProjectSealedOnly EveryUseProjected"
  "Reads WindowChecked ProjectionMatchesReplay"
  "Reads NumberInMac ProjectionMatchesReplay"
  "Reads ReplaceOnConflict LagShown"
  "Reads CursorAfterRows LagShown"
  "Reads CursorMac LagShown"
  "Reads CountChecked DeletionDetected"
  "ReadsRace IdempotentByNumber NoDuplicate"
  "ReadsRetain FromChecked RetiredStayGone"
  "ReadsProbe DeriveFromSealed ProjectionMatchesReplayOrFlagged"
  "ReadsSeal ProjectorApart SealNeverWaitsOnProjection"
  "ReadsSeal ProjectorApart ChangeAnswered"
  "ReadsLive CursorAfterRows EveryUseProjected"
  "ReadsLive DeriveFromSealed EveryUseProjected"
  # 0.15's log across a rotation of the vault's signing key (Rotation.tla; T168, W277). An isolate under the old key,
  # serving on after the deploy, is refused at its write, under the lock, ordered against the rotation's entry.
  "RotationDeploy RetiredRefused OldWritesBelowBoundary"
  "RotationDeploy RetiredRefused LogWorks"
  "RotationDeploy RefusedUnderLock OldWritesBelowBoundary"
  "RotationDeploy RotateUnderLock OldWritesBelowBoundary"
  # The signer carries its memory across, and takes the database's pair under the old key after a restore.
  "RotationDeploy MemoryUnderPrevious LogWorks"
  "RotationDeploy RowUnderPrevious LogWorks"
  "RotationDeploy PendingAccepted NoFalseAlarm"
  # Someone who holds the old key: it vouches for nothing past the rotation, in a tick or a check.
  "RotationLeak BoundaryChecked SealedBelowBoundary"
  "RotationLeak BoundaryChecked VerifiedSound"
  "RotationLeak RotationProbed VerifiedSound"
  "RotationLeak AnchorKeyHeld VerifiedSound"
  # A config rolled back to the old key: its signer signs nothing, refused by itself or by the trigger.
  "RotationRollback KeyNeverBack+RetiredRefused NoOldPairOverRotation"
  # Sol's review r1 of #444: a tick sealing its window in parts leaves a pair under the new key below the rotation; a
  # rotation's row renumbered; a pair naming a key it is not signed under; a reader whose two reads straddle the deploy.
  "RotationChunked KeyringBound NoFalseAlarm"
  "RotationMove NumberInRotation SealedBelowBoundary"
  "RotationMove NumberInRotation VerifiedSound"
  "RotationClaim SignerVerified VerifiedSound"
  "RotationReader SnapshotRead ReaderNoFalseAlarm"
  "RotationReader SnapshotRead ReaderSound"
  # Muse's review r2 of #444: the fence's `retired` is a row a database writer edits; a rotation into the old key,
  # planted past its own, must not make the signer write a second boundary.
  "RotationFence ChainRule SealedBelowBoundary"
  # Muse's review r3: the vault's own rotation deleted as well; the planted rotation still counts for nothing.
  "RotationFenceGone ChainRule SealedBelowBoundary"
  # Fable's review r6: two rotations, A to B to C, and someone who holds A and B; a rotation counts only where the key
  # it moves the log to vouches at its number (Keyring.tla).
  "RotationChain ChainRule KeyringSound"
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
  # The page does not see a projection row deleted below its cursor: the full verify does (Reads.tla).
  "Reads ListedComplete"
  # A use's MAC that covers only its own columns: the projector's probe of the changes finds a sealed change, not
  # provably the newest, and a writer who deletes the newest is seen by Seal's verifier alone (Reads.tla).
  "ReadsProbe ProjectionMatchesReplay"
  # The floor is an unsigned row: a writer who lowers it and puts it back before the next barrier reads it lets uses in
  # unsealed, which BarrierChecksFloor cannot see; a late barrier of a checkpointer given up on (T169) can put it back
  # as well (HotPathOne.tla).
  "HotPathOneStall CheckpointsHold"
  # Postgres's clock stepping back: a use may sit past its checkpoint's ceiling, which the verifier's bounded read
  # misses, and alarms on: fail closed (HotPathOne.tla's CeilingHolds).
  "HotPathOneChunksClock CeilingHolds"
  # Values decided before an edit serve out their window (cacheSeconds, or the use's deadline), as a revoked handle's
  # do: a request may still go to the upstream an edit replaced, W at most after it (Routing.tla).
  "Routing StrictlyCurrent"
  # Not a gap but a witness: code shadows a UI version in RoutingCode's protected runs, so NoRevival holds for a reason.
  "RoutingCode NeverShadowed"
  # An Owner who releases a reserved name while a deployment still serving defines it: the UI definition saved after,
  # hidden there, serves again once that deployment is gone (Routing.tla). Release says so before it acts.
  "RoutingRelease NoRevival"
  # The rotation entry deleted before its first seal, by someone who holds the old key, who signs a pair over its
  # place: the rotation's window, a tick long, which no check sees (Rotation.tla).
  "RotationWindow VerifiedSound"
  # Today's path decides at the vault's wrap and commits after, weighing only the policy (`policyStill`), the
  # environment and the key's row again: a grant revoked or a session ended after the front door does not stop the
  # write (Writing.tla's WToday, WTodayCommit; reviews r1 and r3 of #469). Every
  # write has had this window since 0.14; the two-trip path closes it for the writes it serves (WritesStandAtCommit),
  # and for their refusals since PR 6; what it does not serve keeps it (a key made a reference here; docs/design/two-trips.md,
  # PR 3b and PR 7).
  "WritingFallBack TodayStandsAtCommit"
  # Today's path after a try the vault served goes on with the caller that try's read checked, and its wrap weighs the
  # caller's member and roles, not its session: a session revoked between that check and the wrap does not stop the
  # write (Writing.tla's Auth, WToday; review r2 of #469). Today's front door has had the same window before its wrap
  # since 0.14; after a served try it spans those tries too. A refused try no longer goes there (PR 6, WritingCaller);
  # one the vault no longer serves (a key made a reference) still does (docs/design/two-trips.md, PR 3b and PR 7).
  "WritingCallerShape TodayCallerStandsAtDecision"
)

# CI's shards, balanced by what each scenario took on a runner (seconds,
# `--workers 4 --heap 4g`): Tampering alone about 410, and `large` about 400.
# `rest`, every other scenario, took 39 minutes of its 45 on CI by 2026-11-02 and
# was cancelled at 45 from 2026-11-06 on, with identical state counts but each
# scenario about 1.75 times slower (Probing 361 s against 201 s): run 42220741374
# of #515 timed 96 scenarios at 40 minutes and their runs without a protection
# at 5 more. So it is three, each 11 to 18 minutes there, none dominated by a
# scenario that could not move:
#   probing   Probing, ProbingFork and ProbingFallback: 17 minutes;
#   routing   Routing's six and the other Probing variants: 17 minutes;
#   rest      every other scenario, the Writing ones' 63 and 59 seconds the
#             largest: 11 to 13 minutes.
# T165's ProbingMany scenarios, about 10 minutes of CI (ProbingManyFork 7 of
# them), are in `large`. 0.15's models (HotPathOne, Seal,
# Migration015) have eight of their own, each about 5 minutes of TLC with 4
# workers on a shared host, which CI's runners took about twice as long to
# run: hotpath, hotpath-policy (the policy, liveness and stale-bulk
# scenarios), hotpath-bulk (the bulk cap's main scenario), hotpath-phases
# (its keys' phases, and beside the previous release's statement, T204),
# hotpath-skew (its slack and clock-skew scenarios), seal (Seal and Migration015),
# seal-plugin (SealPlugin and SealCore) and seal-retention (SealRetention,
# SealRetentionCrash and the key's Rotation scenarios). A scenario in no case
# below is in `rest`; `scripts/formal-shards.test.mjs` holds the shards to a
# partition of every scenario and every run without a protection.
SHARDS="tampering large probing routing rest hotpath hotpath-policy hotpath-bulk hotpath-phases hotpath-skew seal seal-plugin seal-retention"
shard_of() {
  case "$1" in
    Tampering) echo tampering ;;
    Overtaking|Walking|Sharing|Rows|Mixed|ProbingMany*) echo large ;;
    Probing|ProbingFork|ProbingFallback) echo probing ;;
    Routing*|Probing*) echo routing ;;
    HotPathOneBulkSkew|HotPathOneBulkSlack) echo hotpath-skew ;;
    HotPathOneBulk) echo hotpath-bulk ;;
    HotPathOneBulkPhases|HotPathOneBulkSwitch) echo hotpath-phases ;;
    HotPathOneLive|HotPathOneStallLive|HotPathOnePolicy|HotPathOnePolicyWindow|HotPathOneStaleBulk) echo hotpath-policy ;;
    HotPathOne*) echo hotpath ;;
    SealPlugin|SealCore|SealStall) echo seal-plugin ;;
    SealRetention*|Rotation*) echo seal-retention ;;
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
if [ -z "$list" ]; then "$root/scripts/fetch.sh" "$TLA_URL" "$TLA_SHA256" "$jar"; fi

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
