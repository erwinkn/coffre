/**
 * A workload's use stopped at its next request, and let go again
 * (`packages/vault/src/ops/freezes.ts`, docs/design/workload-access.md,
 * 8.2): a freeze is a field of the row it stops, and keeps the sessions,
 * codes and bindings under it, so lifting it restores service with no new
 * sign-in. An upstream credential's is its environment's
 * (`upstream.freeze`, `upstream.thaw`).
 */
export type FreezeChanges = WorkloadFreeze | WorkloadUnfreeze;

export type FreezeAnswers = {
  /** The target in its one spelling, and since when it is frozen: a freeze already there is kept, with its time. */
  'workload.freeze': Frozen;
  /** The target in its one spelling, and null: it is not frozen now. */
  'workload.unfreeze': Frozen;
};

export type Frozen = { target: string; frozenAt: string | null };

/**
 * What a freeze names, as `freezeTarget` spells it, and who freezes and
 * lifts it:
 *
 *   instance         every workload's use      an Owner of the whole instance, on a session
 *   token:<name>     one service account's     whoever manages it (`managesService`)
 *   binding:<uuid>   one of its trust bindings the same
 *   session:<uuid>   one workload's session    the same
 *
 * Refused `no_access` where the target is not there (a service account
 * removed, a binding revoked, a session ended or of another generation)
 * or not theirs, one answer; `tampered` where a row the decision weighs
 * was written behind the vault; `workload_cannot_issue` to a workload's
 * session. A target in another spelling, or `credential:…`, is a fault:
 * the app canonicalizes it first. `reason` is why, 1 to 400 characters,
 * which the entry keeps.
 */
export type WorkloadFreeze = { op: 'workload.freeze'; target: string; reason: string };

/** A freeze lifted: by whoever may make it, as `WorkloadFreeze` says. */
export type WorkloadUnfreeze = { op: 'workload.unfreeze'; target: string };
