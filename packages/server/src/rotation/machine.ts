import type { Credential, CredentialProvider } from './provider.ts';

/**
 * PROTOTYPE (W109): one automatic rotation, as a row the scheduled job
 * advances a step at a time, each beat.
 *
 *   issue    sweep orphans, make the new credential, store it as the current
 *            version: one step, since its value lives only in memory
 *   overlap  both work; wait until the overlap has passed, everyone who read
 *            the old value has read the new one, and the provider has seen
 *            the old one idle
 *   revoke   revoke the old one at the provider, then record it
 *   done
 *
 * No step holds a transaction across a call to the provider or the vault:
 * each provider call is made, then its outcome saved, so a crash anywhere
 * leaves a row a later beat can finish. The two halfway cases:
 *
 * - The provider made the credential, but coffre never stored it (the
 *   answer was lost, or the write failed): the row is still at `issue`. Its
 *   value is gone, so the credential is an orphan; the next attempt finds it
 *   by its name (`coffre/<rotation id>`) and revokes it before issuing again.
 * - The provider revoked the old one, but coffre never recorded it: the row
 *   is still at `revoke`, and revoking again finds it gone, which counts.
 *
 * Two beats on one row (a slow one and the next) each compare and set it;
 * the loser revokes what it made. A lease on the row would spare the
 * provider the second call; the comparison is what keeps it correct.
 *
 * And the order holds one thing always: the old credential is revoked only
 * once the new one is stored as the current version, so whatever reads
 * coffre gets a value that works.
 */
export type Rotation = {
  id: string;
  step: 'issue' | 'overlap' | 'revoke' | 'done';
  /** The credential being replaced; null when coffre does not know it (a key pasted by hand), so revoking it is a person's job. */
  old: Credential | null;
  /** The one made, once stored. */
  next: Credential | null;
  /** The secret's version holding it, and when that became current. */
  version: number | null;
  storedAt: number | null;
  failures: number;
  lastError: string | null;
};

export type RotationPolicy = {
  /** How long both must work, at least. */
  overlapMs: number;
  /** How long the provider must have seen the old one unused, where it can say. */
  idleMs: number;
};

export interface RotationStore {
  /**
   * Store `value` as the secret's new current version and `after` as the
   * rotation, in one transaction, after the vault wrapped the value's key
   * outside it, if no other beat moved the rotation meanwhile. Answers the
   * version, or null when another beat got there first.
   */
  storeValue(before: Rotation, after: Rotation, value: string): Promise<number | null>;
  /** Save `after` in place of `before`, if no other beat moved it meanwhile. */
  save(before: Rotation, after: Rotation): Promise<boolean>;
}

export type RotationDeps = {
  provider: CredentialProvider;
  store: RotationStore;
  policy: RotationPolicy;
  now: () => number;
  /** Who read the replaced version lately and has not read the new one since (`laggards`). */
  laggards: (rotation: Rotation) => Promise<string[]>;
};

export type Advanced =
  | { rotation: Rotation; outcome: 'moved' | 'done' }
  | { rotation: Rotation; outcome: 'waiting'; on: string[] }
  | { rotation: Rotation; outcome: 'failed'; error: string };

export const namePrefix = (rotation: Rotation): string => `coffre/${rotation.id}`;

/** Take one step. A beat calls it once per open rotation. */
export async function advance(rotation: Rotation, deps: RotationDeps): Promise<Advanced> {
  try {
    switch (rotation.step) {
      case 'issue':
        return await issue(rotation, deps);
      case 'overlap':
        return await overlap(rotation, deps);
      case 'revoke':
        return await revoke(rotation, deps);
      case 'done':
        return { rotation, outcome: 'done' };
    }
  } catch (error) {
    const message = (error as Error).message;
    const failed = { ...rotation, failures: rotation.failures + 1, lastError: message };
    // A save that fails too leaves the row as it was: the next beat tries again.
    await deps.store.save(rotation, failed).catch(() => false);
    return { rotation: failed, outcome: 'failed', error: message };
  }
}

async function issue(rotation: Rotation, { provider, store, now }: RotationDeps): Promise<Advanced> {
  // At `issue`, coffre holds no credential under this rotation's name, so
  // any the provider lists is one an earlier attempt made and lost.
  for (const orphan of await provider.list(namePrefix(rotation))) await provider.revoke(orphan);
  const { credential, value } = await provider.issue(`${namePrefix(rotation)}/${rotation.failures + 1}`);
  const stored: Rotation = { ...rotation, step: 'overlap', next: credential, storedAt: now(), lastError: null };
  const version = await store.storeValue(rotation, stored, value);
  if (version === null) {
    // Another beat stored its own: this one is an orphan already.
    await provider.revoke(credential);
    throw new Error('another beat moved this rotation');
  }
  return { rotation: { ...stored, version }, outcome: 'moved' };
}

async function overlap(rotation: Rotation, deps: RotationDeps): Promise<Advanced> {
  const { provider, policy, now } = deps;
  const on: string[] = [];
  const until = rotation.storedAt! + policy.overlapMs;
  if (now() < until) on.push(`the overlap, until ${new Date(until).toISOString()}`);
  on.push(...(await deps.laggards(rotation)));
  if (rotation.old !== null && provider.lastUsed !== undefined) {
    const used = await provider.lastUsed(rotation.old);
    if (used !== null && now() - used < policy.idleMs) on.push(`${provider.kind}: the old one, used ${new Date(used).toISOString()}`);
  }
  if (on.length > 0) return { rotation, outcome: 'waiting', on };
  return moveTo(rotation, { ...rotation, step: 'revoke' }, deps);
}

async function revoke(rotation: Rotation, deps: RotationDeps): Promise<Advanced> {
  const { provider } = deps;
  if (rotation.old !== null) await provider.revoke(rotation.old);
  // A beat that lost a race, then crashed before revoking what it made,
  // left one more under this rotation's name: none but the stored one stays.
  for (const made of await provider.list(namePrefix(rotation))) {
    if (made.id !== rotation.next!.id) await provider.revoke(made);
  }
  return moveTo(rotation, { ...rotation, step: 'done', lastError: null }, deps);
}

async function moveTo(before: Rotation, after: Rotation, { store }: RotationDeps): Promise<Advanced> {
  if (!(await store.save(before, after))) throw new Error('another beat moved this rotation');
  return { rotation: after, outcome: after.step === 'done' ? 'done' : 'moved' };
}
