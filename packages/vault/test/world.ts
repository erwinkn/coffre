import { EVERYWHERE } from '@coffre/core/access';

import type { BulkRows } from '../src/bulk.ts';
import type { BulkLimit } from '../src/config.ts';
import { decideUse, type UseCode, type UseRequest } from '../src/decide.ts';
import { limitOp, applyOp, objectKey, sealKey, sealOf, type Input, type Op, type Ref } from '../src/inputs.ts';
import { readUse, type Logged } from '../src/log-replay.ts';

/**
 * The tables of 0.15, as the change path and the use path will write and
 * read them, over maps: each change applied with `applyOp`, its row written
 * with the seal it leaves, and logged; each use read with `readUse`, logged,
 * and decided. Its log is what a replay walks.
 */
export const SEAL_KEYS = [sealKey(Buffer.alloc(32, 7))];

export class World {
  readonly rows = new Map<string, { row: Input; seal: Buffer | null }>();
  /** Each object's newest seal, as the changes table has it. */
  readonly newest = new Map<string, Buffer | null>();
  readonly bulk = new Map<string, BulkRows>();
  /** The cap the policy's newest change logged, as the changes table has it. */
  limit: BulkLimit | null = null;
  readonly log: Logged[] = [];
  /** Every row each object has had, with its seal: what a database writer could put back. */
  readonly history = new Map<string, { row: Input; seal: Buffer }[]>();
  #number = 0n;

  /** The change, if it does something: its row written, its entry logged. Whether it did. */
  change(ref: Ref, op: Op, at = 0): boolean {
    const key = objectKey(ref);
    const after = applyOp(this.rows.get(key)?.row ?? null, ref, op);
    if (after === undefined) return false;
    const seal = after === null ? null : sealOf(SEAL_KEYS[0]!, ref, after);
    if (after === null) this.rows.delete(key);
    else {
      this.rows.set(key, { row: after, seal });
      this.history.set(key, [...(this.history.get(key) ?? []), { row: after, seal: seal! }]);
    }
    this.newest.set(key, seal);
    if (after?.kind === 'policy') this.limit = after.bulk;
    this.log.push({ kind: 'change', number: (this.#number += 1n), at, ref, op, seal });
    return true;
  }

  /** A use: read, logged, decided. */
  use(request: UseRequest): UseCode | null {
    this.log.push({ kind: 'use', number: (this.#number += 1n), request });
    return decideUse(SEAL_KEYS, readUse(this.rows, this.newest, this.limit, this.bulk, request), request);
  }
}

/** A small instance: market's dev and prod (protected), a fork of dev, Ada's personal config of dev; Ada, an Owner; Bo, a Viewer of dev; ci, a token. */
export const MARKET = '00000000-0000-4000-8000-000000000001';
export const DEV = '00000000-0000-4000-8000-0000000000d1';
export const PROD = '00000000-0000-4000-8000-0000000000d2';
export const FORK = '00000000-0000-4000-8000-0000000000d3';
export const MINE = '00000000-0000-4000-8000-0000000000d4';
export const ADA = 'user:ada@acme.example';
export const BO = 'user:bo@acme.example';
export const CI = 'token:ci';
export const key = (n: number) => `00000000-0000-4000-8001-${n.toString(16).padStart(12, '0')}`;
export const credential = (n: number) => `00000000-0000-4000-8002-${n.toString(16).padStart(12, '0')}`;
export const WRAPPED = { kekProvider: 'local', kekId: 'k1', kekVersion: '1', bytes: 'AAAA' };

export function market(limit = { count: 3, windowMs: 60_000 }): World {
  const w = new World();
  w.change({ kind: 'policy', id: 'instance' }, limitOp(limit));
  w.change({ kind: 'roles', id: 'instance' }, { op: 'role.define', table: 'roles', role: 'viewer', definition: null });
  w.change({ kind: 'environment', id: DEV }, { op: 'environment.create', projectId: MARKET, slug: 'dev', owner: null, parentId: null, protected: false });
  w.change({ kind: 'environment', id: PROD }, { op: 'environment.create', projectId: MARKET, slug: 'prod', owner: null, parentId: null, protected: true });
  w.change({ kind: 'environment', id: FORK }, { op: 'environment.create', projectId: MARKET, slug: 'fork', owner: null, parentId: DEV, protected: false });
  w.change({ kind: 'environment', id: MINE }, { op: 'environment.create', projectId: MARKET, slug: 'dev', owner: ADA, parentId: DEV, protected: false });
  w.change({ kind: 'principal', id: ADA }, { op: 'member.add', role: 'owner', scope: EVERYWHERE });
  w.change({ kind: 'principal', id: BO }, { op: 'member.add', role: 'member', scope: EVERYWHERE });
  w.change({ kind: 'principal', id: BO }, { op: 'access.grant', grant: { projectId: MARKET, environmentId: DEV, environmentSlug: null, role: 'viewer', expiresAt: null } });
  w.change({ kind: 'principal', id: CI }, { op: 'member.add', role: 'member', scope: EVERYWHERE });
  w.change({ kind: 'principal', id: CI }, { op: 'access.grant', grant: { projectId: MARKET, environmentId: null, environmentSlug: null, role: 'viewer', expiresAt: null } });
  w.change({ kind: 'credential', id: credential(1) }, { op: 'credential.issue', principal: ADA, caller: 'person', scope: null, expiresAt: null });
  w.change({ kind: 'credential', id: credential(2) }, { op: 'credential.issue', principal: BO, caller: 'person', scope: null, expiresAt: 1_000_000 });
  w.change({ kind: 'credential', id: credential(3) }, { op: 'credential.issue', principal: CI, caller: 'bearer', scope: null, expiresAt: null });
  for (const [n, environmentId, nature] of [[1, DEV, 'secret'], [2, DEV, 'sensitive'], [3, PROD, 'secret'], [4, DEV, 'secret'], [5, DEV, 'secret'], [6, MINE, 'secret']] as const) {
    w.change({ kind: 'secret', id: key(n) }, { op: 'secret.write', projectId: MARKET, environmentId, version: `v${n}`, nature, key: WRAPPED, digest: null, source: null, reference: null });
  }
  // A reference in the fork to dev's first key.
  w.change({ kind: 'secret', id: key(9) }, { op: 'secret.write', projectId: MARKET, environmentId: FORK, version: 'r9', nature: 'secret', key: null, digest: null, source: key(1), reference: key(1) });
  return w;
}

export const ask = (credentialN: number, keyN: number, extra: Partial<UseRequest> = {}): UseRequest => ({
  credential: credential(credentialN), secretId: key(keyN), place: null, purpose: 'reveal', keepsSensitive: false, at: 1000, ...extra,
});
