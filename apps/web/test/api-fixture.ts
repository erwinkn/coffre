import { randomUUID } from 'node:crypto';

import type { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import type { Database } from '../../../packages/db/src/database.ts';
import { loadCaller } from '../src/server/api/caller.ts';
import type { ApiContext } from '../src/server/api/context.ts';
import { SyncRunner } from '../src/server/api/syncs.ts';

export type FixtureDeps = {
  db: Database;
  keks: KekRegistry;
  chainKey: Buffer;
  rootAdmins: readonly string[];
  waitUntil?: ApiContext['waitUntil'];
  syncs?: SyncRunner;
};

/** A handler context for one principal, loaded the way a request loads it. */
export async function contextFor(
  deps: FixtureDeps,
  id: string,
  type: 'user' | 'service' = 'user',
): Promise<ApiContext> {
  return {
    db: deps.db,
    keks: deps.keks,
    chainKey: deps.chainKey,
    rootAdmins: deps.rootAdmins,
    waitUntil:
      deps.waitUntil ??
      ((promise) => {
        promise.catch((error: unknown) => console.error('background task failed', error));
      }),
    syncs: deps.syncs ?? new SyncRunner({ db: deps.db, keks: deps.keks, chainKey: deps.chainKey }),
    caller: await loadCaller(deps.db, { type, id }, deps.rootAdmins),
    requestId: randomUUID(),
    sourceIp: null,
    credentialId: null,
  };
}
