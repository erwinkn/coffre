import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '../../../packages/client/src/index.ts';
import { LocalKekProvider } from '../../../packages/core/src/kek/local.ts';
import { KekRegistry } from '../../../packages/core/src/kek/registry.ts';
import { tablesOf, type Database } from '../../../packages/db/src/database.ts';
import { loadCaller } from '../src/server/api/caller.ts';
import type { ApiContext } from '../src/server/api/context.ts';
import { serveApi } from '../src/server/api/router.ts';
import type { SigninService } from '../src/server/api/signin.ts';
import { SyncRunner } from '../src/server/api/syncs.ts';

export type FixtureDeps = {
  db: Database;
  keks: KekRegistry;
  chainKey: Buffer;
  rootAdmins: readonly string[];
  waitUntil?: ApiContext['waitUntil'];
  syncs?: SyncRunner;
  signin?: SigninService;
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
    signin: deps.signin ?? null,
    caller: await loadCaller(deps.db, { type, id }, deps.rootAdmins),
    requestId: randomUUID(),
    sourceIp: null,
    credentialId: null,
  };
}

/**
 * The API as one principal sees it, without a server: each call is a
 * Request handed to the router, and the caller is loaded afresh for each
 * one, as a real request would.
 */
export function clientFor(
  deps: FixtureDeps,
  id: string,
  type: 'user' | 'service' = 'user',
): CoffreClient {
  return createClient({
    url: 'https://coffre.test',
    transport: async (request) => serveApi(request, await contextFor(deps, id, type)),
  });
}

export { openTestDatabase } from '../../../packages/db/test/engine.ts';

/** Deps for a fresh instance with one root admin, over the restricted role. */
export function testDeps(db: Database, rootAdmins: readonly string[], extra: Partial<FixtureDeps> = {}): FixtureDeps {
  return {
    db,
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    chainKey: randomBytes(32),
    rootAdmins,
    ...extra,
  };
}

/** Empty every table, children first, and rewind the audit chain. */
export async function resetDatabase(owner: Database): Promise<void> {
  const {
    auditChainHead,
    auditCheckpoints,
    auditHeartbeat,
    auditLog,
    credentials,
    deviceAuthorizations,
    environments,
    grants,
    identities,
    principals,
    projects,
    secrets,
    secretVersions,
    syncKeys,
    syncs,
  } = tablesOf(owner);
  await owner.delete(syncKeys);
  await owner.delete(syncs);
  await owner.delete(credentials);
  await owner.delete(deviceAuthorizations);
  await owner.delete(identities);
  await owner.delete(auditLog);
  await owner.delete(auditCheckpoints);
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  await owner.update(auditHeartbeat).set({ lastSeq: 0n });
  await owner.update(secrets).set({ currentVersionId: null });
  await owner.delete(secretVersions);
  await owner.delete(secrets);
  await owner.delete(grants);
  await owner.delete(principals);
  await owner.delete(environments);
  await owner.delete(projects);
}
