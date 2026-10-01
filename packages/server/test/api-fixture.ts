import { randomBytes, randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createClient, type CoffreClient } from '@coffre/client';
import type { Vault } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { localVault, type LocalVault, type VaultConfig } from '@coffre/vault/node';

import { loadCaller } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { serveApi } from '../src/api/router.ts';
import type { SigninService } from '../src/api/signin.ts';
import { SyncRunner } from '../src/api/syncs.ts';
import { assertOutsideTransaction } from './transaction-guard.ts';

export type FixtureDeps = {
  db: Database;
  vault: TestVault;
  chainKey: Buffer;
  waitUntil?: ApiContext['waitUntil'];
  syncs?: SyncRunner;
  signin?: SigninService;
};

/**
 * The vault in this process, over a libSQL file of its own, opened on first
 * use. `resetDatabase` starts every one of them afresh, so a suite's tests
 * do not share members, grants, checkpoints or bulk-limit counts.
 */
export type TestVault = Vault & {
  /** The raw KEK and signing key, which no database may hold. */
  kek: Buffer;
  signingKey: Buffer;
  /** The vault's file, while it is open. */
  file(): string | null;
  /** Move the vault's clock, for expiry and the bulk limit. */
  advance(ms: number): void;
  reset(): Promise<void>;
};

const vaults = new Set<TestVault>();

export function testVault(rootAdmins: readonly string[], config: Pick<VaultConfig, 'bulkLimit'> = {}): TestVault {
  const kek = randomBytes(32);
  const signingKey = randomBytes(32);
  let offset = 0;
  let file: string | null = null;
  let current: Promise<LocalVault> | null = null;
  const open = () => {
    file = join(tmpdir(), `coffre-vault-${randomUUID()}.db`);
    return localVault(
      {
        store: file,
        kek: { id: 'test-kek-1', key: kek.toString('base64') },
        rootAdmins,
        signingKey: signingKey.toString('base64'),
        ...config,
      },
      { now: () => Date.now() + offset },
    );
  };
  const call = (name: keyof Vault) => async (...args: unknown[]) => {
    assertOutsideTransaction(name);
    return ((await (current ??= open()))[name] as (...args: unknown[]) => Promise<unknown>)(...args);
  };
  const vault = {
    unwrap: call('unwrap'),
    wrap: call('wrap'),
    rewrap: call('rewrap'),
    access: call('access'),
    members: call('members'),
    setAccess: call('setAccess'),
    admit: call('admit'),
    remove: call('remove'),
    checkpoint: call('checkpoint'),
    latestCheckpoint: call('latestCheckpoint'),
    log: call('log'),
    verifyLog: call('verifyLog'),
    kek,
    signingKey,
    file: () => file,
    advance: (ms: number) => void (offset += ms),
    async reset() {
      const opened = current;
      current = null;
      offset = 0;
      if (opened === null) return;
      (await opened).close();
      for (const suffix of ['', '-wal', '-shm']) rmSync(`${file}${suffix}`, { force: true });
      file = null;
    },
  } as TestVault;
  vaults.add(vault);
  return vault;
}

/** A handler context for one principal, loaded the way a request loads it. */
export async function contextFor(
  deps: FixtureDeps,
  id: string,
  type: 'user' | 'service' = 'user',
): Promise<ApiContext> {
  return {
    db: deps.db,
    vault: deps.vault,
    chainKey: deps.chainKey,
    waitUntil:
      deps.waitUntil ??
      ((promise) => {
        promise.catch((error: unknown) => console.error('background task failed', error));
      }),
    syncs: deps.syncs ?? new SyncRunner({ db: deps.db, vault: deps.vault, chainKey: deps.chainKey }),
    signin: deps.signin ?? null,
    caller: await loadCaller(deps.vault, { type, id }),
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

export { openTestDatabase } from './db/engine.ts';

/** Deps for a fresh instance with these root admins, over the restricted role. */
export function testDeps(db: Database, rootAdmins: readonly string[], extra: Partial<FixtureDeps> = {}): FixtureDeps {
  return {
    db,
    vault: testVault(rootAdmins),
    chainKey: randomBytes(32),
    ...extra,
  };
}

/**
 * Empty every table, children first, and rewind the audit chain; and start
 * every test vault afresh, since its members, grants and checkpoints are
 * about this data.
 */
export async function resetDatabase(owner: Database): Promise<void> {
  for (const vault of vaults) await vault.reset();
  const {
    auditChainHead,
    auditHeartbeat,
    auditLog,
    credentials,
    deviceAuthorizations,
    environments,
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
  await owner.update(auditChainHead).set({ nextSeq: 0n, headHash: Buffer.alloc(32) });
  await owner.update(auditHeartbeat).set({ lastSeq: 0n });
  await owner.update(secrets).set({ currentVersionId: null });
  await owner.delete(secretVersions);
  await owner.delete(secrets);
  await owner.delete(principals);
  await owner.delete(environments);
  await owner.delete(projects);
}
