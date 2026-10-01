import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import type { Vault } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { localVault, type LocalVault, type VaultConfig } from '@coffre/vault/node';

import { loadCaller } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { serveApi } from '../src/api/router.ts';
import type { SigninService } from '../src/api/signin.ts';
import { SyncRunner } from '../src/api/syncs.ts';
import { emptyLog, openVaultDatabase } from './db/engine.ts';
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
 * The vault in this process, over the suite's database as the vault's own
 * login, opened on first use. `resetDatabase` empties its members, grants
 * and entries with everything else, and starts every one of them afresh, so
 * a suite's tests do not share them, checkpoints or bulk-limit counts.
 */
export type TestVault = Vault & {
  /** The raw KEK and signing key, which no database may hold. */
  kek: Buffer;
  signingKey: Buffer;
  /** Move the vault's clock, for expiry and the bulk limit. */
  advance(ms: number): void;
  reset(): Promise<void>;
};

const vaults = new Set<TestVault>();

/**
 * A test vault. Another over the same database, as a second instance would
 * be, shares `keys`: one deployment has one KEK and one signing key, and
 * rows sealed under another are refused as tampered.
 */
export function testVault(
  rootAdmins: readonly string[],
  config: Pick<VaultConfig, 'bulkLimit'> = {},
  keys: { kek: Buffer; signingKey: Buffer } = { kek: randomBytes(32), signingKey: randomBytes(32) },
): TestVault {
  const { kek, signingKey } = keys;
  let offset = 0;
  let current: Promise<LocalVault> | null = null;
  const open = async () =>
    localVault(
      {
        database: await openVaultDatabase(),
        kek: { id: 'test-kek-1', key: kek.toString('base64') },
        rootAdmins,
        signingKey: signingKey.toString('base64'),
        ...config,
      },
      { clockOffset: () => offset },
    );
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
    advance: (ms: number) => void (offset += ms),
    async reset() {
      current = null;
      offset = 0;
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
    auditHeartbeat,
    credentials,
    deviceAuthorizations,
    environments,
    identities,
    projects,
    secrets,
    secretVersions,
    syncKeys,
    syncs,
    vaultGrants,
    vaultMembers,
  } = tablesOf(owner);
  await owner.delete(syncKeys);
  await owner.delete(syncs);
  await owner.delete(credentials);
  await owner.delete(deviceAuthorizations);
  await owner.delete(identities);
  await emptyLog(owner);
  await owner.delete(vaultGrants);
  await owner.delete(vaultMembers);
  await owner.update(auditHeartbeat).set({ lastSeq: 0n });
  await owner.update(secrets).set({ currentVersionId: null });
  await owner.delete(secretVersions);
  await owner.delete(secrets);
  await owner.delete(environments);
  await owner.delete(projects);
}
