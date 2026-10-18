import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import type { Vault } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { derivedSigningKey } from '@coffre/vault';
import { localVault, type LocalVault, type VaultConfig } from '@coffre/vault/node';

import { loadCaller } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { serveApi } from '../src/api/router.ts';
import type { SigninService } from '../src/api/signin.ts';
import type { WorkloadService } from '../src/api/workloads.ts';
import { emptyLog, openVaultDatabase } from './db/engine.ts';
import { assertOutsideTransaction } from './transaction-guard.ts';
import { drainBackgroundTasks, trackBackgroundTask } from './background-tasks.ts';

export type FixtureDeps = {
  db: Database;
  vault: TestVault;
  chainKey: Buffer;
  waitUntil?: ApiContext['waitUntil'];
  signin?: SigninService;
  workloads?: WorkloadService;
};

/**
 * The vault in this process, over the suite's database as the vault's own
 * login, opened on first use. `resetDatabase` empties its members, grants
 * and entries with everything else, and starts every one of them afresh, so
 * a suite's tests do not share them, checkpoints or bulk-limit counts.
 */
export type TestVault = Vault & {
  /** The raw KEK, and the signing key the vault derives from it, which no database may hold. */
  kek: Buffer;
  signingKey: Buffer;
  /** Move the vault's clock, for expiry and the bulk limit. */
  advance(ms: number): void;
  reset(): Promise<void>;
};

const vaults = new Set<TestVault>();

/** A test runtime's waitUntil: retain the task until the case is finished. */
export function waitUntil(promise: Promise<unknown>): void {
  trackBackgroundTask(promise);
  promise.catch((error: unknown) => console.error('background task failed', error));
}

/**
 * A test vault, configured as a deployment with a local KEK is: the vault
 * derives its signing key from the KEK. Another over the same database, as
 * a second instance would be, shares `keys`: rows sealed under another
 * deployment's keys are refused as tampered.
 *
 * `owners` own the instance from the start: the first is the one the
 * deployment names (`owners`), signed in as the vault opens, and makes the
 * others Owners too, as a deployment's first Owner would. With none,
 * nobody has signed in yet, and the configuration names someone who never
 * comes.
 */
export function testVault(
  owners: readonly string[],
  config: Partial<Pick<VaultConfig, 'bulkLimit' | 'kek' | 'signingKey'>> = {},
  keys: { kek: Buffer } = { kek: randomBytes(32) },
): TestVault {
  const { kek } = keys;
  const signingKey = derivedSigningKey(kek);
  let offset = 0;
  let current: Promise<LocalVault> | null = null;
  const open = async () => {
    const opened = await localVault(
      {
        database: await openVaultDatabase(),
        kek: { id: 'test-kek-1', key: kek.toString('base64') },
        owners: owners.length > 0 ? owners.slice(0, 1) : ['nobody@coffre.test'],
        ...config,
      },
      { clockOffset: () => offset },
    );
    const [first, ...others] = owners.map((email) => `user:${email}`);
    // A vault given the wrong keys checks no row and answers nobody: its own tests ask it.
    const signedIn = first === undefined ? null : await opened.access(first).catch(() => null);
    if (signedIn?.role === 'owner') {
      for (const principal of others) await opened.admit({ actor: first, principal, role: 'owner' });
    }
    return opened;
  };
  const call = (name: keyof Vault) => async (...args: unknown[]) => {
    assertOutsideTransaction(name);
    return ((await (current ??= open()))[name] as (...args: unknown[]) => Promise<unknown>)(...args);
  };
  const vault = {
    unwrap: call('unwrap'),
    wrap: call('wrap'),
    rewrap: call('rewrap'),
    reference: call('reference'),
    endReferences: call('endReferences'),
    access: call('access'),
    setAccess: call('setAccess'),
    admit: call('admit'),
    remove: call('remove'),
    settings: call('settings'),
    setSettings: call('setSettings'),
    policy: call('policy'),
    changePolicy: call('changePolicy'),
    checkpoint: call('checkpoint'),
    about: call('about'),
    keyChecks: call('keyChecks'),
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
    waitUntil: (promise) => {
      // A custom observer must not bypass the fixture's lifetime tracking.
      if (deps.waitUntil) {
        trackBackgroundTask(promise);
        deps.waitUntil(promise);
      } else {
        waitUntil(promise);
      }
    },
    signin: deps.signin ?? null,
    workloads: deps.workloads ?? null,
    mcp: null,
    caller: await loadCaller(deps.vault, { type, id }),
    requestId: randomUUID(),
    sourceIp: null,
    credentialId: null,
    provenance: null,
    via: null,
    personalToken: null,
    credentialExpiresAt: null,
    rotateAfterDays: 365,
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

/** Deps for a fresh instance with these Owners (`testVault`), over the restricted role. */
export function testDeps(db: Database, owners: readonly string[], extra: Partial<FixtureDeps> = {}): FixtureDeps {
  return {
    db,
    vault: testVault(owners),
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
  await drainBackgroundTasks();
  for (const vault of vaults) await vault.reset();
  const {
    credentials,
    deviceAuthorizations,
    environments,
    identities,
    projects,
    secrets,
    secretVersions,
    serviceBindings,
    consumedTokens,
    secretReferences,
    dismissedKeys,
    mcpApprovals,
    mcpConnections,
    oauthClients,
    vaultGrants,
    vaultMembers,
  } = tablesOf(owner);
  await owner.delete(mcpApprovals);
  await owner.delete(mcpConnections);
  await owner.delete(oauthClients);
  await owner.delete(credentials);
  await owner.delete(serviceBindings);
  await owner.delete(consumedTokens);
  await owner.delete(deviceAuthorizations);
  await owner.delete(identities);
  // A reference names its vault entry: it goes before the log.
  await owner.delete(secretReferences);
  await emptyLog(owner);
  await owner.delete(vaultGrants);
  await owner.delete(vaultMembers);
  await owner.delete(dismissedKeys);
  await owner.update(secrets).set({ currentVersionId: null });
  await owner.delete(secretVersions);
  await owner.delete(secrets);
  await owner.delete(environments);
  await owner.delete(projects);
}

/**
 * Give a service account `viewer` on a project of its own, `<name>-reads`,
 * made straight in the database, so that the app's log holds none of it:
 * a token or a binding reaches only what its account holds when it is
 * made (docs/design/instance-roles.md, "Credentials' scopes").
 */
export async function holdSomething(owner: Database, vault: Vault, service: string, actor: string): Promise<string> {
  const { projects } = tablesOf(owner);
  const slug = `${service.replace(/^token:/, '')}-reads`;
  const id = randomUUID();
  await owner.insert(projects).values({ id, slug, name: slug });
  const granted = await vault.setAccess({ actor, principal: service, changes: [{ projectId: id, environmentId: null, role: 'viewer', expiresAt: null }] });
  if (!granted.ok) throw new Error(`could not give ${service} something to hold: ${granted.refusal.message}`);
  return id;
}
