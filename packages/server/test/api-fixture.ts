import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { issuedGrant } from '@coffre/core/access';
import { sealEntry, type LogFields } from '@coffre/core/audit';
import { UNSEALED, type Through, type UseInput, type UseOutcome, type Vault, type VaultEntry } from '@coffre/core/vault';
import { type Database } from '@coffre/db';
import { auditLog, credentials, environments, grants, logConfig, principals, projects, proxyDefinitions, proxyReserved, secretReferences, secrets, secretVersions, serviceBindings, logUses, logChanges, auditChainHead, deviceLogins, enrollmentCodes, identities, spentIdTokens, cappedAlerts, dismissedKeys, mcpApprovals, mcpConnections, oauthClients, policy, roles, passkeys, bulkCap, auditCursor, logCheckpoints, logTiles } from '@coffre/db/schema';
import { rowsOf } from '@coffre/db/dialect';
import { and, desc, eq, inArray, sql } from 'drizzle-orm';
import { derivedSigningKey } from '@coffre/vault';
import { localVault, runCheckpointer, spoken, type RunningCheckpointer, type SpokenVault, type VaultConfig, type VaultOptions } from '@coffre/vault/node';

import { memoryAnchor, type AnchorStore } from '../src/anchor.ts';
import { appLogKey } from '../src/db/audit.ts';
import { auditWatch } from '../src/plugins/audit-watch.ts';
import { forgetProxyGates } from '../src/proxy-gate.ts';
import { watchContext, watcherOf } from '../src/watch.ts';
import { loadCaller, type Caller } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { serveApi } from '../src/api/router.ts';
import type { SigninService } from '../src/api/signin.ts';
import type { WorkloadService } from '../src/api/workloads.ts';
import { TEST_HOT_DATABASE_URL } from './db/connections.ts';
import { emptyLog, openVaultDatabase, withLogUnlocked } from './db/engine.ts';
import { assertOutsideTransaction } from './transaction-guard.ts';
import { drainBackgroundTasks, trackBackgroundTask } from './background-tasks.ts';

export type FixtureDeps = {
  db: Database;
  vault: TestVault;
  chainKey: Buffer;
  /** The audit anchor, in memory: `resetDatabase` forgets it with the log. */
  anchor: AnchorStore;
  waitUntil?: ApiContext['waitUntil'];
  /** What the deployment's credential proxy says, as `credentialProxy({ … })` would (`ProxyCode`): none unless set. */
  proxy?: ApiContext['proxy'];
  signin?: SigninService;
  workloads?: WorkloadService;
  /**
   * Whether a read of the audit page or a member's report first lists every log so far (`TestVault.listAudit`), as a
   * deployment's projector has a few seconds after: on unless a test runs a checkpointer of its own, which would then
   * not hold the pairs another one signed.
   */
  settleAudit?: boolean;
};

/**
 * The vault in this process, over the suite's database as the vault's own
 * login, opened on first use. `resetDatabase` empties its members, grants
 * and entries with everything else, and starts every one of them afresh, so
 * a suite's tests do not share them, checkpoints or bulk-limit counts.
 */
export type TestVault = SpeakingVault<Vault> & VaultEntry & {
  /** The raw KEK, and the signing key the vault derives from it, which no database may hold. */
  kek: Buffer;
  signingKey: Buffer;
  /** Move the vault's clock, for expiry and the bulk limit. */
  advance(ms: number): void;
  reset(): Promise<void>;
  /**
   * Every log as the audit projection lists it, as `listAudit` settles it, with a checkpointer of its own;
   * `settling`, as a read of the page does first (`settleAudit`): a log a test broke is left as far as it was listed,
   * as a deployment's projector leaves it, for the test to find what its pages say of it.
   */
  listAudit(settling?: boolean): Promise<void>;
};

/**
 * Every log as the audit projection lists it, up to now: while `audit_log` is still appended to, it is listed behind
 * its newest signed 0.14 checkpoint, which the beat writes every five minutes and this asks for at once; the chains
 * behind the newest pair, which a tick signs; then the projector runs until nothing is left. The one place to change
 * when `audit_log` freezes (the checkpoint goes).
 */
export async function listAudit(vault: Pick<Vault, 'checkpoint'>, signer: Pick<RunningCheckpointer, 'checkpointer' | 'auditProjected'>): Promise<void> {
  const checkpoint = await vault.checkpoint();
  assert.ok(checkpoint.ok, JSON.stringify(checkpoint));
  await projected(signer);
}

/** The chains signed to their newest pair, and the projector run until nothing is left. */
async function projected(signer: Pick<RunningCheckpointer, 'checkpointer' | 'auditProjected'>): Promise<void> {
  await signer.checkpointer.tick();
  await signer.auditProjected();
}

/** A vault's input as a test writes it: its `caller` may be left out, for `speaking` to say. */
type Spoken<I> = I extends Through ? Omit<I, 'caller'> & Partial<Through> : I;

/** A vault whose calls may leave `caller` out (`speaking`). */
export type SpeakingVault<V> = { [K in keyof V]: V[K] extends (input: infer I) => infer R ? (I extends Through ? (input: Spoken<I>) => R : V[K]) : V[K] };

/**
 * `vault`, spoken to as the app does by a test about something other than
 * who asks: a call that leaves its `caller` out says the kind its acting
 * principal is, a person for `user:`, a bearer for `token:`. One about a
 * workload says so itself.
 */
export function speaking<V extends object>(vault: V): SpeakingVault<V> {
  return new Proxy(vault, {
    get(target, name) {
      const value: unknown = Reflect.get(target, name);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => value.apply(target, [said(args[0]), ...args.slice(1)]);
    },
  }) as unknown as SpeakingVault<V>;
}

function said(input: unknown): unknown {
  if (typeof input !== 'object' || input === null || 'caller' in input) return input;
  const { actor, principal } = input as { actor?: unknown; principal?: unknown };
  const asking = typeof actor === 'string' ? actor : principal;
  return typeof asking === 'string' ? { ...input, caller: asking.startsWith('user:') ? 'person' : 'bearer' } : input;
}

const vaults = new Set<TestVault>();

/** The vault's calls that use values by name, which it makes before the app authenticates, and by ids, after. */
const BY_NAME = ['useNamed', 'useNamedMany'] as const;
const BY_IDS = ['use', 'useMany'] as const;

/**
 * Run `before` and `after` once, around the vault's next use by ids (`use`, or `useMany` for several keys), which the
 * app asks once it has authenticated the request. A request by name is one vault call, made before the app
 * authenticates from the rows it returns; its next one is declined (`served: false`), as a vault that serves none,
 * so the app authenticates the request as ever and asks by ids, as a workload's read does.
 */
export function aroundNextUseByIds(vault: Vault, hooks: { before?: () => Promise<unknown>; after?: () => Promise<unknown> }): void {
  const methods = vault as unknown as Record<string, ((...args: unknown[]) => Promise<unknown>) | undefined>;
  const saved = [...BY_NAME, ...BY_IDS].map((name) => [name, methods[name]] as const);
  const restore = () => {
    for (const [name, original] of saved) methods[name] = original;
  };
  for (const name of BY_NAME) if (methods[name] !== undefined) methods[name] = async () => ({ served: false });
  for (const name of BY_IDS) {
    const method = methods[name];
    if (method === undefined) continue;
    methods[name] = async (...args) => {
      restore();
      await hooks.before?.();
      const used = await method.apply(vault, args);
      await hooks.after?.();
      return used;
    };
  }
}

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
/**
 * The uses 0.15's log holds, oldest first: each read's record there, where 0.14's are its `secret.read` and
 * `credential.use` entries. Slim (R53): the credential, the key, the purpose's code (`log-replay.ts`, PURPOSES: 4 a
 * use) and the place; a repeat its isolate's cover rides writes none.
 */
export async function usesLogged(owner: Database): Promise<{ credential: string; secret: string; purpose: number; place: string | null }[]> {
  return owner.select({ credential: logUses.credential, secret: logUses.secret, purpose: logUses.purpose, place: logUses.place }).from(logUses).orderBy(logUses.number);
}

/**
 * The reason the newest refusal of a read gives: a key's one "no" says none (D153), its entry does. The app's entry,
 * or, where the vault refused by its own path and logged it, the vault's code: one of them, never both.
 */
export async function refusedIn(owner: Database): Promise<string | null> {
  const [newest] = await owner.select({ author: auditLog.author, code: auditLog.code, metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'deny'))).orderBy(desc(auditLog.seq)).limit(1);
  if (newest === undefined) return null;
  return newest.author === 'vault' ? newest.code : ((JSON.parse(newest.metadata) as { reason?: string }).reason ?? null);
}

/** A sign-in through a trust binding, as its log records it (`signInsLogged`). */
export type LoggedSignIn = { actor: string; credentialId: string; bindingId: string; run: Record<string, unknown>; record: Record<string, unknown> };

/**
 * The sign-ins through trust bindings, oldest first, as the log that records
 * them has them: 0.14's `token.exchange` entries; or, with 0.15's log, where
 * the vault makes them (T149), their changes, whose payload records the
 * sign-in (D147). `record` is the entry's metadata, or the change's payload.
 */
export async function signInsLogged(owner: Database): Promise<LoggedSignIn[]> {
  const entries = await owner.select({ actor: auditLog.actor, metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.action, 'token.exchange'), eq(auditLog.decision, 'allow'))).orderBy(auditLog.seq);
  const changes = await owner.select({ actor: logChanges.actor, payload: logChanges.payload }).from(logChanges).orderBy(logChanges.number);
  return [
    ...entries.map(({ actor, metadata }) => {
      const record = JSON.parse(metadata) as Record<string, unknown>;
      return { actor: actor!, credentialId: record.credentialId as string, bindingId: record.bindingId as string, run: record.run as Record<string, unknown>, record };
    }),
    ...changes.flatMap(({ actor, payload }) => {
      const record = JSON.parse(payload) as { ref: { id: string }; signIn?: { binding: string; run: Record<string, unknown> } };
      return record.signIn === undefined ? [] : [{ actor, credentialId: record.ref.id, bindingId: record.signIn.binding, run: record.signIn.run, record }];
    }),
  ];
}

/**
 * The tokens issued by request, oldest first, as the log that records them
 * has them: 0.14's allowed `token.create` entries; or, with 0.15's log,
 * where the vault issues them (T149, PR 2), their changes, which record who
 * issued what kind (D147). `scope` is the token's, as stored.
 */
export async function issuesLogged(owner: Database): Promise<{ actor: string; kind: string; targetCredentialId: string; label: string | null }[]> {
  const entries = await owner.select({ actor: auditLog.actor, metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.action, 'token.create'), eq(auditLog.decision, 'allow'))).orderBy(auditLog.seq);
  const changes = await owner.select({ payload: logChanges.payload }).from(logChanges).orderBy(logChanges.number);
  return [
    ...entries.map(({ actor, metadata }) => {
      const { kind, targetCredentialId, label } = JSON.parse(metadata) as { kind: string; targetCredentialId: string; label?: string | null };
      return { actor: actor!, kind, targetCredentialId, label: label ?? null };
    }),
    ...changes.flatMap(({ payload }) => {
      const record = JSON.parse(payload) as { ref: { id: string }; issue?: { by: string; kind: string; label: string | null } };
      return record.issue === undefined ? [] : [{ actor: record.issue.by, kind: record.issue.kind, targetCredentialId: record.ref.id, label: record.issue.label }];
    }),
  ];
}

/**
 * The credentials revoked by request, oldest first, as the log that records
 * them has them: 0.14's allowed `token.revoke` and `sign_out` entries; or,
 * with 0.15's log, where the vault revokes them (T149), their changes, each
 * with its reason (D147). Who, and which credential: as each one names them.
 */
export async function revokesLogged(owner: Database): Promise<{ actor: string; reason: 'revoke' | 'sign_out'; targetCredentialId: string }[]> {
  const entries = await owner.select({ actor: auditLog.actor, action: auditLog.action, metadata: auditLog.metadata }).from(auditLog)
    .where(and(inArray(auditLog.action, ['token.revoke', 'sign_out']), eq(auditLog.decision, 'allow'))).orderBy(auditLog.seq);
  const changes = await owner.select({ actor: logChanges.actor, payload: logChanges.payload }).from(logChanges).orderBy(logChanges.number);
  return [
    ...entries.map(({ actor, action, metadata }) => ({
      actor: actor!, reason: action === 'sign_out' ? 'sign_out' as const : 'revoke' as const, targetCredentialId: (JSON.parse(metadata) as { targetCredentialId: string }).targetCredentialId,
    })),
    ...changes.flatMap(({ actor, payload }) => {
      const record = JSON.parse(payload) as { ref: { id: string }; revoke?: { reason: 'revoke' | 'sign_out' } };
      return record.revoke === undefined ? [] : [{ actor, reason: record.revoke.reason, targetCredentialId: record.ref.id }];
    }),
  ];
}

/**
 * Each use the vault is asked for from now, and its answer, until `stop` puts its `use` back: how often a value was
 * opened under 0.15's log, where `usesLogged` misses a repeat its cover rode.
 */
export function watchUses(vault: TestVault): { asked: UseInput[]; answered: UseOutcome[]; stop(): void } {
  const use = vault.use!;
  const named = vault.useNamed!;
  const asked: UseInput[] = [];
  const answered: UseOutcome[] = [];
  vault.use = async (input) => {
    asked.push(input);
    const outcome = await use(input);
    answered.push(outcome);
    return outcome;
  };
  // A request's one key, used by name (T145): as the use by ids it made, its key's id the vault's answer. Not a plain
  // value's, which opens nothing, as when the app handed it back itself; nor one the vault serves not by name.
  vault.useNamed = async (input) => {
    const outcome = await named(input);
    if (outcome.served && !(outcome.outcome.ok && 'plain' in outcome.outcome)) {
      asked.push({ credential: '', secretId: outcome.route === 'name' ? outcome.secretId ?? '' : '', place: null, purpose: input.purpose, requestId: input.requestId, at: input.at, deadline: input.deadline });
      answered.push(outcome.outcome as UseOutcome);
    }
    return outcome;
  };
  return { asked, answered, stop: () => void Object.assign(vault, { use, useNamed: named }) };
}

/** The ids of the keys named `key`, in any environment: what a use names (`watchUses`). */
export async function keyIds(owner: Database, key: string): Promise<string[]> {
  return (await owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, key))).map((row) => row.id);
}

/** 0.15's hot path's database, as a vault's `hotDatabase` takes it: its own login. */
export function hotDatabaseUrl(): string {
  return TEST_HOT_DATABASE_URL;
}

/** A checkpointer that seals everything at once: what a change waits on, in a test with no tree. */
export const sealedNow: NonNullable<VaultOptions['sealThrough']> = async () => ({}) as Awaited<ReturnType<NonNullable<VaultOptions['sealThrough']>>>;

/**
 * A checkpointer that seals at once until `stalled` is set, then answers every wait as a stalled one does: the change
 * committed, its seal not in time (`Unsealed`, T169).
 */
export function stallingSeal(): { sealThrough: NonNullable<VaultOptions['sealThrough']>; stalled: boolean } {
  const sealing = {
    stalled: false,
    sealThrough: (async (...args) => {
      if (sealing.stalled) throw new Error(`change ${String(args[0])} ${UNSEALED}: the test's checkpointer stalled; try again shortly`);
      return sealedNow(...args);
    }) as NonNullable<VaultOptions['sealThrough']>,
  };
  return sealing;
}

/** No pair held outside, as a signer that never signed: what a vault with no checkpointer is verified against. */
export const nothingHeld: NonNullable<VaultOptions['heldOutside']> = async () => [];

/**
 * `vault` as a deployment's config takes it, the version gate's one entry:
 * each call answered on the caller's release, by the method `vault` has
 * then. For a test's own `Vault` (a counting proxy, a fake): the vault it
 * wraps, if any, gates on its own.
 */
export function entryOf(vault: Vault): VaultEntry {
  return { call: async (release, method, args) => ({ release, result: await (vault[method] as (...given: unknown[]) => Promise<unknown>)(...args) }) };
}

export function testVault(
  owners: readonly string[],
  /**
   * `owners`: the emails the configuration names, the first of `owners` unless given; one named here alone is never admitted until it signs in.
   * `database`, `hotDatabase`: ones a test opened, to watch what the vault sends them; the suite's own otherwise.
   */
  config: Partial<Pick<VaultConfig, 'bulkLimit' | 'kek' | 'signingKey' | 'owners'>> & { database?: Database; hotDatabase?: string | Database } = {},
  keys: { kek: Buffer } = { kek: randomBytes(32) },
  walks: VaultOptions['walks'] = {},
  /** `throttled: false`: its throttle off, for a suite whose answers are `late` on purpose (`VaultOptions.throttled`). */
  options: Pick<VaultOptions, 'sealThrough' | 'heldOutside' | 'uses' | 'throttled'> = { sealThrough: sealedNow, heldOutside: nothingHeld },
): TestVault {
  const { kek } = keys;
  const signingKey = derivedSigningKey(kek);
  let offset = 0;
  let current: Promise<SpokenVault> | null = null;
  const open = async () => {
    const database = config.database ?? await openVaultDatabase();
    const opened = spoken(await localVault(
      {
        database,
        kek: { id: 'test-kek-1', key: kek.toString('base64') },
        owners: owners.length > 0 ? owners.slice(0, 1) : ['nobody@coffre.test'],
        // Its uses over the hot path's login: the app opens values through them.
        hotDatabase: hotDatabaseUrl(),
        ...config,
      },
      { clockOffset: () => offset, walks, ...options },
    ));
    const [first, ...others] = owners.map((email) => `user:${email}`);
    // A vault given the wrong keys checks no row and answers nobody: its own tests ask it.
    const signedIn = first === undefined ? null : await opened.access(first).catch(() => null);
    if (signedIn?.role === 'owner') {
      for (const principal of others) await opened.admit({ actor: first, caller: 'person', principal, role: 'owner' });
    }
    return opened;
  };
  const call = (name: keyof Vault) => async (...args: unknown[]) => {
    assertOutsideTransaction(name);
    return (speaking(await (current ??= open()))[name] as (...args: unknown[]) => Promise<unknown>)(...args);
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
    prepare: call('prepare'),
    writeKeys: call('writeKeys'),
    admitRead: call('admitRead'),
    admitWrite: call('admitWrite'),
    recordRefusal: call('recordRefusal'),
    rebuildAudit: call('rebuildAudit'),
    waitSealed: call('waitSealed'),
    signIn: call('signIn'),
    revokeCredential: call('revokeCredential'),
    issueToken: call('issueToken'),
    changeBindings: call('changeBindings'),
    verifyTrees: call('verifyTrees'),
    verifyReads: call('verifyReads'),
    vouch: call('vouch'),
    // 0.15's use path, which the app opens values through with 0.15's log on (keys.ts, `openValues`).
    use: call('use'),
    // And its use by name (T145, PR B): a reveal's or a handle's one key, which the vault resolves and uses in one call.
    useNamed: call('useNamed'),
    // And a request's several keys in one call, by ids (T167) and by name (T165), as the app asks a vault of this
    // release. Without them, its keys were a call each, four at once: each new to its principal's cap set took the
    // principal's lock in a transaction of its own, so a request's keys waited on each other, and one past the hot
    // login's lock_timeout answered busy, `late`, where the vault's one batch takes the lock once (T203).
    useMany: call('useMany'),
    useNamedMany: call('useNamedMany'),
    // 0.16's proxy definitions (T186).
    proxy: call('proxy'),
    saveProxy: call('saveProxy'),
    reserveProxy: call('reserveProxy'),
    releaseProxy: call('releaseProxy'),
    proxySavedBy: call('proxySavedBy'),
    // And the route use of a UI definition, and its items read as a use finds them (T186 PR C).
    useRoute: call('useRoute'),
    proxyItem: call('proxyItem'),
    // As the app's runtime speaks to it, through `versioned`: each call to this vault's methods as they are then, a
    // test's replacements included. The release it answers is the caller's: the vault it opens gates on its own.
    call: async (release: string, method: keyof Vault, args: readonly unknown[]) => ({ release, result: await (vault[method] as (...given: unknown[]) => Promise<unknown>)(...args) }),
    kek,
    signingKey,
    advance: (ms: number) => void (offset += ms),
    async reset() {
      current = null;
      offset = 0;
    },
    async listAudit(settling = false) {
      const checkpoint = await this.checkpoint();
      if (settling && !checkpoint.ok && checkpoint.refusal.code === 'log_broken') return;
      assert.ok(checkpoint.ok, JSON.stringify(checkpoint));
      const memory = mkdtempSync(join(tmpdir(), 'coffre-audit-'));
      const signer = await runCheckpointer({ database: await openVaultDatabase(), signingKeys: [config.signingKey === undefined ? signingKey : Buffer.from(config.signingKey, 'base64')], memory: join(memory, 'memory'), intervalMs: 3_600_000 });
      try {
        await projected(signer);
      } finally {
        await signer.stop();
        rmSync(memory, { recursive: true, force: true });
      }
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
    previousChainKeys: [],
    // The audit watch over the deps' anchor, as a deployment that added it has.
    watch: {
      hooks: watcherOf(auditWatch({ anchor: deps.anchor }))!,
      context: (asCaller, confirmed) =>
        watchContext({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, ...(asCaller ? { actor: { actorType: type, actorId: id }, confirmed } : {}) }),
    },
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
    caller: await serviceScoped(await loadCaller(deps.db, deps.vault, { type, id })),
    requestId: randomUUID(),
    sourceIp: null,
    credentialId: null,
    passkeyId: null,
    // A person signed in a moment ago, whose touch confirmed it, as anyone who acts from a page has: the fresh check
    // takes it (`freshness`), which tests of that check hold apart (`passkey-fresh.test.ts`).
    session: type === 'user' ? { kind: 'browser', confirmedAt: new Date() } : null,
    provenance: null,
    via: null,
    personalToken: null,
    credentialExpiresAt: null,
    rotateAfterDays: 365,
    proxy: deps.proxy ?? null,
  };
}

/**
 * A service signs in only on a token or a trust binding, whose scope is
 * sealed: here, everything the account holds now, as an Owner of the
 * instance would issue it, so it reads its sensitive values too
 * (`readsSensitive`). A person's caller is left as it is, a session's.
 */
function serviceScoped(caller: Caller): Caller {
  if (!caller.service) return caller;
  return { ...caller, credentialScope: caller.grants.map((grant) => ({ ...issuedGrant(grant, caller.policy), sensitive: true })) };
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
    transport: async (request) => {
      if (deps.settleAudit !== false && listsAudit(request)) await deps.vault.listAudit(true);
      return serveApi(request, await contextFor(deps, id, type));
    },
  });
}

/**
 * A read of what the audit projection lists: the audit page, the members' list (the removed ones' counts) and a
 * member's report, the one a removal answers with included.
 */
function listsAudit(request: Request): boolean {
  const { pathname } = new URL(request.url);
  if (request.method === 'DELETE') return /\/members\/[^/]+$/.test(pathname);
  return request.method === 'GET' && /\/audit$|\/members$|\/members\/[^/]+$/.test(pathname);
}

export { openTestDatabase } from './db/engine.ts';

const anchors: (() => void)[] = [];

/** An audit anchor in memory that `resetDatabase` forgets, as it empties the log it anchors. */
export function testAnchor(): AnchorStore {
  let store = memoryAnchor();
  anchors.push(() => (store = memoryAnchor()));
  return { read: () => store.read(), write: (prev, next) => store.write(prev, next) };
}

/** Deps for a fresh instance with these Owners (`testVault`), over the restricted role. */
export function testDeps(db: Database, owners: readonly string[], extra: Partial<FixtureDeps> = {}): FixtureDeps {
  return {
    db,
    vault: testVault(owners),
    chainKey: randomBytes(32),
    anchor: testAnchor(),
    ...extra,
  };
}

/**
 * Empty every table, children first, and rewind the audit chain; then start
 * every test vault afresh, since its members, grants and checkpoints are
 * about this data. Afresh after the tables, not before: a call still under
 * way from the last test (a tunnel's last check) that opens a vault
 * meanwhile writes its policy into the log about to be emptied, and that
 * vault, which wrote it once, never writes it again: the next test's every
 * use would answer `unconfigured`.
 */
export async function resetDatabase(owner: Database): Promise<void> {
  await drainBackgroundTasks();
  for (const reset of anchors) reset();
  // The vault's log starts over, the names code reserved in it with it.
  forgetProxyGates();
  await owner.delete(mcpApprovals);
  await owner.delete(mcpConnections);
  await owner.delete(oauthClients);
  await owner.delete(credentials);
  await owner.delete(enrollmentCodes);
  await owner.delete(serviceBindings);
  await owner.delete(spentIdTokens);
  await owner.delete(cappedAlerts);
  await owner.delete(deviceLogins);
  await owner.delete(identities);
  // What names a passkey is gone: its passkeys next, before their members.
  await owner.delete(passkeys);
  // A reference names its vault entry: it goes before the log.
  await owner.delete(secretReferences);
  await emptyLog(owner);
  // 0.15's log, which the change path writes, gone with the rows it is of.
  await owner.delete(logChanges);
  await owner.delete(logConfig);
  await owner.delete(policy);
  await owner.delete(roles);
  // 0.16's proxy definitions, the vault's objects too.
  await owner.delete(proxyDefinitions);
  await owner.delete(proxyReserved);
  // Its uses and their cap's rows: a test's reads count from none.
  await owner.delete(logUses);
  await owner.delete(bulkCap);
  // Their signed pairs and tiles too: the projector, which every read of the page or a report runs first, walks the
  // pairs from the start, and a pair of the last test's entries would stop it.
  await owner.delete(logCheckpoints);
  await owner.delete(logTiles);
  // The audit projection at its start: nothing listed of any log.
  await owner.execute(sql`TRUNCATE audit_events, audit_event_places, audit_member_keys`);
  const listed = { through: 0n, pair: 0n, at: 0, oldFloor: 0n, oldFrom: 0n, oldTop: 0n, oldHash: Buffer.alloc(32), mac: null, readsFrom: 0 };
  await owner.insert(auditCursor).values({ onlyRow: true, ...listed }).onConflictDoUpdate({ target: auditCursor.onlyRow, set: listed });
  await owner.delete(grants);
  await owner.delete(principals);
  await owner.delete(dismissedKeys);
  await owner.update(secrets).set({ currentVersionId: null });
  await owner.delete(secretVersions);
  await owner.delete(secrets);
  await owner.delete(environments);
  await owner.delete(projects);
  for (const vault of vaults) await vault.reset();
}

/**
 * The log's next entry numbered `from`, the app's, signed with `chainKey` and chained to the head (the entries between
 * never written, as a log grown so far would hold them), and 0.15's next change numbered past it: its
 * sequence moved on (never back, onto a change numbered already). Past 2^53, no JS number holds them.
 */
export async function numbersFrom(owner: Database, from: bigint, chainKey: Buffer): Promise<void> {
  const key = appLogKey(chainKey);
  const [head] = await owner.select({ headHash: auditChainHead.headHash }).from(auditChainHead);
  const fields: LogFields = {
    seq: from, author: key.author, keyId: key.keyId, occurredAt: Date.now(), actor: 'system:test', action: 'test', decision: 'allow', code: null,
    subjectPrincipal: null, projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null,
    relatedSeq: null, metadata: '{}',
  };
  const prevHash = Buffer.from(head!.headHash);
  const entry = { ...fields, prevHash, ...sealEntry(key, prevHash, fields) };
  await withLogUnlocked(owner, async (owned) => {
    await owned.insert(auditLog).values(entry);
  });
  await owner.update(auditChainHead).set({ nextSeq: from + 1n, headHash: entry.hash });
  await rowsOf(owner, sql`SELECT setval('log_next', greatest(${from.toString()}::bigint, (SELECT coalesce(max(number), 0) FROM log_changes)))`);
}

/**
 * With 0.15's log on: every credential's row carries its object's newest
 * change's seal, or neither has one (a row of 0.14's). A row sealed with no
 * change of its own, or one whose change was logged and its seal not written,
 * fails here. Not run at each reset: tests that plant rows around the app,
 * to see them refused, leave such rows on purpose.
 */
export async function credentialsLogged(owner: Database): Promise<void> {
  const newest = new Map<string, { number: bigint; seal: Buffer | null }>();
  for (const change of await owner.select({ object: logChanges.object, number: logChanges.number, seal: logChanges.seal }).from(logChanges)) {
    const number = BigInt(change.number);
    if ((newest.get(change.object)?.number ?? -1n) < number) newest.set(change.object, { number, seal: change.seal ?? null });
  }
  const strays = (await owner.select({ id: credentials.id, kind: credentials.kind, seal: credentials.seal }).from(credentials)).filter(({ id, seal }) => {
    const logged = newest.get(objectKey('credential', id))?.seal ?? null;
    return seal == null || logged === null ? (seal ?? null) !== logged : !seal.equals(logged);
  });
  assert.deepEqual(strays, [], "every credential's row is its newest change's (0.15's log)");
}

/**
 * Every row a 0.15 use decides on (sealed-inputs.md: members and their
 * grants, credentials, keys with their versions and references,
 * environments and their projects, the policy and the roles, and each
 * vault's access entries in 0.14's log, whose newest a use probes),
 * and 0.14's bindings but their last use, table by table, but the credentials
 * `except` names: what a write that only issues a credential must leave as
 * it was, since it takes no fence (migration 0026, ExchangeOnlyIssues).
 */
export async function decisionInputs(owner: Database, except: readonly string[] = []): Promise<Record<string, string[]>> {
  const inputs = { principals, grants, credentials, secrets,
    secretVersions, secretReferences, environments, projects, logConfig,
    proxyDefinitions, proxyReserved, serviceBindings };
  const text = (row: object) => JSON.stringify(row, (_key, value: unknown) => (typeof value === 'bigint' ? value.toString() : value));
  const read: Record<string, string[]> = {};
  for (const [name, table] of Object.entries(inputs)) {
    const rows = (await owner.select().from(table as typeof projects)) as Record<string, unknown>[];
    read[name] = rows
      .filter((row) => name !== 'credentials' || !except.includes(row.id as string))
      // A binding's last use is stamped by every exchange: no decision reads it.
      .map((row) => text(name === 'serviceBindings' ? { ...row, lastUsedAt: null } : row))
      .sort();
  }
  // The entries use_credential probes for the newest of (0024): the allowed access entries the vault wrote, all of them.
  const access = await owner.select({ principal: auditLog.subjectPrincipal, seq: auditLog.seq }).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.decision, 'allow'), inArray(auditLog.action, ['member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke'])));
  read.accessEntries = access.map(({ principal, seq }) => `${principal} ${seq}`).sort();
  return read;
}

/** An object's key in 0.15's log (sealed-inputs.md): the first 16 bytes of SHA-256 over its kind and id, as a uuid. */
function objectKey(kind: string, id: string): string {
  const hex = createHash('sha256').update(`coffre.object.v1\0${kind}\0${id}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Give a service account `viewer` on a project of its own, `<name>-reads`,
 * made straight in the database, so that the app's log holds none of it:
 * a token or a binding reaches only what its account holds when it is
 * made (docs/design/instance-roles.md, "Credentials' scopes").
 */
export async function holdSomething(owner: Database, vault: Vault, service: string, actor: string): Promise<string> {
  const slug = `${service.replace(/^token:/, '')}-reads`;
  const id = randomUUID();
  await owner.insert(projects).values({ id, slug, name: slug });
  const granted = await speaking(vault).setAccess({ actor, principal: service, changes: [{ projectId: id, environmentId: null, role: 'viewer', expiresAt: null }] });
  if (!granted.ok) throw new Error(`could not give ${service} something to hold: ${granted.refusal.message}`);
  return id;
}

const VERSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * A write's outcomes (`SetOutcome`) as a test compares them, by version and
 * nature: each `versionId` checked to be a version's id, then left out.
 */
export function outcomes<T>(written: T): T {
  if (Array.isArray(written)) return written.map(outcomes) as T;
  if (written === null || typeof written !== 'object') return written;
  return Object.fromEntries(Object.entries(written).flatMap(([name, value]) => {
    if (name !== 'versionId') return [[name, outcomes(value)]];
    assert.match(String(value), VERSION_ID, 'a written version names its id');
    return [];
  })) as T;
}
