import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { createClient, type CoffreClient } from '@coffre/client';
import { issuedGrant } from '@coffre/core/access';
import type { Through, UseInput, UseOutcome, Vault } from '@coffre/core/vault';
import { tablesOf, type Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import { and, desc, eq, inArray } from 'drizzle-orm';
import { derivedSigningKey } from '@coffre/vault';
import { localVault, runCheckpointer, type LocalVault, type VaultConfig, type VaultOptions } from '@coffre/vault/node';

import { memoryAnchor, type AnchorStore } from '../src/anchor.ts';
import { auditWatch } from '../src/plugins/audit-watch.ts';
import { watchContext, watcherOf } from '../src/watch.ts';
import { loadCaller, type Caller } from '../src/api/caller.ts';
import type { ApiContext } from '../src/api/context.ts';
import { serveApi } from '../src/api/router.ts';
import type { SigninService } from '../src/api/signin.ts';
import type { WorkloadService } from '../src/api/workloads.ts';
import { TEST_HOT_DATABASE_URL } from './db/connections.ts';
import { emptyLog, openVaultDatabase, TEST_ENGINE } from './db/engine.ts';
import { assertOutsideTransaction } from './transaction-guard.ts';
import { drainBackgroundTasks, trackBackgroundTask } from './background-tasks.ts';

export type FixtureDeps = {
  db: Database;
  vault: TestVault;
  chainKey: Buffer;
  /** The audit anchor, in memory: `resetDatabase` forgets it with the log. */
  anchor: AnchorStore;
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
export type TestVault = SpeakingVault<Vault> & {
  /** The raw KEK, and the signing key the vault derives from it, which no database may hold. */
  kek: Buffer;
  signingKey: Buffer;
  /** Move the vault's clock, for expiry and the bulk limit. */
  advance(ms: number): void;
  reset(): Promise<void>;
  /**
   * 0.15's reads as the audit pages list them, once the log is sealed and the
   * vault's projector has gone that far (T166): a checkpointer of its own,
   * under the vault's signing key, ticks once, then the projector runs to its
   * newest pair. Nothing under 0.14's log.
   */
  listReads(): Promise<void>;
};

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
 * Which log the suite's vaults keep (`VaultOptions.log`): 0.15's, the
 * default, the app's writes logged through the vault (`prepare`), unless
 * `COFFRE_TEST_LOG` says 0.14, which runs every server test on 0.14's
 * alone, as CI does beside it until 0.16 removes it. Its changes answer
 * once committed here: no checkpointer runs (`sealedNow`).
 */
export const LOG = process.env.COFFRE_TEST_LOG === '0.14' ? '0.14' : '0.15';

/** For a test whose setup writes an input's row around the app (a session's end moved in the database), which 0.15's log refuses as not the vault's: run under 0.14's only. */
export const LOG_014_ONLY = LOG === '0.15' ? "0.15's log refuses a row written around the app: this test's setup is 0.14's" : false;

/**
 * Whether a test may edit roles and read values on a credential: not under 0.15's log, which holds no roles until the
 * cutover makes their genesis (plan PR 9). A use decides on the built-in roles meanwhile (vault decide.ts, `noEdits`),
 * where 0.14 decides on the edited ones.
 */
export const EDITS_ROLES = LOG === '0.14';

/** For a test of 0.14's start over of a tampered member, which 0.15's log does not take (the vault's tests' START_OVER): run under 0.14's only. */
export const START_OVER_014 = LOG === '0.15' ? "0.15's log changes no tampered member until a reseal makes its row the log's again (plan PR 9), never 0.14's start over" : false;

/**
 * The uses 0.15's log holds, oldest first: each read's record there, where 0.14's are its `secret.read` and
 * `credential.use` entries. Slim (R53): the credential, the key, the purpose's code (`log-replay.ts`, PURPOSES: 4 a
 * use) and the place; a repeat its isolate's cover rides writes none.
 */
export async function usesLogged(owner: Database): Promise<{ credential: string; secret: string; purpose: number; place: string | null }[]> {
  const { logUses } = tablesOf(owner);
  return owner.select({ credential: logUses.credential, secret: logUses.secret, purpose: logUses.purpose, place: logUses.place }).from(logUses).orderBy(logUses.number);
}

/**
 * The reason the newest refusal of a read gives: a key's one "no" says none (D153), its entry does. The app's entry,
 * or, where the vault refused by its own path and logged it, the vault's code: one of them, never both.
 */
export async function refusedIn(owner: Database): Promise<string | null> {
  const { auditLog } = tablesOf(owner);
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
  const { auditLog, logChanges } = tablesOf(owner);
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
  const { auditLog, logChanges } = tablesOf(owner);
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
  const { auditLog, logChanges } = tablesOf(owner);
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
  const { secrets } = tablesOf(owner);
  return (await owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, key))).map((row) => row.id);
}

/** 0.15's hot path's database, as a vault's `hotDatabase` takes it: its own login on Postgres, the same file on SQLite. */
export function hotDatabaseUrl(): string {
  return TEST_ENGINE === 'postgres' ? TEST_HOT_DATABASE_URL : process.env.COFFRE_TEST_DATABASE_URL!;
}

/** A checkpointer that seals everything at once: what a change waits on, in a test with no tree. */
export const sealedNow: NonNullable<VaultOptions['sealThrough']> = async () => ({}) as Awaited<ReturnType<NonNullable<VaultOptions['sealThrough']>>>;

/** No pair held outside, as a signer that never signed: what a vault with no checkpointer is verified against. */
export const nothingHeld: NonNullable<VaultOptions['heldOutside']> = async () => [];

export function testVault(
  owners: readonly string[],
  config: Partial<Pick<VaultConfig, 'bulkLimit' | 'kek' | 'signingKey'>> & { hotDatabase?: string } = {},
  keys: { kek: Buffer } = { kek: randomBytes(32) },
  walks: VaultOptions['walks'] = {},
  /** `cutover: 'app'`: a 0.15 vault left for the app's door to cut over (cutover.test.ts), not cut over as it opens. */
  { cutover, ...log }: Pick<VaultOptions, 'log' | 'sealThrough' | 'heldOutside' | 'uses'> & { cutover?: 'app' } = LOG === '0.15' ? { log: '0.15', sealThrough: sealedNow, heldOutside: nothingHeld } : { log: '0.14' },
): TestVault {
  const { kek } = keys;
  const signingKey = derivedSigningKey(kek);
  let offset = 0;
  let current: Promise<LocalVault> | null = null;
  const open = async () => {
    const database = await openVaultDatabase();
    const opened = await localVault(
      {
        database,
        kek: { id: 'test-kek-1', key: kek.toString('base64') },
        owners: owners.length > 0 ? owners.slice(0, 1) : ['nobody@coffre.test'],
        // With 0.15's log, its uses too, over the hot path's login (the same file on SQLite): the app opens values through them.
        ...(log.log === '0.15' ? { hotDatabase: hotDatabaseUrl() } : {}),
        ...config,
      },
      { clockOffset: () => offset, walks, ...log },
    );
    // Under 0.15's log, cut over from 0.14 first, as the app's door has it (cutover.ts).
    if (log.log === '0.15' && cutover !== 'app') await cutOverAtOpen(opened, database);
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
    waitSealed: call('waitSealed'),
    signIn: call('signIn'),
    revokeCredential: call('revokeCredential'),
    issueToken: call('issueToken'),
    changeBindings: call('changeBindings'),
    cutover: call('cutover'),
    verifyTrees: call('verifyTrees'),
    verifyReads: call('verifyReads'),
    vouch: call('vouch'),
    // 0.15's use path, which the app opens values through with 0.15's log on (keys.ts, `openValues`).
    use: call('use'),
    // And its use by name (T145, PR B): a reveal's or a handle's one key, which the vault resolves and uses in one call.
    useNamed: call('useNamed'),
    kek,
    signingKey,
    advance: (ms: number) => void (offset += ms),
    async reset() {
      current = null;
      offset = 0;
    },
    async listReads() {
      if (log.log !== '0.15') return;
      const memory = mkdtempSync(join(tmpdir(), 'coffre-reads-'));
      // On a connection of its own, closed after: on SQLite, a connection the vault reads on meanwhile is another.
      const own = TEST_ENGINE === 'postgres' ? null : await openDatabase(process.env.COFFRE_TEST_DATABASE_URL!);
      const signer = await runCheckpointer({ database: own?.db ?? await openVaultDatabase(), signingKeys: [config.signingKey === undefined ? signingKey : Buffer.from(config.signingKey, 'base64')], memory: join(memory, 'memory'), intervalMs: 3_600_000 });
      try {
        await signer.checkpointer.tick();
        await signer.projected();
      } finally {
        await signer.stop();
        await own?.close();
        rmSync(memory, { recursive: true, force: true });
      }
    },
  } as TestVault;
  vaults.add(vault);
  return vault;
}

/**
 * The cutover (plan PR 9) as the app asks for it, of a vault the suite opens
 * on a database nothing of the app's was written to yet: it vouches for no
 * credential, binding or deleted place, and its chain is checked to its
 * head. The app's own half, which vouches, is cutover.test.ts's. Refused,
 * the vault stays as it is: the test asks what it asks of it.
 */
async function cutOverAtOpen(vault: Vault, db: Database): Promise<void> {
  // Refused (a test that broke 0.14's chain before its vault's first call): left so, as the door leaves it; 0.14's
  // own checks go on, and nothing of 0.15's is served.
  const asked = await vault.cutover!();
  if (!asked.ok || asked.done) return;
  const { auditChainHead } = tablesOf(db);
  const [head] = await db.select({ nextSeq: auditChainHead.nextSeq, headHash: auditChainHead.headHash }).from(auditChainHead);
  const to = { seq: (BigInt(head!.nextSeq) - 1n).toString(), hash: Buffer.from(head!.headHash).toString('hex') };
  await vault.cutover!({ checked: { from: asked.from, to }, credentials: [], bindings: [], connections: [], deleted: [] });
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
      context: (asCaller) => watchContext({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, actor: asCaller ? { actorType: type, actorId: id } : undefined }),
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
    provenance: null,
    via: null,
    personalToken: null,
    credentialExpiresAt: null,
    rotateAfterDays: 365,
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
    transport: async (request) => serveApi(request, await contextFor(deps, id, type)),
  });
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
  const {
    credentials,
    deviceAuthorizations,
    enrollments,
    environments,
    identities,
    projects,
    secrets,
    secretVersions,
    serviceBindings,
    consumedTokens,
    cappedAlerts,
    secretReferences,
    dismissedKeys,
    mcpApprovals,
    mcpConnections,
    oauthClients,
    vaultGrants,
    vaultMembers,
    logChanges,
    logConfig,
    logUses,
    logBulk,
    logReads,
    logReadDays,
    logReadsCursor,
  } = tablesOf(owner);
  await owner.delete(mcpApprovals);
  await owner.delete(mcpConnections);
  await owner.delete(oauthClients);
  await owner.delete(credentials);
  await owner.delete(enrollments);
  await owner.delete(serviceBindings);
  await owner.delete(consumedTokens);
  await owner.delete(cappedAlerts);
  await owner.delete(deviceAuthorizations);
  await owner.delete(identities);
  // A reference names its vault entry: it goes before the log.
  await owner.delete(secretReferences);
  await emptyLog(owner);
  // 0.15's log, which the change path writes (unless COFFRE_TEST_LOG=0.14), gone with the rows it is of.
  await owner.delete(logChanges);
  await owner.delete(logConfig);
  // Its uses and their cap's rows: a test's reads count from none.
  await owner.delete(logUses);
  await owner.delete(logBulk);
  // And their projection (T166), from the start again.
  await owner.delete(logReads);
  await owner.delete(logReadDays);
  // Its one row put back if a test deleted it (review r6).
  const start = { through: 0n, pair: 0n, at: 0, mac: null };
  await owner.insert(logReadsCursor).values({ onlyRow: true, ...start }).onConflictDoUpdate({ target: logReadsCursor.onlyRow, set: start });
  await owner.delete(vaultGrants);
  await owner.delete(vaultMembers);
  await owner.delete(dismissedKeys);
  await owner.update(secrets).set({ currentVersionId: null });
  await owner.delete(secretVersions);
  await owner.delete(secrets);
  await owner.delete(environments);
  await owner.delete(projects);
  for (const vault of vaults) await vault.reset();
}

/**
 * With 0.15's log on: every credential's row carries its object's newest
 * change's seal, or neither has one (a row of 0.14's). A row sealed with no
 * change of its own, or one whose change was logged and its seal not written,
 * fails here. Not run at each reset: tests that plant rows around the app,
 * to see them refused, leave such rows on purpose.
 */
export async function credentialsLogged(owner: Database): Promise<void> {
  const { credentials, logChanges } = tablesOf(owner);
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
 * it was, since it takes no fence (migration 0026; Migration015.tla's
 * ExchangeOnlyIssues).
 */
export async function decisionInputs(owner: Database, except: readonly string[] = []): Promise<Record<string, string[]>> {
  const tables = tablesOf(owner);
  const inputs = { vaultMembers: tables.vaultMembers, vaultGrants: tables.vaultGrants, credentials: tables.credentials, secrets: tables.secrets,
    secretVersions: tables.secretVersions, secretReferences: tables.secretReferences, environments: tables.environments, projects: tables.projects, logConfig: tables.logConfig,
    serviceBindings: tables.serviceBindings };
  const { auditLog } = tables;
  const text = (row: object) => JSON.stringify(row, (_key, value: unknown) => (typeof value === 'bigint' ? value.toString() : value));
  const read: Record<string, string[]> = {};
  for (const [name, table] of Object.entries(inputs)) {
    const rows = (await owner.select().from(table as typeof tables.projects)) as Record<string, unknown>[];
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
  const { projects } = tablesOf(owner);
  const slug = `${service.replace(/^token:/, '')}-reads`;
  const id = randomUUID();
  await owner.insert(projects).values({ id, slug, name: slug });
  const granted = await speaking(vault).setAccess({ actor, principal: service, changes: [{ projectId: id, environmentId: null, role: 'viewer', expiresAt: null }] });
  if (!granted.ok) throw new Error(`could not give ${service} something to hold: ${granted.refusal.message}`);
  return id;
}
