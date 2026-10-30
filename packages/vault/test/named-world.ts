// The worlds the tests of 0.15's use by name run in (use-named.test.ts, use.matrix.ts): a sealed world whose
// credential's token is known, a vault whose hot path's calls are counted and may be slowed, and a lock held beside.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { encrypt, freshDek } from '@coffre/core/envelope';
import type { NamedUseInput } from '@coffre/core/vault';
import { createDatabase, tablesOf } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { appendEntries } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import type { Input } from '../src/inputs.ts';
import { vaultLogKey } from '../src/log.ts';
import { newRequestId } from '../src/use.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { ENGINE, HOT_URL, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { change, CONFIG, genesis, LOG_015, ROOT, seal, SIGNING_KEY, world } from './use-world.ts';

/** A world whose credential's token is known, and the names its requests use: its project's slug, `dev`, a key's name. */
export async function namedWorld(db: TestDatabase, options: Parameters<typeof world>[0] = {}) {
  const w = await world(options);
  const tokenHash = randomBytes(32);
  await run(db.owner, sql`UPDATE credentials SET token_hash = ${tokenHash} WHERE id = ${w.credentialId}`);
  const [project] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM projects WHERE id = ${w.project}`);
  const nameOf = async (id: string) => (await rows<{ key: string }>(db.owner, sql`SELECT key FROM secrets WHERE id = ${id}`))[0]!.key;
  const ask = (key: string, extra: Partial<NamedUseInput> = {}): NamedUseInput => {
    const at = Date.now();
    return {
      tokenHash: tokenHash.toString('base64'), place: { project: project!.slug, environment: 'dev' }, key, accepts: { signin: true, issuers: [] }, purpose: 'use',
      requestId: newRequestId(), at, deadline: at + 3000, ...extra,
    };
  };
  /** A plain value in `dev`, sealed: its text's digest in its object, no key. */
  const plain = async (text: string, name = `PLAIN_${randomUUID().slice(0, 4)}`) => {
    const t = tablesOf(db.owner);
    const id = randomUUID();
    const version = randomUUID();
    // Its version as the app writes a plain one: sealed as any, its text beside (app-places.test.ts, `newVersion`).
    const dek = freshDek();
    const context = { projectId: w.project, environmentId: w.dev, secretId: id };
    const sealed = encrypt(Buffer.from(text), context, dek);
    const wrapped = await CONFIG.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
    await db.owner.insert(t.secrets).values({ id, projectId: w.project, environmentId: w.dev, key: name });
    await db.owner.insert(t.secretVersions).values({
      id: version, secretId: id, version: 1, envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
      wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT, sensitive: false, plaintext: text,
    });
    await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 1 WHERE id = ${id}`);
    const object: Input = {
      kind: 'secret', id, projectId: w.project, environmentId: w.dev, version, nature: 'plain', key: null,
      digest: createHash('sha256').update(text).digest('base64'), source: null, reference: null,
    };
    await genesis({ kind: 'secret', id }, object);
    return { id, name };
  };
  /** Revoke the member's grant on dev: a change to their object, as `access.revoke` makes it. */
  const revoke = () => change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } },
    { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [] }, async (tx, value) => {
      await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w.principal}`);
      await seal('vault_members', 'principal', w.principal)(tx, value);
    });
  type Grant = Extract<Input, { kind: 'principal' }>['grants'][number];
  /** Their grants as their object holds them: an environment's with its project. */
  const grantsNow = async (): Promise<Grant[]> => (await rows<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: number | string | null }>(
    db.owner, sql`SELECT project_id, environment_id, environment_slug, role, expires_at FROM vault_grants WHERE principal = ${w.principal}`,
  )).map((g) => ({ projectId: g.project_id ?? w.project, environmentId: g.environment_id, environmentSlug: g.environment_slug, role: g.role, expiresAt: g.expires_at === null ? null : Number(g.expires_at) }));
  /** A grant of theirs on `environment`, in place of any they hold there: a change to their object, as `access.grant` makes it. */
  const grantAt = async (environment: string, role: string) => {
    const added: Grant = { projectId: w.project, environmentId: environment, environmentSlug: null, role, expiresAt: null };
    const grants = [...(await grantsNow()).filter((held) => held.environmentId !== environment), added];
    const now = Date.now();
    await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant: added },
      { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants }, async (tx, value) => {
        await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w.principal} AND environment_id = ${environment}`);
        await run(tx, sql`INSERT INTO vault_grants (principal, project_id, environment_id, environment_slug, role, granted_at, granted_by)
          VALUES (${w.principal}, NULL, ${environment}, NULL, ${role}, ${now}, ${ROOT})`);
        await seal('vault_members', 'principal', w.principal)(tx, value);
      });
  };
  type Environment = Extract<Input, { kind: 'environment' }>;
  const environments = new Map<string, Environment>([[w.dev, w.objects.environment as Environment]]);
  /** Another environment of the project, `slug`, archived or not: made as the app makes one, sealed. */
  const environment = async (slug: string, archived = false) => {
    const id = randomUUID();
    const object: Environment = { kind: 'environment', id, projectId: w.project, slug, owner: null, parentId: null, protected: false, deleted: false, archived, projectArchived: false };
    await db.owner.insert(tablesOf(db.owner).environments).values({ id, projectId: w.project, slug, name: slug, protected: false, ...(archived ? { archivedAt: new Date() } : {}) });
    await genesis({ kind: 'environment', id }, object);
    environments.set(id, object);
    return id;
  };
  /** An environment renamed `slug`, as the app renames one: a change to its object. */
  const rename = async (id: string, slug: string) => {
    const object = { ...environments.get(id)!, slug };
    await change({ kind: 'environment', id }, { op: 'environment.rename', slug }, object, async (tx, value) => {
      await run(tx, sql`UPDATE environments SET slug = ${slug} WHERE id = ${id}`);
      await seal('environments', 'id', id)(tx, value);
    });
    environments.set(id, object);
  };
  /** An environment, or its project, archived, as the app archives it: a change to its object. */
  const archive = async (id: string, project: boolean) => {
    const object = { ...environments.get(id)!, ...(project ? { projectArchived: true } : { archived: true }) };
    await change({ kind: 'environment', id }, project ? { op: 'project.archive', archived: true } : { op: 'environment.archive', archived: true }, object, async (tx, value) => {
      if (project) await run(tx, sql`UPDATE projects SET archived_at = ${new Date()} WHERE id = ${w.project}`);
      else await run(tx, sql`UPDATE environments SET archived_at = ${new Date()} WHERE id = ${id}`);
      await seal('environments', 'id', id)(tx, value);
    });
    environments.set(id, object);
  };
  /** Another credential of theirs, its own token: made as the app makes one, sealed. */
  const credential = async () => {
    const id = randomUUID();
    const expiresAt = Date.now() + 86_400_000;
    await db.owner.insert(tablesOf(db.owner).credentials).values({
      id, kind: w.principal.startsWith('user:') ? 'cli' : 'service', authMac: Buffer.alloc(32), tokenHash: randomBytes(32), tokenHint: 'hint', generation: 0, principal: w.principal, createdBy: ROOT, expiresAt: new Date(expiresAt), scope: null,
    });
    await genesis({ kind: 'credential', id }, { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), id, expiresAt });
    return id;
  };
  type Secret = Extract<Input, { kind: 'secret' }>;
  /** A reference named `name` in `dev` to a key of its own there, as the app makes one: sealed, its source's value. */
  /** A reference held in `dev` as `name`, to a key of its own in `at` (`dev` by default). */
  const reference = async (name: string, at = w.dev) => {
    const source = await w.key(`source of ${name}`, false, at);
    const holder = randomUUID();
    const row = randomUUID();
    const appended = await db.vault.transaction((tx) => appendEntries(tx, vaultLogKey(SIGNING_KEY), [{ actor: ROOT, action: 'reference.create', decision: 'allow', metadata: '{}' }]));
    await db.owner.insert(tablesOf(db.owner).secrets).values({ id: holder, projectId: w.project, environmentId: w.dev, key: name });
    await db.owner.insert(tablesOf(db.owner).secretReferences).values({
      id: row, projectId: w.project, environmentId: w.dev, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: at, sourceSecretId: source,
      createdSeq: appended.seqStart, createdBy: ROOT,
    });
    const object: Secret = { kind: 'secret', id: holder, projectId: w.project, environmentId: w.dev, version: '', nature: 'secret', key: null, digest: null, source, reference: row };
    await genesis({ kind: 'secret', id: holder }, object);
    return { holder, source, row, object };
  };
  /** A key deleted, as the app deletes one: archived, its name freed, a change to its object. */
  const remove = (id: string) => change({ kind: 'secret', id }, { op: 'secret.delete' }, null, async (tx) => {
    await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()}, key = ${`GONE_${id.replaceAll('-', '').toUpperCase()}`} WHERE id = ${id}`);
  });
  /** A reference ended, as the vault ends one: its row's end, and its object no version and no source. */
  const end = (made: Awaited<ReturnType<typeof reference>>) => {
    const ended: Secret = { ...made.object, source: null, reference: null };
    return change({ kind: 'secret', id: made.holder }, { op: 'secret.write', projectId: w.project, environmentId: w.dev, version: '', nature: 'secret', key: null, digest: null, source: null, reference: null },
      ended, async (tx, value) => {
        await run(tx, sql`UPDATE secret_references SET ended_at = ${new Date()} WHERE id = ${made.row}`);
        await seal('secrets', 'id', made.holder)(tx, value);
      });
  };
  /** A key's row put back from before a change to it, around the log: its old seal over its row now (`stale`). */
  const putBack = async (id: string) => {
    const [before] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM secrets WHERE id = ${id}`);
    const object = w.keys.find((made) => made.id === id)!.object as Secret;
    const { projectId, environmentId, version, key, digest, source, reference: of } = object;
    await change({ kind: 'secret', id }, { op: 'secret.write', projectId, environmentId, version, nature: 'sensitive', key, digest, source, reference: of },
      { ...object, nature: 'sensitive' }, seal('secrets', 'id', id));
    await run(db.owner, sql`UPDATE secrets SET seal = ${before!.seal} WHERE id = ${id}`);
  };
  /** Their credential revoked, as the app revokes one: a change to its object. */
  const revokeToken = () => change({ kind: 'credential', id: w.credentialId }, { op: 'credential.revoke' },
    { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), revoked: true }, async (tx, value) => {
      await run(tx, sql`UPDATE credentials SET revoked_at = ${new Date()} WHERE id = ${w.credentialId}`);
      await seal('credentials', 'id', w.credentialId)(tx, value);
    });
  /** An environment's seal replaced around the log, by a writer: its row no longer the vault's (`tampered`). */
  const forge = (id: string) => run(db.owner, sql`UPDATE environments SET seal = ${randomBytes(16)} WHERE id = ${id}`);
  return { ...w, tokenHash, project: w.project, slug: project!.slug, nameOf, ask, plain, revoke, revokeToken, forge, grantAt, environment, rename, archive, credential, reference, remove, end, putBack };
}

/** Hold `lock` on a connection of its own (the vault's, or with `owner` the database owner's) while `work` runs, then let it go. */
export async function holding<T>(db: TestDatabase, lock: ReturnType<typeof sql>, work: () => Promise<T>, owner = false): Promise<T> {
  // A client of its own, ended after: an idle one stays open until the test's database closes.
  const client = owner ? null : postgresClient(VAULT_URL, { max: 1 });
  const holder = client === null ? db.owner : createDatabase(client);
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const held = holder.transaction(async (tx) => {
    await run(tx, lock);
    await released;
  });
  await sleep(50);
  try {
    return await work();
  } finally {
    release();
    await held;
    await client?.end();
  }
}

/**
 * A vault over a hot path of its own, each of its calls counted as it is sent, and, on Postgres, sent `delay` ms late
 * when set: a database slow alike for every statement, as review r4 of #412 ran its probes on. On Postgres, a call is
 * a statement; on SQLite, which runs a use as a transaction of its own and the read of names as statements outside
 * one, a call is either (review d3 of #416: its statements differ by a key's shape, its calls must not).
 */
export async function slowed(db: TestDatabase, options: { connections?: number } = {}) {
  let statements = 0;
  let delay = 0;
  /** The last `use_credential` call sent, as postgres.js sends it: its text and arguments (Postgres only). */
  let last: HotCall | null = null;
  if (ENGINE === 'sqlite') {
    const hot = new Proxy(db.vault, {
      get(target, key) {
        const value: unknown = Reflect.get(target, key, target);
        if (key !== 'transaction' && key !== 'all') return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
        return (...args: unknown[]) => {
          statements += 1;
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
    const prepared = await prepareVault(CONFIG, LOG_015);
    const vault = openVault(db.vault, prepared, hot);
    return { vault, cache: prepared.uses, statements: () => statements, last: (): HotCall | null => null, slow: (_ms: number) => {}, end: async () => {} };
  }
  const pool = new Proxy(postgresClient(HOT_URL, { max: options.connections ?? 4 }), {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        if (typeof args[0] === 'string' && args[0].includes('use_credential')) last = { query: args[0], args: [...((args[1] ?? []) as unknown[])] };
        if (delay === 0) return (value as (...a: unknown[]) => unknown).apply(target, args);
        // postgres.js's query is a lazy promise: sent once awaited, so `delay` holds it back.
        return sleep(delay).then(() => (value as (...a: unknown[]) => unknown).apply(target, args));
      };
    },
  });
  const prepared = await prepareVault(CONFIG, LOG_015);
  const vault = openVault(db.vault, prepared, createDatabase(pool));
  return { vault, cache: prepared.uses, statements: () => statements, last: () => last, slow: (ms: number) => { delay = ms; }, end: () => pool.end() };
}

/** A `use_credential` call as it was sent: its text and its arguments, `$1` first. */
export type HotCall = { query: string; args: unknown[] };

/**
 * The shared buffers `call` reads, the least of a few runs, each of `EXPLAIN (ANALYZE, BUFFERS)` in a transaction rolled
 * back, on the hot login: what the statement's own work costs inside, which its calls and the statements counted do not
 * show (Fable's review and review r12 of D153: a form of the statement an isolate's history chose). Its time and deadline
 * are now's, so that it is not refused `late`; whatever it would write is rolled back. Null on SQLite, or for no call.
 * `on`: a session to weigh it in, whose plans, made once, weigh every call it is given alike (a session of its own
 * makes them anew, on the statistics of the moment: W268 saw one call of a row read hundreds of buffers more).
 */
export async function bufferedBy(call: HotCall | null, on?: ReturnType<typeof postgresClient>): Promise<number | null> {
  return (await weighed(call, on))?.buffers ?? null;
}

/**
 * The relations a key's own work reads, and nothing else a refusal reads does: its row, its version, a reference, its
 * source, its row of the cap's, an entry a cover names, each with its indexes; and the index a key's object's newest
 * change is probed in, which a refusal's other probes (its credential's, principal's, roles', places') take one path
 * each through, whatever the key. A call that reads no key (W268, NoKeyBeforeStanding) fetches as many blocks of
 * them for every key: its probes by a key it never looked up are by none, which a B-tree answers reading nothing.
 */
const KEY_TABLES = ['secrets', 'secret_versions', 'secret_references', 'log_bulk', 'log_uses'];
const KEY_INDEXES = ['log_changes_object_idx'];

/** What a weighed call read: its shared buffers, of them the blocks `KEY_TABLES` and `KEY_INDEXES` gave, and every relation's blocks. */
export type Weighed = { buffers: number; keyBlocks: number; blocks: Record<string, number> };

/**
 * `bufferedBy`'s buffers, of them the key's relations' blocks, and each relation's: a call's own, the counters' change
 * across its EXPLAIN in its transaction (`pg_stat_get_xact_blocks_fetched` answers what the backend has not yet flushed,
 * runs and calls before included). After a run unweighed, which plans what this session had not; then the run of the
 * fewest buffers of a few.
 */
export async function weighed(call: HotCall | null, on?: ReturnType<typeof postgresClient>): Promise<Weighed | null> {
  if (ENGINE !== 'postgres' || call === null) return null;
  const client = on ?? postgresClient(HOT_URL, { max: 1 });
  const counters = `SELECT c.relname AS name, pg_stat_get_xact_blocks_fetched(c.oid)::int AS n FROM pg_class c
    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'i', 'p')`;
  try {
    let least: Weighed | null = null;
    for (let run = 0; run < 4; run += 1) {
      const args = [...call.args];
      const now = Date.now();
      // `callUse`'s order: credential, key, request, at, purpose, place, MAC, deadline.
      [args[3], args[7]] = [String(now), String(now + 3000)];
      const read = await client.begin(async (tx) => {
        const before = await tx.unsafe(counters) as unknown as { name: string; n: number }[];
        const [plan] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${call.query}`, args as never[]) as unknown as { 'QUERY PLAN': { Plan: Buffers }[] }[];
        const after = await tx.unsafe(counters) as unknown as { name: string; n: number }[];
        const was = new Map(before.map((row) => [row.name, row.n]));
        const blocks = Object.fromEntries(after.map((row) => [row.name, row.n - (was.get(row.name) ?? 0)]).filter(([, n]) => n !== 0));
        throw new RolledBack({ plan: plan!['QUERY PLAN'][0]!.Plan, blocks });
      }).then(() => null, (error: unknown) => {
        if (error instanceof RolledBack) return error.read;
        throw error;
      });
      if (run === 0) continue;
      const buffers = read!.plan['Shared Hit Blocks'] + read!.plan['Shared Read Blocks'];
      if (least !== null && least.buffers <= buffers) continue;
      least = { buffers, keyBlocks: keyBlocksOf(read!.blocks), blocks: read!.blocks };
    }
    return least;
  } finally {
    if (on === undefined) await client.end();
  }
}

/**
 * The blocks of the key's relations among a call's: `KEY_TABLES`, their indexes and partitions (named for their table),
 * `KEY_INDEXES`; but those of the tables `except` names.
 */
export function keyBlocksOf(blocks: Record<string, number>, except: readonly string[] = []): number {
  const of = (name: string, table: string) => name === table || name.startsWith(`${table}_`);
  return Object.entries(blocks).reduce((sum, [name, n]) =>
    sum + ((KEY_INDEXES.includes(name) || KEY_TABLES.some((table) => of(name, table))) && !except.some((table) => of(name, table)) ? n : 0), 0);
}

type Buffers = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number };

/** A session of the hot login's to weigh calls in alike (`bufferedBy`): its plans made once, by the first. */
export function weighingSession(): ReturnType<typeof postgresClient> {
  return postgresClient(HOT_URL, { max: 1 });
}

class RolledBack extends Error {
  readonly read: { plan: Buffers; blocks: Record<string, number> };

  constructor(read: { plan: Buffers; blocks: Record<string, number> }) {
    super('rolled back');
    this.read = read;
  }
}

/** The principal's lock (0022: 1668244066, hashtext(principal)), which a key entering the cap's set takes. */
export const principalLock = (principal: string) => sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${principal}))`;
