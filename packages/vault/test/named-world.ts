// The worlds the tests of 0.15's use by name run in (use-named.test.ts, use.matrix.ts): a sealed world whose
// credential's token is known, a vault whose hot path's calls are counted and may be slowed, and a lock held beside.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { encrypt, freshDek } from '@coffre/core/envelope';
import type { NamedUseInput } from '@coffre/core/vault';
import { createDatabase, tablesOf, type Queryable } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { appendEntries } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import type { Input, Op } from '../src/inputs.ts';
import { vaultLogKey } from '../src/log.ts';
import { newRequestId } from '../src/use.ts';
import { openVault, prepareVault } from '../src/vault.ts';
import { absentOf, twinOf, weigh, weighInTurn, weighingSession as weighingSessionAt, type HotCall, type Weighed, type WeighingSession } from '../../../scripts/matrix-weigh.ts';
import { ENGINE, HOT_URL, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { change, CONFIG, genesis, LOG_015, ROOT, seal, SIGNING_KEY, world } from './use-world.ts';
import { freshKeyId } from './window-fixture.ts';

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
      tokenHash: tokenHash.toString('base64'), place: { project: project!.slug, environment: 'dev' }, key, accepts: { signin: true, issuers: [], passkeys: 'off' as const }, purpose: 'use',
      requestId: newRequestId(), at, deadline: at + 3000, ...extra,
    };
  };
  /** A plain value in `dev`, sealed: its text's digest in its object, no key. */
  const plain = async (text: string, name = `PLAIN_${randomUUID().slice(0, 4)}`) => {
    const t = tablesOf(db.owner);
    const id = freshKeyId(w.principal);
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
      await run(tx, sql`DELETE FROM grants WHERE principal = ${w.principal}`);
      await seal('principals', 'principal', w.principal)(tx, value);
    });
  type Grant = Extract<Input, { kind: 'principal' }>['grants'][number];
  /** Their grants as their object holds them: an environment's with its project. */
  const grantsNow = async (): Promise<Grant[]> => (await rows<{ project_id: string | null; environment_id: string | null; environment_slug: string | null; role: string; expires_at: number | string | null }>(
    db.owner, sql`SELECT project_id, environment_id, environment_slug, role, expires_at FROM grants WHERE principal = ${w.principal}`,
  )).map((g) => ({ projectId: g.project_id ?? w.project, environmentId: g.environment_id, environmentSlug: g.environment_slug, role: g.role, expiresAt: g.expires_at === null ? null : Number(g.expires_at) }));
  /** A grant of theirs on `environment`, in place of any they hold there: a change to their object, as `access.grant` makes it. */
  const grantAt = async (environment: string, role: string) => {
    const added: Grant = { projectId: w.project, environmentId: environment, environmentSlug: null, role, expiresAt: null };
    const grants = [...(await grantsNow()).filter((held) => held.environmentId !== environment), added];
    const now = Date.now();
    await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant: added },
      { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants }, async (tx, value) => {
        await run(tx, sql`DELETE FROM grants WHERE principal = ${w.principal} AND environment_id = ${environment}`);
        await run(tx, sql`INSERT INTO grants (principal, project_id, environment_id, environment_slug, role, granted_at, granted_by)
          VALUES (${w.principal}, NULL, ${environment}, NULL, ${role}, ${now}, ${ROOT})`);
        await seal('principals', 'principal', w.principal)(tx, value);
      });
  };
  /**
   * Their grant on `environment` gone, the others kept: a change to their object, as `access.revoke` makes it; or, with
   * `endsAt`, the grant there ending then, which no change will record.
   */
  const revokeAt = async (environment: string, endsAt?: number) => {
    const held = await grantsNow();
    const grants = endsAt === undefined ? held.filter((g) => g.environmentId !== environment) : held.map((g) => (g.environmentId === environment ? { ...g, expiresAt: endsAt } : g));
    const op: Op = endsAt === undefined
      ? { op: 'access.revoke', place: { projectId: w.project, environmentId: environment, environmentSlug: null } }
      : { op: 'access.grant', grant: grants.find((g) => g.environmentId === environment)! };
    await change({ kind: 'principal', id: w.principal }, op, { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants }, async (tx, value) => {
      if (endsAt === undefined) await run(tx, sql`DELETE FROM grants WHERE principal = ${w.principal} AND environment_id = ${environment}`);
      else await run(tx, sql`UPDATE grants SET expires_at = ${endsAt} WHERE principal = ${w.principal} AND environment_id = ${environment}`);
      await seal('principals', 'principal', w.principal)(tx, value);
    });
  };
  type Environment = Extract<Input, { kind: 'environment' }>;
  const environments = new Map<string, Environment>([[w.dev, w.objects.environment as Environment]]);
  /**
   * Another environment of the project, `slug`, archived or not: made as the app makes one, sealed. `parentId`, a fork of
   * that one; with `owner` too, its owner's personal config of it (T165).
   */
  const environment = async (slug: string, archived = false, { parentId = null, owner = null }: { parentId?: string | null; owner?: string | null } = {}) => {
    const id = randomUUID();
    const object: Environment = { kind: 'environment', id, projectId: w.project, slug, owner, parentId, protected: false, deleted: false, archived, projectArchived: false };
    await db.owner.insert(tablesOf(db.owner).environments).values({ id, projectId: w.project, slug, name: slug, protected: false, parentId, owner, ...(archived ? { archivedAt: new Date() } : {}) });
    await genesis({ kind: 'environment', id }, object);
    environments.set(id, object);
    return id;
  };
  /** A fork of `parent` (`dev` by default), as the app makes one: sealed, its slug `slug`. */
  const fork = (slug: string, parent = w.dev) => environment(slug, false, { parentId: parent });
  /** The caller's personal config of `of` (`dev` by default), as the app makes one (`makePersonal`): sealed, its slug generated. */
  const personal = (of = w.dev) => environment(`dev-p-${randomBytes(4).toString('hex')}`, false, { parentId: of, owner: w.principal });
  /** `key` removed in `environment`, a fork's (a dismissal, which no seal covers): what it inherits of that name, gone there. */
  const dismiss = (environment: string, key: string) => db.owner.insert(tablesOf(db.owner).dismissedKeys).values({ environmentId: environment, key, dismissedBy: ROOT });
  /** An environment renamed `slug`, as the app renames one: a change to its object. */
  /** `during`, if given, runs in the rename's transaction once it holds the fence (Postgres), before it writes. */
  const rename = async (id: string, slug: string, during?: (tx: Queryable) => Promise<void>) => {
    const object = { ...environments.get(id)!, slug };
    await change({ kind: 'environment', id }, { op: 'environment.rename', slug }, object, async (tx, value) => {
      await during?.(tx);
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
    const holder = freshKeyId(w.principal);
    const row = randomUUID();
    const appended = await db.vault.transaction((tx) => appendEntries(tx, vaultLogKey(SIGNING_KEY), [{ actor: ROOT, action: 'reference.create', decision: 'allow', metadata: '{}' }], undefined, undefined, [], true));
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
  return {
    ...w, tokenHash, project: w.project, slug: project!.slug, nameOf, ask, plain, revoke, revokeAt, revokeToken, forge, grantAt, environment, fork, personal, dismiss, rename, archive,
    credential, reference, remove, end, putBack,
  };
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
 * `work` over `items`, side by side on Postgres; on SQLite, which writes one at a time, in turn. One failing fails them
 * all, but once every other has settled: one still running past it would open a pool after its file's last `endSlowed`,
 * and the file would never exit (T246: a cell refused a connection, 53300, left 18 of its row's open for four hours).
 */
export async function each<T, R>(items: readonly T[], work: (item: T) => Promise<R>): Promise<R[]> {
  if (ENGINE !== 'postgres') {
    const done: R[] = [];
    for (const item of items) done.push(await work(item));
    return done;
  }
  const settled = await Promise.allSettled(items.map(work));
  const failed = settled.find((result) => result.status === 'rejected');
  if (failed !== undefined) throw failed.reason;
  return settled.map((result) => (result as PromiseFulfilledResult<R>).value);
}

/** The pools `slowed` opened, not yet ended: a cell made and never asked holds its own until `endSlowed`. */
const slowedPools = new Set<() => Promise<void>>();

/** Ends every pool `slowed` opened and nothing ended yet: a matrix's `finally`, so that a failure ends its file. */
export async function endSlowed(): Promise<void> {
  await Promise.all([...slowedPools].map((end) => end()));
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
  /** The last `use_credential` call sent, or `use_named_batch`, as postgres.js sends it: its text and arguments (Postgres only). */
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
    return { vault, cache: prepared.uses, statements: () => statements, last: (): HotCall | null => null, slow: (_ms: number) => {}, connect: async () => {}, end: async () => {} };
  }
  const client = postgresClient(HOT_URL, { max: options.connections ?? 4 });
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        if (typeof args[0] === 'string' && (args[0].includes('use_credential') || args[0].includes('use_named_batch'))) last = { query: args[0], args: [...((args[1] ?? []) as unknown[])] };
        if (delay === 0) return (value as (...a: unknown[]) => unknown).apply(target, args);
        // postgres.js's query is a lazy promise: sent once awaited, so `delay` holds it back.
        return sleep(delay).then(() => (value as (...a: unknown[]) => unknown).apply(target, args));
      };
    },
  });
  const prepared = await prepareVault(CONFIG, LOG_015);
  const vault = openVault(db.vault, prepared, createDatabase(pool));
  // `connect`: the pool's connection opened, and the hot path's plans made on it, by statements no count or delay sees,
  // so that a measured call's time is its own: an isolate's first, as cold as its row makes it, on a connection that has
  // served before. A connection's first call plans every form of the use functions (T131). On CI's runners, beside the
  // other cells and matrices, a cold connection's first statement took 135 ms past its delay at the median, 377 ms at
  // p90 and 585 ms at most (636 calls); a two-statement answer then took up to 2.48 s, and a slower one crossed the 3 s
  // deadline (T198). Warmed, the same took 10 ms, 51 ms and 218 ms (756 calls), and answers at most 2.15 s: that the
  // difference is planning is inferred from this comparison, not measured apart. An isolate of its
  // own makes that call, by a token no credential has: it writes nothing, and the measured isolate's map stays as its
  // row set it. It knows the log cut over, so that its call is the one statement on this connection and reads nothing
  // on the vault's pool: one that checked the cutover there, every cell at once, left the matrices unfinished on CI.
  const connect = async () => {
    await client.unsafe('SELECT 1');
    const at = Date.now();
    const prepared = await prepareVault(CONFIG, LOG_015);
    prepared.cutover = true;
    const warming = openVault(db.vault, prepared, createDatabase(client));
    await warming.useNamedMany!({
      tokenHash: randomBytes(32).toString('base64'), place: { project: 'warm', environment: 'dev' }, keys: ['WARM'],
      accepts: { signin: true, issuers: [], passkeys: 'off' as const }, purpose: 'use', at, deadline: at + 3000,
    });
  };
  // Ended once, whoever ends it first: the cell, or its file's `endSlowed`.
  let ending: Promise<void> | null = null;
  const end = () => {
    ending ??= (async () => {
      slowedPools.delete(end);
      await client.end();
    })();
    return ending;
  };
  slowedPools.add(end);
  return { vault, cache: prepared.uses, statements: () => statements, last: () => last, slow: (ms: number) => { delay = ms; }, connect, end };
}

export { absentOf, keyBlocksOf, turnsApart, twinOf, type HotCall, type Weighed } from '../../../scripts/matrix-weigh.ts';

/**
 * The shared buffers `call` reads, the least of a few runs, each of `EXPLAIN (ANALYZE, BUFFERS)` in a transaction rolled
 * back, on the hot login: what the statement's own work costs inside, which its calls and the statements counted do not
 * show (Fable's review and review r12 of D153: a form of the statement an isolate's history chose). Null on SQLite, or
 * for no call. `on`: a session to weigh it in, whose plans, made once, weigh every call it is given alike (a session of
 * its own makes them anew, on the statistics of the moment: W268 saw one call of a row read hundreds of buffers more).
 */
export async function bufferedBy(call: HotCall | null, on?: WeighingSession): Promise<number | null> {
  return (await weighed(call, on))?.buffers ?? null;
}

/** `weigh`'s buffers, of them the key's relations' blocks, and each relation's (`scripts/matrix-weigh.ts`); null on SQLite, or for no call. */
export async function weighed(call: HotCall | null, on?: WeighingSession): Promise<Weighed | null> {
  if (ENGINE !== 'postgres' || call === null) return null;
  const session = on ?? weighingSession();
  try {
    return await weigh(session, call);
  } finally {
    if (on === undefined) await session.end();
  }
}

/**
 * What `call` reads at each of a new session's first calls, at the server's planner settings (`weighInTurn`), and what
 * its controls read at each, each in a new session of its own: its twin, of a key its world never made (`twinOf`), and
 * that twin with nothing the isolate kept of the key (`absentOf`); null on SQLite, or for no call. Each of the three is
 * first called once unweighed, in a session of its own: after a batch's rolled-back writes (its standing cells',
 * weighed), a request's first scan of `bulk_cap` read 1 or 2 more blocks than any after it, the same request again
 * included, and settling the last control alone left the key's own first call to differ (docs/design/planner-defaults.md,
 * "Holding it"). A settled request still plans afresh in each weighed
 * session, so a read the planning or the call makes by the key's id shows at every weighing (a dry run reading
 * `secrets` by `p_secret` fails the matrices).
 */
export async function weighedInTurn(call: HotCall | null): Promise<{ asked: Weighed[]; twin: Weighed[]; absent: Weighed[] } | null> {
  if (ENGINE !== 'postgres' || call === null) return null;
  const controls = { twin: twinOf(call), absent: absentOf(call) };
  for (const request of [call, controls.twin, controls.absent]) await weighInTurn(HOT_URL, request, 1);
  return { asked: await weighInTurn(HOT_URL, call), twin: await weighInTurn(HOT_URL, controls.twin), absent: await weighInTurn(HOT_URL, controls.absent) };
}

/** A session of the hot login's to weigh calls in alike (`bufferedBy`): its plans made once, by the first. */
export function weighingSession(): WeighingSession {
  return weighingSessionAt(HOT_URL);
}

/** The principal's lock (0022: 1668244066, hashtext(principal)), which a key entering the cap's set takes. */
export const principalLock = (principal: string) => sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${principal}))`;

/** `holding`, of several principals' locks at once, on one connection of the vault's: a batch's cells, each its own principal. */
export const principalLocks = (principals: readonly string[]) =>
  sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(p)) FROM unnest(${sql.param([...principals])}::text[]) p`;
