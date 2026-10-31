// The matrix of use.matrix.ts in @coffre/vault, through the app (T158, D153; formal/Probing.tla, NoIsFixed): what a
// person is answered, byte for byte, by `POST /api/reveals` of a key's path and through the credential proxy's
// environment URL, for each of a key's states (held, made since, used before, deleted since, never made, a reference
// broken since or repointed around the log, its row put back, a reference whose source's key or environment was
// archived since), generated over what the vault's map of the names holds (what
// they asked before: never, while they stood, after; or, asked while they stood, their place since renamed, its grant
// left them, or deleted, and its slug taken by a new one, review d4 of #416), their grant (revoked, or kept), the place
// (live, its environment archived, its project archived), the request's admission (as asked, the floor of `at` past it)
// and the cap's window (open, or passed since, so that a use of a key would take the principal's lock). Every key of a
// row they may not have must be answered alike, one `no` whatever the reason (D153), with the principal's lock held and
// every statement of the vault's hot path slowed, so that a lock waited for, or a statement more, shows as a 503; and
// in as many of the vault's calls, of the hot path's statements and of the app's own (reviews r2 and r3 of D153). Each
// cell is a project, an environment and a person of its own. On SQLite, which has neither the lock nor a hot path of
// its own to relay, the same answers and calls, and the app's statements as drizzle prepares them.
//
// A map set as it should never be (another place's key, an id never made, another credential's) is the vault's own
// state, which no request and no API of the app's reaches: use.matrix.ts sets it, in the vault (D150).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { connect, createServer, type Server } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

import { github, signin } from '@coffre/core/identity';
import { postgresClient } from '@coffre/db/connect';
import { createDatabase } from '@coffre/db';
import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { shardOf } from '../../../scripts/matrix-shard.ts';
import { resolveConfig } from '../src/config.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { checkPlugins, pluginRoute } from '../src/plugins.ts';
import { credentialProxy, header } from '../src/plugins/credential-proxy.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { clientFor, contextFor, hotDatabaseUrl, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL } from './db/connections.ts';
import { logFence } from './db/tables.ts';
import { drainBackgroundTasks } from './background-tasks.ts';
import { TEST_ENGINE } from './db/engine.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';

const KEYS = [
  'held', 'made since', 'used before', 'deleted', 'never made',
  // Used before, then its value gone: a reference broken since (review d5 of #416). The app deletes no source a reference
  // reads (`referenced`): use.matrix.ts deletes one, in the vault.
  'a reference, broken since',
  // Its source pointed elsewhere by a writer around the log, no change of the log's: its rows not as sealed, nor as the
  // vault's seals of them say (review r2 of D153): refused by name, never routed to the app's path.
  'a reference repointed around the log',
  // Its row put back, by a writer around the log, as it was before a write of it: not its newest change's.
  'its row put back since',
  // Its source's key archived since, or its source's environment: the reference reads nothing until it is back, the
  // vault's refusal by name, never the app's path (review r4 of D153). As the app lets them, its holder archived first.
  "a reference, its source's key archived since",
  "a reference, its source's environment archived since",
] as const;
/** The keys a use of theirs, while they stood, left fresh in their set. */
const USED = new Set<string>([
  'used before', 'a reference, broken since', 'a reference repointed around the log', 'its row put back since',
  "a reference, its source's key archived since", "a reference, its source's environment archived since",
]);
const ASKED = ['never', 'while standing', 'after', 'renamed, its slug reused', 'deleted, its slug reused'] as const;
/** The place: live, archived, or its row's seal replaced around the log, which a token revoked still sees past (401). */
const PLACES = ['live', 'environment archived', 'project archived', 'its seal replaced'] as const;
const ADMISSIONS = ['as asked', 'past the floor'] as const;
const WINDOWS = ['open', 'passed'] as const;
/** Their grant revoked, or kept: then the keys they may not have are the ones to answer alike (D153); or their token and handle revoked, which every key answers 401. */
const LOST = ['revoked', 'they stand', 'token revoked'] as const;
type Row = { asked: (typeof ASKED)[number]; lost: (typeof LOST)[number]; place: (typeof PLACES)[number]; admission: (typeof ADMISSIONS)[number]; window: (typeof WINDOWS)[number] };
type Key = (typeof KEYS)[number];
/** A map out of date by its place's slug taken since, over each place and admission, the window passed (a use would lock). */
const reused = (asked: Row['asked']) => asked === 'renamed, its slug reused' || asked === 'deleted, its slug reused';
const labelOf = (row: Row) => `${row.asked} / ${row.lost} / ${row.place} / ${row.admission} / window ${row.window}`;
/** Every row, generated, which CI runs in shards, a slice each (`shardOf`). */
const ROWS: Row[] = shardOf(import.meta.url, [
  ...ASKED.flatMap((asked) => PLACES.filter((place) => place !== 'its seal replaced').flatMap((place) => ADMISSIONS.flatMap((admission) =>
    (reused(asked) ? (['passed'] as const) : WINDOWS).map((window) => ({ asked, lost: 'revoked' as const, place, admission, window }))))),
  // Standing, where a key's answer may differ, as asked at a live place: those they may not have, alike.
  ...(['never', 'while standing', 'after'] as const).flatMap((asked) => WINDOWS.map((window) => ({ asked, lost: 'they stand' as const, place: 'live' as const, admission: 'as asked' as const, window }))),
  // A place whose seal a writer replaced: refused alike, and a token revoked 401 there as anywhere (review r1 of D153).
  ...(['never', 'while standing', 'after'] as const).flatMap((asked) => (['revoked', 'token revoked'] as const).flatMap((lost) => (['live', 'its seal replaced'] as const).map((place) =>
    ({ asked, lost, place, admission: 'as asked' as const, window: 'passed' as const })))).filter((row) => row.lost === 'token revoked' || row.place === 'its seal replaced'),
], labelOf);
/** A key they may have: they stand, and it is held with its value. Its answer is theirs to know of. */
const usable = (row: Row, key: Key) => row.lost === 'they stand' && (key === 'held' || key === 'made since' || key === 'used before');

/** As use.matrix.ts: 1.6 s a statement, a refusal being one whatever the vault's map holds (D153). */
const DELAY = 1600;

/**
 * The vault's hot path's database, through a relay of our own whose delay a test sets, each way half of it: none while
 * a cell is made, the row's while it is asked. Its connections are made, and kept, at no delay. `statements`: how many
 * it has carried, each ended by its Sync (or a simple Query), as the client sends them. `statementsOf`: how many of
 * them bound one of `requests` as their third parameter, `use_credential`'s `p_request`, the only statement the hot
 * path runs; and every simple Query, which binds none. So a request is counted its own statements, never one a request
 * before it sent late (review r6 of D153: a use whose deadline passed while its connection was opening sent its
 * statement once it had, inside a later request's count).
 */
async function relay(at: string): Promise<{
  url: string; delay(ms: number): void; statements(): number; statementsOf(requests: readonly string[]): number; callsOf(requests: readonly string[]): HotCall[];
  close(): Promise<void>;
}> {
  let half = 0;
  let statements = 0;
  let unbound = 0;
  const bound = new Map<string, HotCall[]>();
  const target = new URL(at);
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port), target.hostname);
    const pass = (from: NodeJS.ReadableStream, to: NodeJS.WritableStream) => from.on('data', (chunk) => {
      if (half === 0) to.write(chunk);
      else setTimeout(() => to.write(chunk), half);
    });
    // The client's messages, framed: its startup (and an SSL request before it) untyped, then each a type and a length.
    let pending = Buffer.alloc(0);
    let started = false;
    // This connection's statements as it prepared them (Parse), by name: what each Bind binds its arguments to.
    const prepared = new Map<string, string>();
    client.on('data', (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      for (;;) {
        if (!started) {
          if (pending.length < 8) return;
          const length = pending.readInt32BE(0);
          if (pending.length < length) return;
          started = pending.readInt32BE(4) !== 80877103;
          pending = pending.subarray(length);
          continue;
        }
        if (pending.length < 5) return;
        const length = pending.readInt32BE(1);
        if (pending.length < 1 + length) return;
        if (pending[0] === 0x53 || pending[0] === 0x51) statements += 1;
        if (pending[0] === 0x51) unbound += 1;
        if (pending[0] === 0x50) {
          const body = pending.subarray(5, 1 + length);
          const name = body.toString('utf8', 0, body.indexOf(0));
          const start = body.indexOf(0) + 1;
          prepared.set(name, body.toString('utf8', start, body.indexOf(0, start)));
        }
        if (pending[0] === 0x42) {
          const { statement, args } = bindOf(pending.subarray(5, 1 + length));
          const request = typeof args[2] === 'string' ? args[2] : Buffer.isBuffer(args[2]) ? args[2].readBigInt64BE(0).toString() : '';
          bound.set(request, [...(bound.get(request) ?? []), { query: prepared.get(statement) ?? '', args }]);
        }
        pending = pending.subarray(1 + length);
      }
    });
    pass(client, upstream);
    pass(upstream, client);
    const end = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('close', end).on('error', end);
    upstream.on('close', end).on('error', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = new URL(at);
  url.port = String((server.address() as { port: number }).port);
  return {
    url: url.href, delay: (ms) => { half = ms / 2; }, statements: () => statements,
    statementsOf: (requests) => unbound + requests.reduce((sum, request) => sum + (bound.get(request)?.length ?? 0), 0),
    callsOf: (requests) => requests.flatMap((request) => bound.get(request) ?? []),
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/** A statement as a Bind sent it: the text it was prepared from, and its arguments, `$1` first (text, bytes or null). */
type HotCall = { query: string; args: (string | Buffer | null)[] };

/** A Bind message's statement, by name, and its arguments: text as text, binary as its bytes, null as null. */
function bindOf(body: Buffer): { statement: string; args: (string | Buffer | null)[] } {
  let at = body.indexOf(0) + 1;
  const statement = body.toString('utf8', at, body.indexOf(0, at));
  at = body.indexOf(0, at) + 1;
  const formats = Array.from({ length: body.readInt16BE(at) }, (_, i) => body.readInt16BE(at + 2 + 2 * i));
  at += 2 + 2 * formats.length;
  const count = body.readInt16BE(at);
  at += 2;
  const args: (string | Buffer | null)[] = [];
  for (let i = 0; i < count; i += 1) {
    const length = body.readInt32BE(at);
    at += 4;
    if (length < 0) {
      args.push(null);
      continue;
    }
    const binary = (formats.length === 1 ? formats[0] : formats[i]) === 1;
    args.push(binary ? Buffer.from(body.subarray(at, at + length)) : body.toString('utf8', at, at + length));
    at += length;
  }
  return { statement, args };
}

/**
 * The shared buffers a `use_credential` call reads, the least of a few runs, each of `EXPLAIN (ANALYZE, BUFFERS)` in a
 * transaction rolled back, on the hot login: the statement's own work, which its count does not show (Fable's review and
 * review r12 of D153: a form an isolate's history chose). Its time and deadline are now's; whatever it would write is
 * rolled back. Null on SQLite, or for no call.
 */
async function bufferedBy(call: HotCall | undefined): Promise<number | null> {
  if (!POSTGRES || call === undefined) return null;
  const client = postgresClient(hotDatabaseUrl(), { max: 1 });
  try {
    let least = Infinity;
    for (let run = 0; run < 3; run += 1) {
      const args = [...call.args];
      const now = Date.now();
      // `callUse`'s order: credential, key, request, at, purpose, place, MAC, deadline.
      [args[3], args[7]] = [String(now), String(now + 3000)];
      const plan = await client.begin(async (tx) => {
        const [explained] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${call.query}`, args as never[]) as unknown as { 'QUERY PLAN': { Plan: Buffers }[] }[];
        throw new RolledBack(explained!['QUERY PLAN'][0]!.Plan);
      }).then(() => null, (error: unknown) => {
        if (error instanceof RolledBack) return error.plan;
        throw error;
      });
      least = Math.min(least, plan!['Shared Hit Blocks'] + plan!['Shared Read Blocks']);
    }
    return least;
  } finally {
    await client.end();
  }
}

type Buffers = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number };

class RolledBack extends Error {
  readonly plan: Buffers;

  constructor(plan: Buffers) {
    super('rolled back');
    this.plan = plan;
  }
}

/**
 * How many more shared buffers one refusal may read than another it is held alike to: a run's noise (a page split, a
 * heap page a world's rows spilled to). A key's own rows read before the standing was decided cost 30 to 90 more (W259:
 * 42 to 136 a refusal), a form chosen by the isolate's history 10 to 34 (Fable's review, review r12 of D153).
 */
const BUFFER_SLACK = 6;

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
/** On Postgres, the vault's hot path and the app's database, each through a relay of ours, which counts statements. */
const POSTGRES = TEST_ENGINE === 'postgres';
let hot: Awaited<ReturnType<typeof relay>> | null = null;
let app: Awaited<ReturnType<typeof relay>> | null = null;
let appPool: ReturnType<typeof postgresClient> | null = null;
/** On SQLite, the app's statements as drizzle prepares them: its own and its transactions' (each takes its session's logger). */
let sqliteStatements = 0;
const appStatements = () => (POSTGRES ? app!.statements() : sqliteStatements);
/**
 * The hot path's statements of `requests`, on Postgres: SQLite's vault opens its own connection, whose calls
 * use.matrix.ts counts.
 */
const hotStatements = (requests: readonly string[]) => (POSTGRES ? hot!.statementsOf(requests) : 0);
const vaultCalls: string[] = [];
/** The request id of each use the app asked of the vault, by name or by ids. */
const useRequests: string[] = [];
const egress = { fetch: async () => new Response(null, { status: 204 }) };

before(async () => {
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
  const kek = randomBytes(32);
  if (POSTGRES) {
    // No autovacuum on this database's tables: a row's refusals are weighed on statistics only the row's own ANALYZE
    // refreshes, before it is weighed, never while it is, as use.matrix.ts weighs its cells. An autoanalyze landing
    // mid-row (of `environments`, `vault_members`) had one cell's runs plan `use_credential`'s statements anew, and that
    // cell read 60 to 260 buffers above the rest of its row, whatever its key (CI, T170: auto_explain showed the
    // planning, and the places' statement turned from a nested loop to a hash join for every cell after).
    await rowsOf(db.owner, sql.raw(`DO $$ DECLARE t record; BEGIN
      FOR t IN SELECT c.oid::regclass AS name FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' LOOP
        EXECUTE format('ALTER TABLE %s SET (autovacuum_enabled = off)', t.name);
      END LOOP; END $$`));
    hot = await relay(hotDatabaseUrl());
    // The app's own database through a relay too, at no delay: its statements counted as the hot path's are.
    app = await relay(TEST_RUNTIME_DATABASE_URL);
    appPool = postgresClient(app.url, { max: 10 });
    deps = testDeps(createDatabase(appPool), [ROOT], { vault: testVault([ROOT], { hotDatabase: hot.url }, { kek }, {}, { log: '0.15', sealThrough: sealedNow }) });
  } else {
    const session = (db.runtime as unknown as { session: { logger: unknown; options: { logger?: unknown } } }).session;
    const counting = { logQuery: () => { sqliteStatements += 1; } };
    session.logger = counting;
    session.options.logger = counting;
    deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow }) });
  }
  // Each call the app makes of the vault, by name: its sequence says the route a request took (`routeOf`).
  for (const method of ['useNamed', 'use', 'access', 'unwrap'] as const) {
    const call = deps.vault[method] as ((...args: unknown[]) => Promise<unknown>) | undefined;
    if (call !== undefined) {
      (deps.vault as unknown as Record<string, unknown>)[method] = (...args: unknown[]) => {
        vaultCalls.push(method);
        const request = (args[0] as { requestId?: unknown } | undefined)?.requestId;
        if ((method === 'useNamed' || method === 'use') && typeof request === 'string') useRequests.push(request);
        return call.apply(deps.vault, args);
      };
    }
  }
  const config = resolveConfig({
    publicUrl: ORIGIN, vault: deps.vault, auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })] }), auditChainKey: deps.chainKey.toString('base64'),
    plugins: [credentialProxy({ credentials: { api: { upstream: 'https://api.example', inject: header('x-api-key', '{API_KEY}'), egress } }, cacheSeconds: 0 })],
  });
  runtime = createRuntime(config, deps.db, deps.vault, { json: async (url) => { throw new Error(`no fetch of ${url.href} here`); } });
  runtime.plugins = checkPlugins(config.plugins);
  deps.signin = runtime.signin!;
});

after(async () => {
  if (db === undefined) return;
  await resetDatabase(db.owner);
  await appPool?.end();
  await db.close();
  await hot?.close();
  await app?.close();
});

/** `POST /api/reveals` of a path with a bearer token: its status and body, as sent. */
async function reveal(token: string, path: string): Promise<{ status: number; body: string }> {
  const response = await fetchApi(new Request(`${ORIGIN}/api/reveals`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }),
  }), runtime, { sourceIp: null });
  return { status: response.status, body: await response.text() };
}

/** A request through the proxy with a handle: its status and body, as sent. */
async function proxied(url: string, handle: string): Promise<{ status: number; body: string }> {
  const response = await pluginRoute(new Request(`${ORIGIN}${url}`, { headers: { 'x-api-key': handle } }), runtime, '203.0.113.7')!;
  return { status: response.status, body: await response.text() };
}

let made = 0;
/** One cell, made at no delay: everything up to its requests. */
async function cell(row: Row, key: Key) {
  const root = clientFor(deps, ROOT);
  const n = made++;
  const project = `t158m${n}`;
  const place = `${project}/dev`;
  const person = `probe${n}@acme.example`;
  await root.projects.create(project, { name: project });
  await root.environments.create(place);
  if (key === 'held' || key === 'used before' || key === 'deleted' || key === 'its row put back since') await root.secrets.set(place, { API_KEY: 'sk_t158' });
  // The key's row as it is now, which a writer puts back later.
  const kept = key === 'its row put back since' ? (await rowsOf<{ id: string; current_version_id: string; current_version: number; seal: Buffer }>(db.owner, sql`SELECT s.id, s.current_version_id, s.current_version, s.seal
    FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = e.project_id WHERE p.slug = ${project} AND e.slug = 'dev' AND s.key = 'API_KEY'`))[0]! : null;
  // A reference to a key of another environment of theirs, which it reads its value from.
  const source = `${project}/source`;
  if (key.startsWith('a reference')) {
    await root.environments.create(source);
    await root.secrets.set(source, { SOURCE_KEY: 'sk_t158_source' });
    await root.secrets.set(place, { API_KEY: { ref: `${source}/SOURCE_KEY` } });
    // The source a writer points it at later, made now: no change of the log's after their asking.
    if (key === 'a reference repointed around the log') await root.secrets.set(source, { OTHER_KEY: 'sk_t158_other' });
  }
  await root.members.add(`user:${person}`);
  await root.access.set(`user:${person}`, { [place]: 'developer' });
  const context = await contextFor(deps, person);
  const issued = await runtime.signin!.issuePersonalToken(context, { label: 'script', expiresInMinutes: 60, scope: { [place]: 'developer' } });
  const handled = await runtime.signin!.issueHandle({ ...context, personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: [place] });
  const [token, handle] = [issued.token, handled.token];
  const path = `${place}/API_KEY`;
  const url = `/use/${place}/api/v1/thing`;
  // Used before: through another token of theirs, while they stood, whose use leaves the key fresh in their set.
  if (USED.has(key)) {
    const other = (await runtime.signin!.issuePersonalToken(context, { label: 'other', expiresInMinutes: 60, scope: { [place]: 'developer' } })).token;
    assert.equal((await reveal(other, path)).status, 200);
  }
  if (row.asked === 'while standing' || reused(row.asked)) {
    await reveal(token, path);
    await proxied(url, handle);
  }
  if (row.lost === 'revoked') await root.access.set(`user:${person}`, { [place]: null });
  if (row.lost === 'token revoked') {
    await runtime.signin!.revokeCredential(context, issued.id);
    await runtime.signin!.revokeCredential(context, handled.id);
  }
  if (row.asked === 'after') {
    await reveal(token, path);
    await proxied(url, handle);
  }
  if (key === 'made since') await root.secrets.set(place, { API_KEY: 'sk_t158_made' });
  if (key === 'deleted') await root.secrets.set(place, { API_KEY: null });
  if (key === 'a reference, broken since') await root.references.break(path);
  if (key === 'its row put back since') await root.secrets.set(place, { API_KEY: 'sk_t158_written' });
  if (key === "a reference, its source's key archived since" || key === "a reference, its source's environment archived since") {
    await root.secrets.update(path, { archived: true });
    if (key === "a reference, its source's key archived since") await root.secrets.update(`${source}/SOURCE_KEY`, { archived: true });
    else await root.environments.update(source, { archived: true });
    await root.secrets.update(path, { archived: false });
  }
  // Their place renamed, their grant there given back, and its slug taken by a new one, where they hold none; or deleted
  // for good, and its slug taken the same: the vault's map holds the old place, and the key's state there.
  if (row.asked === 'renamed, its slug reused') {
    await root.environments.update(place, { slug: 'dev-old' });
    await root.access.set(`user:${person}`, { [`${project}/dev-old`]: 'developer' });
    await root.environments.create(place);
  }
  if (row.asked === 'deleted, its slug reused') {
    await root.environments.update(place, { archived: true });
    await root.environments.delete(place);
    await root.environments.create(place);
  }
  if (row.place === 'environment archived') await root.environments.update(place, { archived: true });
  if (row.place === 'project archived') await root.projects.update(project, { archived: true });
  if (row.place === 'its seal replaced') {
    await rowsOf(db.owner, sql`UPDATE environments SET seal = ${randomBytes(16)} WHERE slug = 'dev' AND project_id = (SELECT id FROM projects WHERE slug = ${project})`);
  }
  // Last, around the log: the app changes nothing of a key whose rows are not as sealed (its place renamed or archived).
  if (key === 'its row put back since') {
    await rowsOf(db.owner, sql`UPDATE secrets SET current_version_id = ${kept!.current_version_id}, current_version = ${kept!.current_version}, seal = ${kept!.seal} WHERE id = ${kept!.id}`);
  }
  if (key === 'a reference repointed around the log') {
    const id = (environment: string, name: string) => sql`(SELECT s.id FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = e.project_id
      WHERE p.slug = ${project} AND e.slug = ${environment} AND s.key = ${name} AND s.archived_at IS NULL)`;
    await rowsOf(db.owner, sql`UPDATE secret_references SET source_secret_id = ${id('source', 'OTHER_KEY')}
      WHERE secret_id IN (SELECT s.id FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = e.project_id
        WHERE p.slug = ${project} AND s.key = 'API_KEY')`);
  }
  return { key, person, token, handle, path, url };
}

test(`through the app, a person is answered alike for every key they may not have, in ${ROWS.length} rows, by the API and the proxy (T158, D153)`, { timeout: 3_600_000 }, async () => {
  const differing: string[] = [];
  // The hot path's statements counted to their requests, over the run: none would mean the relay read no Bind's
  // request, and every cell would be alike for nothing.
  let attributed = 0;
  /** The widest spread of buffers within a row's refusals, over the run. */
  let widest = 0;
  // On Postgres, the principal's lock held by a connection of its own while each cell is asked; SQLite has none.
  const holder = POSTGRES ? postgresClient(TEST_RUNTIME_DATABASE_URL, { max: 1 }) : null;
  const lockDb = holder === null ? null : createDatabase(holder);
  try {
    for (const phase of [ROWS.filter((row) => row.admission === 'as asked'), ROWS.filter((row) => row.admission === 'past the floor')]) {
      for (const row of phase) {
        const cells: Awaited<ReturnType<typeof cell>>[] = [];
        for (const key of KEYS) cells.push(await cell(row, key));
        if (row.window === 'passed') for (const c of cells) await rowsOf(db.owner, sql`DELETE FROM log_bulk WHERE principal = ${`user:${c.person}`}`);
        if (row.admission === 'past the floor') await db.owner.update(logFence).set({ atFloor: Date.now() + 60_000 });
        const answers: { key: Key; api: unknown; proxy: unknown; work: unknown; sent: { api: HotCall | undefined; proxy: HotCall | undefined } }[] = [];
        try {
          for (const c of cells) {
            let release!: () => void;
            const released = new Promise<void>((resolve) => { release = resolve; });
            const held = lockDb === null ? Promise.resolve() : lockDb.transaction(async (tx) => {
              await tx.execute(sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${`user:${c.person}`}))`);
              await released;
            });
            await sleep(50);
            hot?.delay(DELAY);
            try {
              // Each answer, and its work: the vault's calls, by name, the statements on its hot path, and the app's own
              // statements, what it wrote in the background included (review r3 of D153).
              const measured = async <T>(ask: () => Promise<T>) => {
                const [calls, uses, own] = [vaultCalls.length, useRequests.length, appStatements()];
                const unbound = hotStatements([]);
                const answer = await ask();
                await drainBackgroundTasks();
                const statements = hotStatements(useRequests.slice(uses)) - unbound;
                attributed += statements;
                // Its last statement on the hot path, as sent, whose own work the row weighs once its lock is let go.
                const sent = POSTGRES ? hot!.callsOf(useRequests.slice(uses)).at(-1) : undefined;
                return { answer, calls: vaultCalls.slice(calls), statements, app: appStatements() - own, sent };
              };
              const api = await measured(() => reveal(c.token, c.path));
              const proxy = await measured(() => proxied(c.url, c.handle));
              answers.push({
                key: c.key, api: api.answer, proxy: proxy.answer, work: { api: [api.calls, api.statements, api.app], proxy: [proxy.calls, proxy.statements, proxy.app] },
                sent: { api: api.sent, proxy: proxy.sent },
              });
            } finally {
              hot?.delay(0);
              release();
              await held;
            }
          }
        } finally {
          if (row.admission === 'past the floor') await db.owner.update(logFence).set({ atFloor: Date.now() - 60_000 });
        }
        const label = labelOf(row);
        // The keys they may not have, each answered alike (D153); a key they may have is theirs to know of.
        const refused = answers.filter((a) => !usable(row, a.key));
        const [first] = refused;
        // Byte for byte, by the same route, in as many vault calls and statements (review r2 of D153).
        if (refused.some((a) => JSON.stringify(a.api) !== JSON.stringify(first!.api) || JSON.stringify(a.proxy) !== JSON.stringify(first!.proxy) || JSON.stringify(a.work) !== JSON.stringify(first!.work))) {
          differing.push(`${label}: ${refused.map((a) => `${a.key} ${JSON.stringify(a.api)} ${JSON.stringify(a.proxy)} ${JSON.stringify(a.work)}`).join(' | ')}`);
        }
        // On Postgres, as asked: each refusal's last statement in the same form, the probe's (a named call never runs the
        // cached form, `p_known`, the 12th argument); its work inside, which the statements counted do not show (Fable's
        // review, review r12 of D153), in buffers. No standing: no key read (W268, NoKeyBeforeStanding), as many for
        // every key (BUFFER_SLACK, the run's noise). Standing: a key's may cost what its shape does, a key they may know
        // of (R6), never what their asking before left (`histories`, below).
        if (POSTGRES && row.admission === 'as asked') {
          // The statistics as the row's cells left them, and none changing while they are weighed (autovacuum is off,
          // `before`): every cell's statements planned on the same.
          await rowsOf(db.owner, sql`ANALYZE`);
          for (const via of ['api', 'proxy'] as const) {
            const cached = refused.filter((a) => a.sent[via] !== undefined && a.sent[via]!.args[11] !== null);
            if (cached.length > 0) differing.push(`${label}: ${via}, the cached form for ${cached.map((a) => a.key).join(', ')}`);
            // Standing: the form alone here. The app runs no statement of its own on this path, and the vault's
            // matrix holds each refusal's buffers to the same request's from an isolate with no history.
            if (row.lost === 'they stand') continue;
            const read: { key: Key; buffers: number }[] = [];
            for (const a of refused) {
              const buffers = await bufferedBy(a.sent[via]);
              if (buffers !== null) read.push({ key: a.key, buffers });
            }
            const spread = read.length === 0 ? 0 : Math.max(...read.map((r) => r.buffers)) - Math.min(...read.map((r) => r.buffers));
            widest = Math.max(widest, spread);
            if (spread > BUFFER_SLACK) differing.push(`${label}: ${via}, buffers ${read.map((r) => `${r.key} ${r.buffers}`).join(', ')}`);
          }
        }
        // As asked, never a 503: no lock waited for, no statement more than the deadline holds.
        if (row.admission === 'as asked' && refused.some((a) => (a.api as { status: number }).status === 503 || (a.proxy as { status: number }).status === 503)) {
          differing.push(`${label}: a 503, as asked`);
        }
      }
    }
  } finally {
    await holder?.end();
  }
  if (POSTGRES) console.log(`the widest spread of buffers within a row's refusals: ${widest}`);
  assert.deepEqual(differing, []);
  if (POSTGRES) assert.ok(attributed >= ROWS.length * KEYS.length, `the hot path's statements counted to their requests: ${attributed}`);
});
