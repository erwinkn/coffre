// The growth sweep's run at one size (`scripts/growth-sweep.sh`, docs/growth-sweep.md): an instance with a history
// grown `COFFRE_SWEEP_SIZE` entries long in each of the shapes that have hidden a walk before, then every request path
// it can reach, once warm and twice measured (`ROUNDS`), as the app's, the vault's and the hot path's logins, which
// auto_explain logs for this database alone, each statement's plan with its buffers. The script runs it at two sizes
// and compares the logs: a statement that reads more at the larger is one whose cost grows with history. Not a test of
// the suite's (`pnpm test` runs `*.test.ts` and `*.alone.ts`).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, hkdfSync, randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { macData, type LeafValue } from '@coffre/core/merkle';
import { defineSignin, github } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { appendEntries, logObject, type NewEntry } from '@coffre/db/log';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sql } from 'drizzle-orm';
import { runCheckpointer } from '@coffre/vault/node';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { SigninService } from '../src/api/signin.ts';
import { serveApi } from '../src/api/router.ts';
import { appLogKey } from '../src/db/audit.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { auditReadiness, walkAuditBacklog, writeAuditHeartbeat } from './watch-fixture.ts';
import { TEST_HOT_DATABASE_URL, TEST_OWNER_DATABASE_URL } from './db/connections.ts';
import { closeVaultDatabase, openVaultDatabase, withLogUnlocked, withTriggersLifted } from './db/engine.ts';
import { keepTestConnections, testPostgresPool, watched } from './db/postgres-pool.ts';
import { createClient, type CoffreClient } from '@coffre/client';

// Before any pool opens: each path's statements measured on backends that ran them before (`ROUNDS`).
keepTestConnections();
/** How long each shape of history grows: the script's two sizes, ten times apart. */
const SIZE = Number(process.env.COFFRE_SWEEP_SIZE ?? 2_000);
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
/**
 * Who audits market alone (`auditor` there): every page of theirs is a place's (`within`), the reads a whole log's reader
 * never asks; the viewer's pages answer 403 (Fable r2 of #559).
 */
const AUDITOR = 'auditor@acme.example';
/** A member the vault reported, again and again: `SIZE` findings about them. */
const TAMPERED = 'tampered@acme.example';
/** A member who read a lot, then left: an offboarding report of `SIZE` reads. */
const LEAVER = 'leaver@acme.example';
/**
 * Who leaves in each round, the last of them `LEAVER`, whom the other paths read until then: as many members of the
 * same history as rounds, so that an offboarding runs in each, the measured ones' warm (`statementsOf`, growth-sweep.mjs).
 */
const LEAVERS = ['leaver-warm@acme.example', 'leaver-first@acme.example', LEAVER];
/**
 * The rounds of request paths: one to warm the backends, then two measured. A pool's backend first runs a statement in
 * any of them, and that run reads the catalog too; a path measured twice has a warm run of each of its statements, where
 * one measured once had its run land on a backend new to it (review r3 of #559).
 */
const ROUNDS = ['warm', 'measured', 'measured'] as const;
/** Someone no member row names, whom the vault granted and refused again and again (`missingMembers`). */
const GHOST = 'user:ghost@acme.example';
/** Someone whose every entry an audit page leaves out: sign-ins alone. */
const SIGNER = 'user:signer@acme.example';
/** Who writes the audit watch's heartbeats (`watch.ts`), almost nothing else: its page is behind all of them. */
const SCHEDULER = 'system:coffre-scheduler';
const SERVICE = 'token:ci-web';
/** The runtime logins, whose statements auto_explain logs. */
const LOGINS = ['coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot'];
const ZERO16 = Buffer.alloc(16);
/** The log's own object for its rotations (`KEY_OBJECT`, @coffre/vault's log-entry.ts). */
const KEY_OBJECT = logObject('log', 'key');
/** The most rotations a log takes in its life (`ROTATIONS_HELD`, @coffre/vault's log-store.ts). */
const ROTATIONS = 246;

/**
 * The MAC of an entry of 0.15's log under the vault's key, as the checkpointer checks it before it seals one
 * (`entryMac` in packages/vault/src/log-entry.ts, which this package cannot import; bench/uses.ts makes it so too): the
 * key's 4-byte tag, then 12 bytes of HMAC over the tree's columns.
 */
function logMac(seed: Uint8Array): (tree: 'changes' | 'uses', columns: readonly LeafValue[]) => Buffer {
  const tag = Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.log.tag.v1', 4));
  const key = Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), 'coffre.log.mac.v1', 32));
  return (tree, columns) => Buffer.concat([tag, createHmac('sha256', key).update(macData(tree, columns)).digest().subarray(0, 12)]);
}

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let signinService: SigninService;
/** 0.15's hot path's pool, kept as the others are (`keepTestConnections`), and how many statements it has run. */
let hot: PostgresClient;
let hotRan = 0;
/** A CLI sign-in waiting for its approval, whose page `GET /device-logins/:code` reads. */
let deviceCode = '';

/** Turns auto_explain on for the runtime logins in this database alone, before any of them connects. */
async function explainRuntime(): Promise<void> {
  const owner = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
  const database = new URL(TEST_OWNER_DATABASE_URL).pathname.slice(1);
  const settings: Record<string, string> = {
    session_preload_libraries: 'auto_explain',
    'auto_explain.log_min_duration': '0',
    'auto_explain.log_analyze': 'on',
    'auto_explain.log_buffers': 'on',
    'auto_explain.log_timing': 'off',
    'auto_explain.log_format': 'json',
    'auto_explain.log_nested_statements': 'on',
  };
  try {
    for (const login of LOGINS) {
      for (const [name, value] of Object.entries(settings)) await owner.unsafe(`ALTER ROLE ${login} IN DATABASE "${database}" SET ${name} = '${value}'`);
    }
  } finally {
    await owner.end();
  }
}

/** A line of the log the script splits the plans by: the path whose statements follow, until the next. */
async function mark(name: string): Promise<void> {
  // On the app's login, so that auto_explain logs it, between the path before and this one.
  await rowsOf(db.runtime, sql.raw(`/* sweep:${JSON.stringify(name).slice(1, -1).replace(/\*\//g, '* /')} */ SELECT 1`));
}

/** `count` entries of `entry(i)`, under `key`, a thousand a transaction: each thousand shares one `occurred_at`. */
async function appendMany(key: Parameters<typeof appendEntries>[1], count: number, entry: (i: number) => NewEntry): Promise<void> {
  for (let done = 0; done < count; done += 1000) {
    const batch = Array.from({ length: Math.min(1000, count - done) }, (_, i) => entry(done + i));
    await withLogUnlocked(db.owner, (tx) => appendEntries(tx as never, key, batch));
  }
}

before(async () => {
  await explainRuntime();
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  // The vault's hot path on a pool of the sweep's own: one connection, kept, as the app's and the vault's are, where the
  // vault's own would open ten that close when idle; and counted, so that a reveal that never reached it fails (review
  // r4 of #559: a reveal of a caller with no way in takes 0.14's unwrap, and the hot path's reads went unmeasured).
  hot = testPostgresPool(TEST_HOT_DATABASE_URL);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], { hotDatabase: createDatabase(watched(hot, () => (hotRan += 1))) }) });
  signinService = new SigninService({ ...deps, signin: defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }) });
  deps.signin = signinService;
  const root = clientFor(deps, ROOT);
  // The instance: two projects, a fork, keys, a reference, members of each kind, a token.
  await root.projects.create('market', { name: 'Market' });
  for (const path of ['market/dev', 'market/prod']) await root.environments.create(path, { name: path });
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key', DATABASE_URL: 'postgres://fake', WEBHOOK_SECRET: 'fake-webhook' });
  await root.secrets.set('market/prod', { API_KEY: 'fake-prod-key', DEV_KEY: { ref: 'market/dev/API_KEY' } });
  await root.projects.create('shop', { name: 'Shop' });
  await root.environments.create('shop/dev', { name: 'dev' });
  await root.secrets.set('shop/dev', { SHOP_KEY: 'fake-shop-key' });
  await root.environments.create('shop/dev-eu', { name: 'dev-eu', from: 'dev', inherit: true });
  for (const member of [READER, TAMPERED, ...LEAVERS]) {
    await root.members.add(`user:${member}`);
    await root.access.set(`user:${member}`, { 'market/dev': 'viewer' });
  }
  await root.members.add(`user:${AUDITOR}`);
  await root.access.set(`user:${AUDITOR}`, { market: 'auditor' });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  await root.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 });
  await root.environments.protect('market/prod');
  deviceCode = (await signinService.startDevice({ clientLabel: 'laptop', sourceIp: null })).userCode;
  // Real uses and reads, a few, then sealed and projected, so that the pages and the checkpointer have their own.
  for (const member of [READER, ...LEAVERS]) for (let i = 0; i < 3; i += 1) await throughAccess(member).secrets.reveal('market/dev');
  assert.ok(hotRan > 0, "the seed's reveals ran no statement on the hot path: they planted no 0.15 use");
  await deps.vault.listReads();

  // What the instance's own requests wrote to 0.14's log, beside 0.15's: the shapes `grow` adds to are those.
  console.log(`sweep instance ${JSON.stringify(await rowsOf(db.owner, sql`SELECT author, action, count(*)::int AS n FROM audit_log GROUP BY 1, 2 ORDER BY 1, 2`))}`);
  await grow();
  await caughtUp();
  await settled();
});

/**
 * Every table vacuumed and analyzed, then left alone: no dead row and no missing statistic, and no autovacuum that
 * would vacuum or analyze one at a moment of its own choosing during the measured rounds, which flipped plans and
 * buffer counts by a few pages from run to run before (T200, T209, T225). Each size is a fresh clone of the template,
 * so what a sweep compares is what each size's history does to the same statements.
 */
async function settled(): Promise<void> {
  await rowsOf(db.owner, sql.raw('VACUUM (ANALYZE, PARALLEL 0)'));
  const tables = await rowsOf<{ name: string }>(db.owner, sql`
    SELECT format('%I.%I', n.nspname, c.relname) AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'`);
  for (const { name } of tables) await rowsOf(db.owner, sql.raw(`ALTER TABLE ${name} SET (autovacuum_enabled = false)`));
}

after(async () => {
  // `COFFRE_SWEEP_KEEP=1`, run outside the suite's clones: the grown database left as it is, to look into.
  if (process.env.COFFRE_SWEEP_KEEP !== '1') await resetDatabase(db.owner);
  await db.close();
  await closeVaultDatabase();
  await hot.end();
});

/**
 * The API as `id` sees it signed in behind Access, a way in (`wayIn`): its reveals are 0.15's uses, on the hot path,
 * where `clientFor`'s caller, who came in no way, reads as 0.14's do.
 */
function throughAccess(id: string): CoffreClient {
  return createClient({
    url: 'https://coffre.test',
    transport: async (request) => serveApi(request, { ...await contextFor(deps, id), session: null, access: true }),
  });
}

/**
 * The watch and the vault caught up with the grown log, as a deployment's are between its beats: what a beat or a
 * checkpoint walks is what came since the last, and a request measured after reads no backlog the growth left.
 */
async function caughtUp(): Promise<void> {
  // 0.15's log sealed to its head, a window a tick (`WINDOW_MAX`), as a deployment's checkpointer seals what comes in
  // every 500 ms: a measured tick reads what came since, and the trees' check what is above the newest pair, not the
  // whole history as a backlog.
  for (let round = 0, sealed = ''; round < 1_000; round += 1) {
    await deps.vault.listReads();
    const [newest] = await rowsOf<{ upto: string }>(db.owner, sql`SELECT coalesce(max(k.upto), 0)::text AS upto FROM log_checkpoints k`);
    if (newest!.upto === sealed) break;
    sealed = newest!.upto;
  }
  const [left] = await rowsOf<{ n: number }>(db.owner, sql`
    SELECT ((SELECT count(*) FROM log_changes c WHERE c.number > k.upto) + (SELECT count(*) FROM log_uses u WHERE u.number > k.upto))::int AS n
      FROM (SELECT coalesce(max(upto), 0) AS upto FROM log_checkpoints) k`);
  assert.equal(left!.n, 0, "the checkpointer left 0.15's seeded log unsealed: a measured tick would read it all as a backlog");
  // The vault's checkpoints, each a walk of a stretch, until one signs the head; then the watch's beats and walks.
  for (let round = 0, signed = -1; round < 1_000; round += 1) {
    const checkpoint = await deps.vault.checkpoint();
    const seq = checkpoint.ok ? Number(checkpoint.checkpoint.seq) : -1;
    if (seq === signed) break;
    signed = seq;
  }
  for (let round = 0; round < 3; round += 1) {
    await writeAuditHeartbeat(deps.db, deps.chainKey, deps.vault, deps.anchor, { warn: () => undefined });
    for (let walks = 0; walks < 10_000 && (await walkAuditBacklog(deps.db, deps.chainKey, deps.vault, deps.anchor)); walks += 1);
  }
}

/**
 * The history, `SIZE` long in each shape, oldest first, behind the instance's own entries: a long tail of another
 * member's reads in 0.14's log, a thousand to an `occurred_at`; the vault's findings about one member, 0.14's and
 * 0.15's; the access entries and refusals about someone no row names; 0.15's changes of other objects, and rotations of the log's
 * key; one member's reads, a day's; uses, spread between the checkpointer's floor and its next barrier; someone's
 * sign-ins, and an MCP client's reads of shop, which their pages hide; and, newest, the scheduler's heartbeats, which
 * an ordinary page and its own hide.
 * Entries of 0.14's log are chained and MAC'd under their author's key, and 0.15's under the vault's, which its
 * checkpointer seals (`caughtUp`), as a deployment's every 500 ms.
 */
async function grow(): Promise<void> {
  const app = appLogKey(deps.chainKey);
  const vault = deriveLogKey('vault', deps.vault.signingKey);
  await appendMany(app, SIZE, () => ({ actor: 'user:other@acme.example', action: 'secret.read', decision: 'allow', metadata: '{}' }));
  await appendMany(vault, SIZE, (i) => ({
    actor: 'system:coffre', action: 'vault.tampered', decision: 'deny', code: i % 2 === 0 ? 'mac' : 'stale', subjectPrincipal: `user:${TAMPERED}`,
    metadata: i % 2 === 0 ? '{}' : JSON.stringify({ change: randomBytes(16).toString('hex') }),
  }));
  await appendMany(vault, SIZE, (i) => ({
    actor: `user:${ROOT}`, action: 'access.grant', decision: i % 2 === 1 ? 'deny' : 'allow', code: i % 2 === 1 ? 'forbidden' : null, subjectPrincipal: GHOST, metadata: '{}',
  }));
  const now = Date.now();
  // The rotations of the log's key, as many as a log takes in its life (`ROTATIONS_HELD` in @coffre/vault: no more is
  // written through the vault's login), at both sizes; and as many changes of other objects as the size.
  const mac = logMac(deps.vault.signingKey);
  const changes = Array.from({ length: ROTATIONS + SIZE }, (_, i) => {
    const g = i + 1;
    const row = {
      at: now + g, requestId: `sweep:${g}`, object: g <= ROTATIONS ? KEY_OBJECT : randomUUID(),
      payload: g <= ROTATIONS ? JSON.stringify({ rotation: { from: `k${g}`, to: `k${g + 1}`, at: String(g) } }) : '{}',
    };
    return { ...row, mac: mac('changes', [BigInt(row.at), row.requestId, row.object, 'system:sweep', row.payload, ZERO16]) };
  });
  await withTriggersLifted(db.owner, 'log_changes', async (tx) => {
    for (let done = 0; done < changes.length; done += 5_000) {
      const batch = changes.slice(done, done + 5_000);
      await rowsOf(tx, sql`
        INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
        SELECT nextval('log_number'), r.at, r.request_id, r.object, 'system:sweep', r.payload, ${ZERO16}::bytea, r.mac
          FROM unnest(${sql.param(batch.map((c) => String(c.at)))}::bigint[], ${sql.param(batch.map((c) => c.requestId))}::text[],
                      ${sql.param(batch.map((c) => c.object))}::uuid[], ${sql.param(batch.map((c) => c.payload))}::text[],
                      ${sql.param(batch.map((c) => c.mac))}::bytea[]) AS r(at, request_id, object, payload, mac)`);
    }
  });
  const day = new Date(now).toISOString().slice(0, 10);
  await rowsOf(db.owner, sql`SELECT make_day(${day}::date)`);
  // One member's reads of market/dev's three keys, each at its version, and through market/prod's reference to its
  // API_KEY, whose version a read through it names: the same four again and again, a thousand a day, over a day for
  // every thousand (`readsBy` walks each key and version of each of their days; review r1 of #559).
  const keys = await rowsOf<{ secret: string; environment: string; project: string; version: string; credential: string }>(db.owner, sql`
    SELECT s.id::text AS secret, s.environment_id::text AS environment, s.project_id::text AS project, s.current_version_id::text AS version,
           (SELECT c.id::text FROM credentials c LIMIT 1) AS credential
      FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = s.project_id
     WHERE p.slug = 'market' AND e.slug = 'dev' ORDER BY s.key`);
  // API_KEY, first by name: the uses' key, and the source of the reference's reads.
  const [place] = keys;
  const [through] = await rowsOf<{ secret: string; environment: string; project: string }>(db.owner, sql`
    SELECT s.id::text AS secret, s.environment_id::text AS environment, s.project_id::text AS project
      FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = s.project_id
     WHERE p.slug = 'market' AND e.slug = 'prod' AND s.key = 'API_KEY'`);
  const days = Math.max(1, Math.floor(SIZE / 1_000));
  const today = Math.floor(now / 86_400_000);
  const pick = (column: 'secret' | 'environment' | 'project' | 'version') => sql.raw(`CASE g % 4 ${keys.map((key, i) => `WHEN ${i} THEN '${key[column]}'`).join(' ')} ELSE '${column === 'version' ? place!.version : through![column]}' END`);
  for (let back = days - 1; back >= 0; back -= 1) {
    const start = (today - back) * 86_400_000;
    await rowsOf(db.owner, sql`SELECT make_reads_day(${new Date(start).toISOString().slice(0, 10)}::date)`);
    for (const leaver of LEAVERS) await rowsOf(db.owner, sql`
      INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, source, source_environment, source_project, version, mac)
      SELECT nextval('log_number'), ${back === 0 ? now : start}::bigint + g, ${place!.credential}::uuid, 1, ${`user:${leaver}`},
             CAST(${pick('secret')} AS uuid), CAST(${pick('environment')} AS uuid), CAST(${pick('project')} AS uuid),
             CASE WHEN g % 4 = 3 THEN ${place!.secret}::uuid END, CASE WHEN g % 4 = 3 THEN ${place!.environment}::uuid END, CASE WHEN g % 4 = 3 THEN ${place!.project}::uuid END,
             CAST(${pick('version')} AS uuid), ${ZERO16}::bytea
        FROM generate_series(1, ${Math.min(SIZE, 1_000)}) g`);
    for (const leaver of LEAVERS) await rowsOf(db.owner, sql`INSERT INTO log_read_days (principal, day) VALUES (${`user:${leaver}`}, ${today - back}) ON CONFLICT DO NOTHING`);
  }
  // The uses, spread evenly above the floor the checkpointer reads its window from, so that it seals them
  // (`caughtUp`), and below the floor its next barrier sets, so that, sealed, no window above the newest pair reads
  // them again. How many share a millisecond depends on how long the seeding above took, so on the machine. Uses
  // sharing one `at` are T248's case, a todo test in packages/vault/test/log-store.test.ts.
  const [span] = await rowsOf<{ floor: string | null; ceiling: string }>(db.owner, sql`
    SELECT (SELECT k.at_floor FROM log_checkpoints k ORDER BY k.upto DESC LIMIT 1)::text AS floor,
           ((extract(epoch FROM clock_timestamp()) * 1000)::bigint - deadline_max())::text AS ceiling`);
  assert.ok(span!.floor !== null, 'no checkpoint to read the floor from: the reveals and listReads() above make one');
  const [floor, ceiling] = [Number(span!.floor), Number(span!.ceiling)];
  assert.ok(ceiling - floor > 1, `no time between the checkpointer's floor (${floor}) and the next barrier's (${ceiling}) to stamp uses in`);
  const uses = Array.from({ length: SIZE }, (_, i) => {
    const row = { at: floor + 1 + Math.floor((i * (ceiling - floor - 1)) / SIZE), requestId: BigInt(i + 1) };
    return { ...row, mac: mac('uses', [BigInt(row.at), row.requestId, place!.credential, place!.secret, 1, null]) };
  });
  for (const t of [uses[0]!.at, uses.at(-1)!.at]) await rowsOf(db.owner, sql`SELECT make_day(${new Date(t).toISOString().slice(0, 10)}::date)`);
  for (let done = 0; done < uses.length; done += 5_000) {
    const batch = uses.slice(done, done + 5_000);
    await rowsOf(db.owner, sql`
      INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac)
      SELECT nextval('log_number'), r.at, r.request_id, ${place!.credential}::uuid, ${place!.secret}::uuid, 1, r.mac
        FROM unnest(${sql.param(batch.map((u) => String(u.at)))}::bigint[], ${sql.param(batch.map((u) => String(u.requestId)))}::bigint[],
                    ${sql.param(batch.map((u) => u.mac))}::bytea[]) AS r(at, request_id, mac)`);
  }
  // Entries a page leaves out unless asked for detail, all of an actor's or a place's (Fable r1 of #559): someone who
  // only ever signed in; someone's reads of shop through MCP (its caller the actor, as `mcp/endpoint.ts` writes them), ; and the heartbeats.
  await appendMany(app, SIZE, () => ({ actor: SIGNER, action: 'sign_in', decision: 'allow', metadata: '{}' }));
  const [shop] = await rowsOf<{ id: string }>(db.owner, sql`SELECT id::text AS id FROM projects WHERE slug = 'shop'`);
  await appendMany(app, SIZE, () => ({ actor: 'user:mcp@acme.example', action: 'mcp.read', decision: 'allow', projectId: shop!.id, metadata: '{}' }));
  await appendMany(app, SIZE, () => ({ actor: SCHEDULER, action: 'audit.heartbeat', decision: 'allow', metadata: '{}' }));
}

/** The query a GET route cannot answer without: with none, it answers 400 before it reads anything. */
const QUERIES: Record<string, string> = { '/references': '?path=market%2Fdev', '/audit/reads': '?from=start' };

/**
 * The GET routes the sweep reaches no further than their refusal, by what an owner's request answers: the optional
 * plugins' (workloads, MCP), which the test deployment does not add, so that their statements are not measured
 * (docs/growth-sweep.md). Any other answering otherwise than 2xx fails the sweep: a route no longer reached, its reads
 * no longer measured, would pass the comparison, the same at both sizes.
 */
const UNREACHED: Record<string, number> = {
  '/members/:member/bindings': 404, '/members/:member/bindings/:id/enrollments': 501, '/workloads/lookup': 404, '/workloads/repositories': 404,
  '/freezes': 501, '/oauth/authorizations': 404, '/approvals/:id': 404, '/apps': 404,
};

/** The API's routes read as GET, from the client's own list of them: each route, and its path, its parameters filled. */
function getRoutes(): { route: string; path: string; name: string }[] {
  const api = readFileSync(fileURLToPath(new URL('../../client/src/api.ts', import.meta.url)), 'utf8');
  const values: Record<string, string> = {
    project: 'market', environment: 'dev', key: 'API_KEY', member: `user:${READER}`, id: '00000000-0000-4000-8000-000000000000', code: deviceCode, role: 'developer', folder: 'none',
  };
  const routes = [...api.matchAll(/^ {2}"GET (\/[^"]*)": \{/gm)].map((found) => found[1]!);
  // Every GET the file names, however it is laid out: one the pattern above misses is a route the sweep drops at both sizes.
  assert.equal(routes.length, api.match(/"GET \//g)?.length, 'every GET route of the client read');
  const filled = (route: string, value: (name: string) => string) => route.replace(/:(\w+)/g, (_, name: string) => value(name)) + (QUERIES[route] ?? '');
  // Named with `:code` for the device login's code, which each size draws anew: by its value, its statements would be
  // one path's at the smaller size and another's at the larger, each gone from one and new at the other.
  return routes.map((route) => ({
    route,
    path: filled(route, (name) => encodeURIComponent(values[name] ?? 'none')),
    name: filled(route, (name) => (name === 'code' ? ':code' : encodeURIComponent(values[name] ?? 'none'))),
  }));
}

/** One request to the API as `as`, its status whatever it is: a path that answers 4xx still ran its statements. */
async function get(as: string, path: string): Promise<number> {
  const response = await serveApi(new Request(`${ORIGIN}/api${path}`), await contextFor(deps, as));
  await response.arrayBuffer();
  return response.status;
}

/**
 * A request path, `run` in each round (its index in `ROUNDS`); `last`, one that changes what it reads (an offboarding),
 * run after the others, of the round's own leaver (`LEAVERS`).
 */
/** A request path the sweep measures; `before`, run before its mark, puts its state as it is in every round. */
type Path = { name: string; run: (round: number) => Promise<unknown>; before?: () => Promise<unknown>; last?: boolean };

/** The audit pages each of the owner, the viewer and the auditor of market asks. */
const PAGES = ['', '?detail=1', '?sealed=1', '?sealed=1&hidden=1', '?limit=5', `?actor=${encodeURIComponent(`user:${READER}`)}`, `?actor=${encodeURIComponent(`user:${TAMPERED}`)}`,
  '?path=market', '?path=market%2Fdev', '?path=market%2Fdev%2FAPI_KEY', '?decision=deny', '?sealed=1&path=market%2Fdev', `?sealed=1&actor=${encodeURIComponent(`user:${LEAVER}`)}`,
  // Each behind entries of its own it leaves out: the scheduler's (a system actor by its name alone, as its links name
  // it) behind its heartbeats, the signer's behind their sign-ins, shop's behind its MCP reads.
  `?actor=${SCHEDULER.slice('system:'.length)}`, `?actor=${encodeURIComponent(SIGNER)}`, '?path=shop',
  // An actor with shown entries outside market (the owner's grants, with no place), which the auditor of market's page
  // of them reads past once the page's rows are behind them (Fable r3 of #559).
  `?actor=${encodeURIComponent(`user:${ROOT}`)}`];

function paths(): Path[] {
  const root = clientFor(deps, ROOT);
  const reader = throughAccess(READER);
  const members = [ROOT, READER, TAMPERED, LEAVER].map((member) => `user:${member}`).concat(SERVICE);
  return [
    ...getRoutes().map(({ path, name }) => ({ name: `GET ${name} (owner)`, run: () => get(ROOT, path) })),
    ...getRoutes().map(({ path, name }) => ({ name: `GET ${name} (viewer)`, run: () => get(READER, path) })),
    ...PAGES.map((query) => ({ name: `GET /audit${query} (owner)`, run: () => get(ROOT, `/audit${query}`) })),
    ...PAGES.map((query) => ({ name: `GET /audit${query} (viewer)`, run: () => get(READER, `/audit${query}`) })),
    // Every page of a reader of one place is a place's page (`within`), which may walk back the log past everyone's
    // entries since the place's newest: a small limit (`?limit=5`) makes such a walk look cheap to the planner.
    ...PAGES.map((query) => ({ name: `GET /audit${query} (auditor of market)`, run: () => get(AUDITOR, `/audit${query}`) })),
    ...members.flatMap((member) => [`/members/${encodeURIComponent(member)}`, `/members/${encodeURIComponent(member)}/access`, `/members/${encodeURIComponent(member)}/tokens`]
      .map((path) => ({ name: `GET ${path} (owner)`, run: () => get(ROOT, path) }))),
    { name: 'a sign-in (members, findings)', run: () => signinService.completeSignin({ provider: 'github', subject: 'tampered', emails: [TAMPERED], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox' }) },
    { name: 'a reveal (viewer)', before: bulkPeriodPast, run: () => onHotPath(() => reader.secrets.reveal('market/dev')) },
    { name: 'a reveal of one key (viewer)', before: bulkPeriodPast, run: () => onHotPath(() => reader.secrets.reveal('market/dev', ['API_KEY'])) },
    { name: 'a key write (owner)', run: () => root.secrets.set('market/dev', { SWEPT: randomUUID() }) },
    { name: 'an access change (owner)', run: () => root.access.set(`user:${READER}`, { 'market/dev': 'viewer', 'shop/dev': 'viewer' }) },
    { name: `GET /members/${GHOST} (owner, no row)`, run: () => get(ROOT, `/members/${encodeURIComponent(GHOST)}`) },
    { name: 'a heartbeat', run: () => writeAuditHeartbeat(deps.db, deps.chainKey, deps.vault, deps.anchor, { warn: () => undefined }) },
    { name: 'readiness', run: () => auditReadiness(deps.db, deps.vault, deps.chainKey, deps.anchor) },
    { name: "the vault's checkpoint", run: () => deps.vault.checkpoint() },
    { name: "the checkpointer's tick and the reads' projection", run: () => deps.vault.listReads() },
    { name: "the checkpointer's tick and projection with a replaced key (the keyring)", run: () => replacedKeyTick() },
    // An offboarding of the member with every read, and their report after.
    { name: 'an offboarding (owner)', run: (round) => root.members.remove(`user:${LEAVERS[round]}`), last: true },
    { name: "GET the removed member's report (owner)", run: (round) => get(ROOT, `/members/${encodeURIComponent(`user:${LEAVERS[round]}`)}`), last: true },
  ];
}

/**
 * The viewer's bulk rows a period behind, so that their next reveal moves each key on: takes the principal's lock
 * shared and updates the row. A key moves on once a period (60 s at most), so a run left to the clock moved it in one
 * round or another, the update in a measured round at one size and in the warm one at the other (`GONE`).
 */
async function bulkPeriodPast(): Promise<void> {
  await rowsOf(db.owner, sql`UPDATE bulk_cap SET last = last - 1 WHERE principal = ${`user:${READER}`}`);
}

/** `reveal`, which must have run a statement on the hot path: one that ran none measured none of its reads. */
async function onHotPath(reveal: () => Promise<unknown>): Promise<void> {
  const before = hotRan;
  await reveal();
  if (hotRan === before) throw new Error('no statement on the hot path');
}

/** A tick of a checkpointer that holds a key it replaced, so that it reads the keyring, and the projector after it. */
async function replacedKeyTick(): Promise<void> {
  const memory = mkdtempSync(join(tmpdir(), 'coffre-sweep-'));
  const signer = await runCheckpointer({ database: await openVaultDatabase(), signingKeys: [deps.vault.signingKey, randomBytes(32)], memory: join(memory, 'memory'), intervalMs: 3_600_000 });
  try {
    await signer.checkpointer.tick();
    await signer.projected();
  } finally {
    await signer.stop();
    rmSync(memory, { recursive: true, force: true });
  }
}

test(`the request paths, warm, then measured twice, at ${SIZE.toLocaleString('en')} entries of each shape`, { timeout: 3_600_000 }, async () => {
  const outcomes: Record<string, string> = {};
  // Each round's answer, once when they agree: a path that answers otherwise in one round says so at both sizes.
  const answer = (name: string, now: string) => {
    outcomes[name] = outcomes[name] === undefined || outcomes[name] === now ? now : `${outcomes[name]} | ${now}`;
  };
  for (const [index, round] of ROUNDS.entries()) {
    const all = paths();
    for (const { name, run, before } of [...all.filter((path) => path.last !== true), ...all.filter((path) => path.last === true)]) {
      await before?.();
      await mark(`${round}:${name}`);
      try {
        const answered = await run(index);
        answer(name, typeof answered === 'number' ? String(answered) : 'ok');
      } catch (error) {
        // Its digits left out: a message naming a seq or a count differs between the sizes when the failure does not.
        answer(name, `failed: ${(error instanceof Error ? error.message.slice(0, 120) : String(error)).replace(/[0-9a-f-]{36}|\d+/gi, '#')}`);
      }
    }
  }
  await mark('end');
  // What each path answered, by a name the same at every size (no random id), for `growth-sweep.mjs`: a path that
  // fails at both sizes still ran its statements up to there; one that answers otherwise at the larger fails the sweep.
  // In a file: the test runner relays a run's output in chunks, and a long line comes back cut by its stderr's.
  if (process.env.COFFRE_SWEEP_OUTCOMES !== undefined) writeFileSync(process.env.COFFRE_SWEEP_OUTCOMES, JSON.stringify(outcomes));
  assert.ok(Object.keys(outcomes).length > 0);
  // A path that failed left the statement it failed on, and every one after, unmeasured at both sizes.
  assert.deepEqual(Object.entries(outcomes).filter(([, outcome]) => outcome.includes('failed:')), [], 'no path fails');
  // Each GET route reached as far as an owner reaches it, but the plugins' (`UNREACHED`).
  const astray = getRoutes().map(({ route, name }) => [route, outcomes[`GET ${name} (owner)`]] as const)
    .filter(([route, outcome]) => !(UNREACHED[route] === undefined ? /^2\d\d$/.test(outcome ?? '') : outcome === String(UNREACHED[route])));
  assert.deepEqual(astray, [], 'every GET route answers an owner as UNREACHED says');
  // The hot path's reads measured: a reveal that failed at both sizes would answer alike at both, and pass the comparison.
  for (const name of ['a reveal (viewer)', 'a reveal of one key (viewer)']) assert.equal(outcomes[name], 'ok', `${name}: ${outcomes[name]}`);
  // A scoped reader's pages measured: answered 403, they would read nothing past their caller's.
  const scoped = Object.entries(outcomes).filter(([name]) => name.startsWith('GET /audit') && name.endsWith('(auditor of market)'));
  assert.equal(scoped.length, PAGES.length, 'every page of the auditor of market measured');
  assert.deepEqual(scoped.filter(([, outcome]) => outcome !== '200'), [], 'every page of the auditor of market answers');
});
