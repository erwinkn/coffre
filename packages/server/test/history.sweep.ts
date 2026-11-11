// The history sweep's run at one size (R48; `scripts/history-sweep.sh`, docs/history-sweep.md): an instance with a
// history grown `COFFRE_SWEEP_SIZE` entries long in each of the shapes that have hidden a walk before, then every
// request path it can reach, once warm and twice measured (`ROUNDS`), as the app's, the vault's and the hot path's logins, which
// auto_explain logs for this database alone, each statement's plan with its buffers. The script runs it at two
// sizes and compares the logs: a statement that reads more at the larger is one whose cost grows with history.
// Postgres only; not a test of the suite's (`pnpm test` runs `*.test.ts` and `*.alone.ts`).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { defineSignin, github } from '@coffre/core/identity';
import { postgresClient } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { appendEntries, logObject, type NewEntry } from '@coffre/db/log';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sql } from 'drizzle-orm';
import { runCheckpointer } from '@coffre/vault/node';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { SigninService } from '../src/api/signin.ts';
import { serveApi } from '../src/api/router.ts';
import { appLogKey } from '../src/db/audit.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { auditReadiness, walkAuditBacklog, writeAuditHeartbeat } from './watch-fixture.ts';
import { TEST_OWNER_DATABASE_URL } from './db/connections.ts';
import { closeVaultDatabase, openVaultDatabase, postgresOnly, withLogUnlocked, withTriggersLifted } from './db/engine.ts';
import { keepTestConnections } from './db/postgres-pool.ts';

const POSTGRES = postgresOnly("auto_explain's plans, Postgres's");
// Before any pool opens: each path's statements measured on backends that ran them before (`ROUNDS`).
keepTestConnections();
/** How long each shape of history grows: the script's two sizes, ten times apart. */
const SIZE = Number(process.env.COFFRE_SWEEP_SIZE ?? 2_000);
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
/** An auditor of market/dev alone, whose pages read their place's entries and no others (`within`; T254). */
const AUDITOR = 'auditor@acme.example';
/** A member the vault reported, again and again: `SIZE` findings about them. */
const TAMPERED = 'tampered@acme.example';
/** A member who read a lot, then left: an offboarding report of `SIZE` reads. */
const LEAVER = 'leaver@acme.example';
/**
 * Who leaves in each round, the last of them `LEAVER`, whom the other paths read until then: as many members of the
 * same history as rounds, so that an offboarding runs in each, the measured ones' warm (`statementsOf`, history-sweep.mjs).
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
const SERVICE = 'token:ci-web';
/** The runtime logins, whose statements auto_explain logs. */
const LOGINS = ['coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot'];
const ZERO16 = Buffer.alloc(16);
/** The log's own object for its rotations (`KEY_OBJECT`, @coffre/vault's log-entry.ts). */
const KEY_OBJECT = logObject('log', 'key');
/** The most rotations a log takes in its life (`ROTATIONS_HELD`, @coffre/vault's log-store.ts). */
const ROTATIONS = 246;

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let signinService: SigninService;

/** Turns auto_explain on for the runtime logins in this database alone, before any of them connects. */
async function explainRuntime(): Promise<void> {
  const owner = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
  const database = new URL(TEST_OWNER_DATABASE_URL).pathname.slice(1);
  const settings: Record<string, string> = {
    session_preload_libraries: 'auto_explain',
    compute_query_id: 'on',
    'auto_explain.log_min_duration': '0',
    'auto_explain.log_analyze': 'on',
    'auto_explain.log_buffers': 'on',
    'auto_explain.log_timing': 'off',
    'auto_explain.log_format': 'json',
    'auto_explain.log_nested_statements': 'on',
    // The plan's query identifier, which the comparison groups by.
    'auto_explain.log_verbose': 'on',
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
  if (POSTGRES.skip) return;
  await explainRuntime();
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
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
  await root.access.set(`user:${AUDITOR}`, { 'market/dev': 'auditor' });
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  await root.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 });
  await root.environments.protect('market/prod');
  // Real uses and reads, a few, then sealed and projected, so that the pages and the checkpointer have their own.
  for (const member of [READER, ...LEAVERS]) for (let i = 0; i < 3; i += 1) await clientFor(deps, member).secrets.reveal('market/dev');
  await deps.vault.listReads();

  // What the instance's own requests wrote to 0.14's log, beside 0.15's: the shapes `grow` adds to are those.
  console.log(`sweep instance ${JSON.stringify(await rowsOf(db.owner, sql`SELECT author, action, count(*)::int AS n FROM audit_log GROUP BY 1, 2 ORDER BY 1, 2`))}`);
  await grow();
  for (const table of ['audit_log', 'log_changes', 'log_uses', 'log_reads']) await rowsOf(db.owner, sql.raw(`VACUUM (ANALYZE, PARALLEL 0) ${table}`));
  await caughtUp();
});

after(async () => {
  if (POSTGRES.skip) return;
  // `COFFRE_SWEEP_KEEP=1`, run outside the suite's clones: the grown database left as it is, to look into.
  if (process.env.COFFRE_SWEEP_KEEP !== '1') await resetDatabase(db.owner);
  await db.close();
  await closeVaultDatabase();
});

/**
 * The watch and the vault caught up with the grown log, as a deployment's are between its beats: what a beat or a
 * checkpoint walks is what came since the last, and a request measured after reads no backlog the growth left.
 */
async function caughtUp(): Promise<void> {
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
 * key; one member's reads, a day's; uses sharing one `at`, unsealed; and, newest, the heartbeats an ordinary page
 * hides. Entries of 0.14's log are chained and MAC'd under their author's key; rows of 0.15's carry no MAC of the
 * vault's, which a page marks forged and a check refuses, reading them all the same.
 */
async function grow(): Promise<void> {
  const app = appLogKey(deps.chainKey);
  const vault = deriveLogKey('vault', deps.vault.signingKey);
  await appendMany(app, SIZE, () => ({ actor: 'user:other@acme.example', action: 'secret.read', decision: 'allow', metadata: '{}' }));
  // A place's pages behind its own detail, MCP's reads of market/dev's API_KEY, and the shown entries about another
  // project, shop's writes, none of them theirs; an auditor of market/dev's behind both (T254). By someone no member row
  // names, whose entries no member's page or activity reads.
  const [api] = await rowsOf<{ secret: string; environment: string; project: string }>(db.owner, sql`
    SELECT s.id::text AS secret, s.environment_id::text AS environment, s.project_id::text AS project
      FROM secrets s JOIN environments e ON e.id = s.environment_id JOIN projects p ON p.id = s.project_id
     WHERE p.slug = 'market' AND e.slug = 'dev' AND s.key = 'API_KEY'`);
  const [shop] = await rowsOf<{ secret: string; environment: string; project: string }>(db.owner, sql`
    SELECT s.id::text AS secret, s.environment_id::text AS environment, s.project_id::text AS project
      FROM secrets s JOIN projects p ON p.id = s.project_id WHERE p.slug = 'shop' AND s.key = 'SHOP_KEY'`);
  await appendMany(app, SIZE, () => ({ actor: 'user:outsider@acme.example', action: 'mcp.read', decision: 'allow', projectId: api!.project, environmentId: api!.environment, secretId: api!.secret, metadata: '{}' }));
  await appendMany(app, SIZE, () => ({ actor: 'user:outsider@acme.example', action: 'secret.write', decision: 'allow', projectId: shop!.project, environmentId: shop!.environment, secretId: shop!.secret, metadata: '{}' }));
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
  await withTriggersLifted(db.owner, 'log_changes', (tx) => rowsOf(tx, sql`
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), ${now}::bigint + g, 'sweep:' || g, CASE WHEN g <= ${ROTATIONS} THEN ${KEY_OBJECT}::uuid ELSE gen_random_uuid() END, 'system:sweep',
           CASE WHEN g <= ${ROTATIONS} THEN json_build_object('rotation', json_build_object('from', 'k' || g, 'to', 'k' || (g + 1), 'at', g::text))::text ELSE '{}' END,
           ${ZERO16}::bytea, ${ZERO16}::bytea
      FROM generate_series(1, ${ROTATIONS + SIZE}) g`));
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
  await rowsOf(db.owner, sql`
    INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac)
    SELECT nextval('log_number'), ${Date.now()}::bigint, g, ${place!.credential}::uuid, ${place!.secret}::uuid, 1, ${ZERO16}::bytea
      FROM generate_series(1, ${SIZE}) g`);
  await appendMany(app, SIZE, () => ({ actor: 'system:coffre', action: 'audit.heartbeat', decision: 'allow', metadata: '{}' }));
}

/** The API's routes read as GET, from the client's own list of them, each with its parameters filled. */
function getRoutes(): string[] {
  const api = readFileSync(fileURLToPath(new URL('../../client/src/api.ts', import.meta.url)), 'utf8');
  const values: Record<string, string> = {
    project: 'market', environment: 'dev', key: 'API_KEY', member: `user:${READER}`, id: '00000000-0000-4000-8000-000000000000', code: 'ABCD-EFGH', role: 'developer', folder: 'none',
  };
  return [...api.matchAll(/^ {2}"GET (\/[^"]*)": \{/gm)].map((found) => found[1]!.replace(/:(\w+)/g, (_, name: string) => encodeURIComponent(values[name] ?? 'none')));
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
type Path = { name: string; run: (round: number) => Promise<unknown>; last?: boolean };

function paths(): Path[] {
  const root = clientFor(deps, ROOT);
  const reader = clientFor(deps, READER);
  const pages = ['', '?detail=1', '?sealed=1', '?sealed=1&hidden=1', '?limit=5', `?actor=${encodeURIComponent(`user:${READER}`)}`, `?actor=${encodeURIComponent(`user:${TAMPERED}`)}`,
    '?path=market', '?path=market%2Fdev', '?path=market%2Fdev%2FAPI_KEY', '?decision=deny', '?sealed=1&path=market%2Fdev', `?sealed=1&actor=${encodeURIComponent(`user:${LEAVER}`)}`];
  const members = [ROOT, READER, TAMPERED, LEAVER].map((member) => `user:${member}`).concat(SERVICE);
  return [
    ...getRoutes().map((path) => ({ name: `GET ${path} (owner)`, run: () => get(ROOT, path) })),
    ...getRoutes().map((path) => ({ name: `GET ${path} (viewer)`, run: () => get(READER, path) })),
    ...pages.map((query) => ({ name: `GET /audit${query} (owner)`, run: () => get(ROOT, `/audit${query}`) })),
    ...pages.map((query) => ({ name: `GET /audit${query} (viewer)`, run: () => get(READER, `/audit${query}`) })),
    ...pages.map((query) => ({ name: `GET /audit${query} (auditor of market/dev)`, run: () => get(AUDITOR, `/audit${query}`) })),
    ...members.flatMap((member) => [`/members/${encodeURIComponent(member)}`, `/members/${encodeURIComponent(member)}/access`, `/members/${encodeURIComponent(member)}/tokens`]
      .map((path) => ({ name: `GET ${path} (owner)`, run: () => get(ROOT, path) }))),
    { name: 'a sign-in (members, findings)', run: () => signinService.completeSignin({ provider: 'github', subject: 'tampered', emails: [TAMPERED], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'Firefox' }) },
    { name: 'a reveal (viewer)', run: () => reader.secrets.reveal('market/dev') },
    { name: 'a reveal of one key (viewer)', run: () => reader.secrets.reveal('market/dev', ['API_KEY']) },
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

test(`the request paths, warm, then measured twice, at ${SIZE.toLocaleString('en')} entries of each shape`, { ...POSTGRES, timeout: 3_600_000 }, async () => {
  const outcomes: Record<string, string> = {};
  // Each round's answer, once when they agree: a path that answers otherwise in one round says so at both sizes.
  const answer = (name: string, now: string) => {
    outcomes[name] = outcomes[name] === undefined || outcomes[name] === now ? now : `${outcomes[name]} | ${now}`;
  };
  for (const [index, round] of ROUNDS.entries()) {
    const all = paths();
    for (const { name, run } of [...all.filter((path) => path.last !== true), ...all.filter((path) => path.last === true)]) {
      await mark(`${round}:${name}`);
      try {
        const answered = await run(index);
        answer(name, typeof answered === 'number' ? String(answered) : 'ok');
      } catch (error) {
        answer(name, `failed: ${error instanceof Error ? error.message.slice(0, 120) : String(error)}`);
      }
    }
  }
  await mark('end');
  // What each path answered, by a name the same at every size (no random id), for `history-sweep.mjs`: a path that
  // fails at both sizes still ran its statements up to there; one that answers otherwise at the larger fails the sweep.
  console.log(`sweep outcomes ${JSON.stringify(outcomes)}`);
  assert.ok(Object.keys(outcomes).length > 0);
});
