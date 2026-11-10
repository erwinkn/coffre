// The history sweep's run at one size (R48; `scripts/history-sweep.sh`, docs/history-sweep.md): an instance with a
// history grown `COFFRE_SWEEP_SIZE` entries long in each of the shapes that have hidden a walk before, then every
// request path it can reach, once warm and once again, as the app's, the vault's and the hot path's logins, which
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
import { openVaultDatabase, postgresOnly, withLogUnlocked, withTriggersLifted } from './db/engine.ts';

const POSTGRES = postgresOnly("auto_explain's plans, Postgres's");
/** How long each shape of history grows: the script's two sizes, ten times apart. */
const SIZE = Number(process.env.COFFRE_SWEEP_SIZE ?? 2_000);
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const READER = 'reader@acme.example';
/** A member the vault reported, again and again: `SIZE` findings about them. */
const TAMPERED = 'tampered@acme.example';
/** A member who read a lot, then left: an offboarding report of `SIZE` reads. */
const LEAVER = 'leaver@acme.example';
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
  for (const member of [READER, TAMPERED, LEAVER]) {
    await root.members.add(`user:${member}`);
    await root.access.set(`user:${member}`, { 'market/dev': 'viewer' });
  }
  await root.members.add(SERVICE);
  await root.access.set(SERVICE, { 'market/dev': 'viewer' });
  await root.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 });
  await root.environments.protect('market/prod');
  // Real uses and reads, a few, then sealed and projected, so that the pages and the checkpointer have their own.
  for (const member of [READER, LEAVER]) for (let i = 0; i < 3; i += 1) await clientFor(deps, member).secrets.reveal('market/dev');
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
  await rowsOf(db.owner, sql`SELECT make_reads_day(${day}::date)`);
  const [place] = await rowsOf<{ secret: string; environment: string; project: string; credential: string }>(db.owner, sql`
    SELECT s.id::text AS secret, s.environment_id::text AS environment, s.project_id::text AS project,
           (SELECT c.id::text FROM credentials c LIMIT 1) AS credential
      FROM secrets s WHERE s.key = 'API_KEY' LIMIT 1`);
  await rowsOf(db.owner, sql`
    INSERT INTO log_reads (number, at, credential, purpose, principal, secret, environment, project, mac)
    SELECT nextval('log_number'), ${now}::bigint + g, ${place!.credential}::uuid, 1, ${`user:${LEAVER}`}, ${place!.secret}::uuid, ${place!.environment}::uuid, ${place!.project}::uuid, ${ZERO16}::bytea
      FROM generate_series(1, ${SIZE}) g`);
  await rowsOf(db.owner, sql`INSERT INTO log_read_days (principal, day) VALUES (${`user:${LEAVER}`}, ${Math.floor(now / 86_400_000)}) ON CONFLICT DO NOTHING`);
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
    project: 'market', environment: 'dev', key: 'API_KEY', member: `user:${READER}`, id: randomUUID(), code: 'ABCD-EFGH', role: 'developer', folder: 'none',
  };
  return [...api.matchAll(/^ {2}"GET (\/[^"]*)": \{/gm)].map((found) => found[1]!.replace(/:(\w+)/g, (_, name: string) => encodeURIComponent(values[name] ?? 'none')));
}

/** One request to the API as `as`, its status whatever it is: a path that answers 4xx still ran its statements. */
async function get(as: string, path: string): Promise<number> {
  const response = await serveApi(new Request(`${ORIGIN}/api${path}`), await contextFor(deps, as));
  await response.arrayBuffer();
  return response.status;
}

/** A request path; `once`, one that changes what it reads (an offboarding), run in the measured round alone, last. */
type Path = { name: string; run: () => Promise<unknown>; once?: boolean };

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
    { name: 'an offboarding (owner)', run: () => root.members.remove(`user:${LEAVER}`), once: true },
    { name: "GET the removed member's report (owner)", run: () => get(ROOT, `/members/${encodeURIComponent(`user:${LEAVER}`)}`), once: true },
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

test(`the request paths, warm, then measured, at ${SIZE.toLocaleString('en')} entries of each shape`, { ...POSTGRES, timeout: 3_600_000 }, async () => {
  const outcomes: Record<string, string> = {};
  for (const round of ['warm', 'measured'] as const) {
    for (const { name, run, once } of paths()) {
      if (once === true && round === 'warm') continue;
      await mark(`${round}:${name}`);
      try {
        const answered = await run();
        outcomes[name] = typeof answered === 'number' ? String(answered) : 'ok';
      } catch (error) {
        outcomes[name] = `failed: ${error instanceof Error ? error.message.slice(0, 120) : String(error)}`;
      }
    }
  }
  await mark('end');
  // What each path answered, for the report: a path that fails at both sizes still ran its statements up to there.
  console.log(`sweep outcomes ${JSON.stringify(outcomes)}`);
  assert.ok(Object.keys(outcomes).length > 0);
});
