// What a CI run's sign-in costs with 0.15's log, where the vault makes it (T149, R42, R44, R48): on the app's
// connection, one read, its service's bindings on the token's issuer with whether the token was spent (which the
// app's check of the token needs); then the vault's one call, `sign_in` (migration 0034), one statement, which weighs
// the binding, the account, the rate and the token on their rows and writes the credential and its change. No 0.14
// head, no entry of 0.14's. Each statement reads as many rows, and as many pages, however many credentials the binding
// issued before, however many tokens were spent, and however long both logs grow.
// Postgres only: the counts are its statements.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign as signWith } from 'node:crypto';

import { github, signin } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import type { PostgresClient } from '@coffre/db/connect';
import { localVault, type LocalVault } from '@coffre/vault/node';
import { sql } from 'drizzle-orm';

import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, sealedNow, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './db/connections.ts';
import { postgresOnly } from './db/engine.ts';
import { testPostgresPool, watched } from './db/postgres-pool.ts';
import { answer, type Pages } from './start-fixture.ts';

const POSTGRES = postgresOnly("counts the app's and the vault's Postgres statements");
const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'ci-web';
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const CLAIMS = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/market/.github/workflows/build.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' };

type Statement = { text: string; values: unknown[]; rows: number };

/** A pool that records each statement run on it while `recording`, with the rows it answered. */
class RecordingPool {
  readonly pool: PostgresClient;
  readonly client: PostgresClient;
  recording: Statement[] | null = null;

  constructor(url: string) {
    this.pool = testPostgresPool(url);
    this.client = watched(this.pool, ({ text, values, rows }) => this.recording?.push({ text, values, rows }));
  }

  /**
   * The pages `statement` touches, as this login, in a transaction rolled back: run once with `fresh` of its values,
   * so that what a backend does once is done, then measured with `fresh` again. A sign-in writes, so each run must
   * be a sign-in of its own: a new request, credential and token.
   */
  async pages(statement: Statement, fresh: (values: unknown[]) => unknown[] = (values) => values): Promise<number> {
    const rolledBack = new Error('rolled back');
    let pages = 0;
    await this.pool.begin(async (tx) => {
      for (let run = 0; run < 2; run++) {
        const [row] = await tx.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, fresh(statement.values) as never[]);
        const [{ Plan: plan }] = (row as unknown as { 'QUERY PLAN': [{ Plan: { 'Shared Hit Blocks': number; 'Shared Read Blocks': number } }] })['QUERY PLAN'];
        pages = plan['Shared Hit Blocks'] + plan['Shared Read Blocks'];
      }
      throw rolledBack;
    }).catch((error: unknown) => {
      if (error !== rolledBack) throw error;
    });
    return pages;
  }
}

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let app: RecordingPool;
let vaultPool: RecordingPool;
let vault: LocalVault;
let vaultCalls = 0;
let runtime: CoffreRuntime;
let idToken: () => string;

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  const kek = randomBytes(32);
  deps = testDeps(db.runtime, [ROOT], { vault: testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: sealedNow }) });
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev');
  await root.secrets.set('market/dev', { API_KEY: 'fake-api-key' });
  await root.members.add(`token:${SERVICE}`);
  await root.access.set(`token:${SERVICE}`, { 'market/dev': 'viewer' });

  // A CI run's ID token, from an issuer of the test's own, for the binding of its workflow.
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' };
  const published = new Map<string, unknown>([[`${ISSUER}/.well-known/openid-configuration`, { issuer: ISSUER, jwks_uri: KEYS }], [KEYS, { keys: [jwk] }]]);
  const transport: WorkloadTransport = {
    json: async (url) => {
      if (!published.has(url.href)) throw new FetchRefused(url, 'answered 404');
      return published.get(url.href);
    },
  };
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  idToken = () => {
    const now = Math.floor(Date.now() / 1000);
    const input = `${part({ alg: 'RS256', kid: 'rs-1', typ: 'JWT' })}.${part({ iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/market:ref:refs/heads/main', iat: now - 5, exp: now + 295, jti: randomUUID(), run_id: '7001', ...CLAIMS })}`;
    return `${input}.${signWith('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
  };
  const auth = signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }) } });
  const setup = createRuntime(resolveConfig({ publicUrl: ORIGIN, vault: deps.vault, auth, auditChainKey: deps.chainKey.toString('base64') }), deps.db, deps.vault, transport);
  const made = await setup.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: CLAIMS, label: 'build', replaces: [] }, { dryRun: false });
  assert.ok('binding' in made);

  // The app and the vault on pools of their own that record what they run, as a deployment's; each vault call counted.
  app = new RecordingPool(TEST_RUNTIME_DATABASE_URL);
  vaultPool = new RecordingPool(TEST_VAULT_DATABASE_URL);
  vault = await localVault({ database: createDatabase(vaultPool.client), kek: { id: 'test-kek-1', key: kek.toString('base64') }, owners: [ROOT] }, { log: '0.15', sealThrough: sealedNow, issuers: { transport } });
  const counted = new Proxy(vault, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        vaultCalls += 1;
        return (value as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  runtime = createRuntime(resolveConfig({ publicUrl: ORIGIN, vault: counted, auth, auditChainKey: deps.chainKey.toString('base64') }), createDatabase(app.client), counted, transport);
});

after(async () => {
  if (POSTGRES.skip) return;
  await vault.close();
  await Promise.all([app.pool.end(), vaultPool.pool.end()]);
  await resetDatabase(db.owner);
  await db.close();
});

/** A sign-in's statements, by pool, and its vault calls, one run before so that what a process does once is done. */
async function statements(): Promise<{ app: Statement[]; vault: Statement[]; vaultCalls: number }> {
  const signIn = async () => {
    const response = await answer(
      new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: `token:${SERVICE}`, token: idToken() }) }),
      runtime, {} as Pages, '203.0.113.9',
    );
    assert.equal(response.status, 200, await response.clone().text());
    await response.arrayBuffer();
  };
  await signIn();
  for (const pool of [app, vaultPool]) pool.recording = [];
  vaultCalls = 0;
  await signIn();
  const ran = { app: app.recording!, vault: vaultPool.recording!, vaultCalls };
  for (const pool of [app, vaultPool]) pool.recording = null;
  return ran;
}

const shown = (ran: Statement[]) => ran.map(({ text }) => text.replace(/\s+/g, ' ').trim().slice(0, 28));

/** `sign_in`'s arguments made a sign-in of their own: a request, a token spent and a credential, each new (migration 0034's order). */
function freshSignIn(values: unknown[]): unknown[] {
  const next = [...values];
  // $1 the request, $17 the token spent, $23 the credential, $26 its token's hash (migration 0037's order).
  next[0] = randomUUID();
  next[16] = randomBytes(32);
  next[22] = randomUUID();
  next[25] = randomBytes(32);
  return next;
}

test("a CI run's sign-in is one app statement and one vault call, one statement there: no 0.14 head, no 0.14 entry (T149)", POSTGRES, async () => {
  const ran = await statements();
  assert.deepEqual(shown(ran.app), ['select "service_bindings"."i'], "its service's bindings on the issuer, with whether the token was spent");
  assert.deepEqual(shown(ran.vault), ['/* writes */ SELECT sign_in('], 'the sign-in, in one statement');
  assert.equal(ran.vaultCalls, 1);
});

test("a sign-in's statements read as many rows and pages however many credentials its binding issued, tokens were spent, and the logs grow (R48)", POSTGRES, async () => {
  const measure = async () => {
    const ran = await statements();
    return [
      ...await Promise.all(ran.app.map(async (statement) => ({ text: shown([statement])[0]!, rows: statement.rows, pages: await app.pages(statement) }))),
      ...await Promise.all(ran.vault.map(async (statement) => ({ text: shown([statement])[0]!, rows: statement.rows, pages: await vaultPool.pages(statement, freshSignIn) }))),
    ];
  };
  const before = await measure();
  // Twenty thousand expired credentials the binding issued, long ago; as many tokens spent; 0.14's log a hundred times as
  // long, with unbinds and freezes of others among it; and as many changes in 0.15's log.
  const [{ id: binding }] = await db.owner.execute<{ id: string }>(sql`SELECT id::text FROM service_bindings LIMIT 1`) as unknown as [{ id: string }];
  await db.owner.execute(sql`
    INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, created_at, expires_at)
    SELECT gen_random_uuid(), 'service', sha256(convert_to('m' || g, 'UTF8')), sha256(convert_to('t' || g, 'UTF8')), 'x', 0, ${`token:${SERVICE}`}, ${`binding:${binding}`},
           now() - (g || ' minutes')::interval - interval '1 hour', now() - (g || ' minutes')::interval
      FROM generate_series(1, 20000) g`);
  await db.owner.execute(sql`INSERT INTO consumed_tokens (hash, consumed_at) SELECT sha256(convert_to('s' || g, 'UTF8')), now() - (g || ' seconds')::interval FROM generate_series(1, 20000) g`);
  await db.owner.transaction(async (tx) => {
    await tx.execute(sql`ALTER TABLE audit_log DISABLE TRIGGER USER`);
    await tx.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, project_id, environment_id, secret_id,
        secret_version_id, operation_id, request_id, source_ip, related_seq, metadata, prev_hash, mac, hash)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - row_number() OVER (ORDER BY g, e.seq), author, key_id, occurred_at - g, actor, action, decision, code,
        subject_principal, project_id, environment_id, secret_id, secret_version_id, operation_id, request_id, source_ip, related_seq, metadata, prev_hash, mac, hash
      FROM audit_log e CROSS JOIN generate_series(1, 100) g WHERE e.seq >= 0`);
    await tx.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
      SELECT (SELECT least(min(seq), 0) FROM audit_log) - g, 'app', a.key_id, a.occurred_at - g, 'user:x', CASE WHEN g % 2 = 0 THEN 'token.unbind' ELSE 'workload.freeze' END, 'allow',
             json_build_object('bindingId', gen_random_uuid(), 'target', 'binding:' || gen_random_uuid())::text, a.prev_hash, a.mac, a.hash
        FROM (SELECT key_id, occurred_at, prev_hash, mac, hash FROM audit_log WHERE author = 'app' LIMIT 1) a CROSS JOIN generate_series(1, 5000) g`);
    await tx.execute(sql`ALTER TABLE audit_log ENABLE TRIGGER USER`);
  });
  await db.owner.execute(sql`
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT -g, c.at - g, gen_random_uuid()::text, gen_random_uuid(), c.actor, c.payload, c.seal, c.mac
      FROM (SELECT at, actor, payload, seal, mac FROM log_changes ORDER BY number DESC LIMIT 1) c CROSS JOIN generate_series(1, 20000) g`);
  await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0)`);
  const grown = await measure();
  assert.deepEqual(grown.map(({ text }) => text), before.map(({ text }) => text), 'the same statements');
  for (const [i, { text, rows, pages }] of before.entries()) {
    assert.equal(grown[i]!.rows, rows, `${text} answered as many rows`);
    assert.ok(grown[i]!.pages <= 2 * pages + 16, `${text} read ${grown[i]!.pages} pages once the instance grew, ${pages} before`);
  }
});

/** A service token's issue by the Owner, through the counted pools, one run before: its statements by pool, and its vault calls. */
async function issueStatements(): Promise<{ app: Statement[]; vault: Statement[]; vaultCalls: number }> {
  const issue = async () => runtime.signin!.issueServiceToken(await contextFor(deps, ROOT), SERVICE, { label: 'deploys', expiresInDays: 30 });
  await issue();
  for (const pool of [app, vaultPool]) pool.recording = [];
  vaultCalls = 0;
  await issue();
  const ran = { app: app.recording!, vault: vaultPool.recording!, vaultCalls };
  for (const pool of [app, vaultPool]) pool.recording = null;
  return ran;
}

/** `issue_token`'s arguments made an issue of their own: a request, a credential and a token, each new (migration 0036's order). */
function freshIssue(values: unknown[]): unknown[] {
  const next = [...values];
  // $1 the request, $19 the credential, $22 its token's hash.
  next[0] = randomUUID();
  next[18] = randomUUID();
  next[21] = randomBytes(32);
  return next;
}

test("a service token's issue: the app's reads and the vault's two answers, as before; then one vault call, its write one statement, no 0.14 head (T149, PR 2)", POSTGRES, async () => {
  const ran = await issueStatements();
  // The issuer's newest policy and access entries, the places, and what sensitive values and references they hold: the
  // scope as the app works it out, by path, with what it withholds.
  assert.equal(ran.app.length, 5);
  assert.ok(ran.app.every(({ text }) => /^\s*select/i.test(text)), 'the app writes nothing');
  // `access` for the issuer and for the account (the app's checks), a snapshot each; then the issue: one snapshot (the
  // members, their grants, the policy, the setting), the places the account's grants name, and its one write.
  assert.equal(ran.vaultCalls, 3);
  assert.deepEqual(shown(ran.vault), ['WITH policy AS ( SELECT * FR', 'WITH policy AS ( SELECT * FR', 'WITH policy AS ( SELECT * FR', 'select "environments"."id", ', '/* writes */ SELECT issue_to']);
});

test("an issue's write reads as many rows and pages however long the logs and the account's history grow (R48)", POSTGRES, async () => {
  const measure = async () => {
    const write = (await issueStatements()).vault.find(({ text }) => text.includes('issue_token'))!;
    return { rows: write.rows, pages: await vaultPool.pages(write, freshIssue) };
  };
  const before = await measure();
  await db.owner.execute(sql`
    INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, created_at, expires_at)
    SELECT gen_random_uuid(), 'service', sha256(convert_to('m' || g, 'UTF8')), sha256(convert_to('i' || g, 'UTF8')), 'x', 0, ${`token:${SERVICE}`}, 'admin@acme.example',
           now() - (g || ' minutes')::interval - interval '1 hour', now() - (g || ' minutes')::interval
      FROM generate_series(1, 20000) g`);
  await db.owner.execute(sql`
    INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT -1000000 - g, c.at - g, gen_random_uuid()::text, gen_random_uuid(), c.actor, c.payload, c.seal, c.mac
      FROM (SELECT at, actor, payload, seal, mac FROM log_changes ORDER BY number DESC LIMIT 1) c CROSS JOIN generate_series(1, 20000) g`);
  await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0)`);
  const grown = await measure();
  assert.equal(grown.rows, before.rows);
  assert.ok(grown.pages <= 2 * before.pages + 16, `issue_token read ${grown.pages} pages once the instance grew, ${before.pages} before`);
});
