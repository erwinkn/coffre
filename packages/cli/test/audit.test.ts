import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { signedInWithToken } from './fakes.ts';

const TOKEN = `coffre_cli_${'s'.repeat(43)}`;

/** An audit entry as `GET /api/audit` gives it; a server before 0.7 leaves `secrets` out. */
function entry(seq: number, fields: Record<string, unknown>) {
  return {
    seq, author: 'vault', occurredAt: '2026-10-17T10:00:00.000Z', actorType: 'user', actorId: 'ada@acme.example',
    action: 'secret.read', decision: 'allow', reason: null, detail: false, subject: null, project: 'market', environment: 'prod',
    key: null, version: null, operationId: null, relatedSeq: null, requestId: null, run: null, metadata: {}, ...fields,
  };
}

/** `coffre audit <args>` against a coffre answering every listing with `entries`, and `more` beside them; the queries it was sent. */
async function audit(t: test.TestContext, entries: unknown[], args: string[], more: Record<string, unknown> = {}) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-audit-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const queries: URLSearchParams[] = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://coffre');
    assert.equal(url.pathname, '/api/audit');
    queries.push(url.searchParams);
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ entries, ...more }));
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  signedInWithToken(home, `http://127.0.0.1:${address.port}`, TOKEN);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
  const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'audit', ...args], {
    env: { ...env, COFFRE_STATE_DIR: home, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000,
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  return { code, stdout, stderr, queries };
}

test('audit asks about the place named, a key included, and counts what a read of several listed', async (t) => {
  const listed = await audit(t, [
    entry(2, { secrets: [{ key: 'DATABASE_URL', version: 4 }, { key: 'STRIPE_KEY', version: 1 }] }),
    entry(1, { key: 'DATABASE_URL', version: 4, secrets: null }),
  ], ['market/prod/DATABASE_URL']);
  assert.equal(listed.code, 0, listed.stderr);
  assert.equal(listed.queries[0]!.get('path'), 'market/prod/DATABASE_URL');
  const lines = listed.stdout.trim().split('\n');
  assert.match(lines[0]!, /secret\.read\s+market\/prod\/DATABASE_URL$/);
  assert.match(lines[1]!, /secret\.read\s+market\/prod \(2 secrets\)$/);
});

test('audit reads a server before 0.7, whose entries say nothing of the secrets a read listed', async (t) => {
  const legacy = entry(1, { key: 'API_KEY', version: 1 });
  assert.equal('secrets' in legacy, false);
  const listed = await audit(t, [legacy], []);
  assert.equal(listed.code, 0, listed.stderr);
  assert.equal(listed.queries[0]!.get('path'), null);
  assert.match(listed.stdout, /secret\.read\s+market\/prod\/API_KEY\n$/);
});

test("audit names the CI run beside a service's entries, its sign-in in 0.15's log or 0.14's (T156)", async (t) => {
  const run = (log: string, runId: string) => ({ exchangeSeq: 7, log, claims: { repository: 'acme/api', run_id: runId, sha: '3f2a9c1e'.padEnd(40, '0') } });
  const service = { actorType: 'service', actorId: 'ci-deploy', project: null, environment: null };
  const listed = await audit(t, [
    entry(7, { ...service, log: '0.15', author: 'vault', action: 'token.exchange', run: run('0.15', '7002') }),
    entry(40, { ...service, action: 'secret.read', project: 'market', environment: 'prod', run: run('0.14', '7001') }),
  ], []);
  assert.equal(listed.code, 0, listed.stderr);
  const lines = listed.stdout.trim().split('\n');
  assert.match(lines[0]!, /service:ci-deploy \(acme\/api run 7001 at 3f2a9c1\)\s+secret\.read\s+market\/prod$/);
  assert.match(lines[1]!, /service:ci-deploy \(acme\/api run 7002 at 3f2a9c1\)\s+token\.exchange\s+-$/);
});

test("audit asks for 0.15's sealed log too, and never for the counts of what a page hides, so each page shows what it holds (T164)", async (t) => {
  for (const args of [[], ['--detail'], ['--actor', 'service:ci']]) {
    const listed = await audit(t, [entry(1, {})], args);
    assert.equal(listed.code, 0, listed.stderr);
    assert.deepEqual([listed.queries[0]!.get('sealed'), listed.queries[0]!.has('hidden')], ['1', false], args.join(' '));
  }
});

test("audit says on stderr when 0.15's reads lag, are not vouched for, or are listed elsewhere, as text or --json, which prints the entries alone (T166, review r9)", async (t) => {
  for (const [more, said] of [
    [{ reads: { through: '2026-10-17T10:00:00.000Z', behind: true } }, /Reads are sealed through 2026-10-17T10:00:00\.000Z; newer reads are not listed yet\./],
    [{ reads: { through: null, behind: true, forged: true } }, /Reads: FORGED: the vault does not vouch for how far they are listed/],
    [{ readsOmitted: 'path' }, /Reads are not listed by place/],
    [{ readsOmitted: 'scope' }, /Reads are listed to whoever reads the whole log/],
  ] as const) {
    for (const json of [false, true]) {
      const listed = await audit(t, [entry(1, {})], json ? ['--json'] : [], more);
      assert.equal(listed.code, 0, listed.stderr);
      assert.match(listed.stderr, said, `${JSON.stringify(more)}${json ? ' --json' : ''}`);
      if (json) assert.deepEqual((JSON.parse(listed.stdout) as { seq: number }[]).map((e) => e.seq), [1]);
    }
  }
  // Reads listed through the newest pair: nothing said.
  const current = await audit(t, [entry(1, {})], ['--json'], { reads: { through: '2026-10-17T10:00:00.000Z', behind: false } });
  assert.equal(current.stderr, '');
});

test("audit pages back from where a page stopped (--before), and says so on stderr: a place's page may show nothing and still go on (T175, review r1)", async (t) => {
  // A page of a place that passed over reads its reader may not see: no entry, and a next.
  const empty = await audit(t, [], ['market/dev', '--actor', 'ada@acme.example', '--json'], { more: true, next: '-:1793553278193.5120' });
  assert.equal(empty.code, 0, empty.stderr);
  assert.deepEqual(JSON.parse(empty.stdout), []);
  assert.match(empty.stderr, /Older entries: the same command with --before=-:1793553278193\.5120/);
  const older = await audit(t, [entry(1, {})], ['market/dev', '--before=-:1793553278193.5120'], { more: false, next: null });
  assert.equal(older.code, 0, older.stderr);
  assert.equal(older.queries[0]!.get('before'), '-:1793553278193.5120');
  assert.doesNotMatch(older.stderr, /Older entries/);
  // A seq of 0.14's log alone, as clients before 0.15 page; anything else is refused before a request.
  assert.equal((await audit(t, [entry(1, {})], ['--before', '5120'])).queries[0]!.get('before'), '5120');
  const wrong = await audit(t, [], ['--before', 'yesterday']);
  assert.notEqual(wrong.code, 0);
  assert.match(wrong.stderr, /--before takes the "next" an earlier page printed/);
  assert.equal(wrong.queries.length, 0);
});
