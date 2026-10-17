import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { signedInWithToken } from './fakes.ts';

const TOKEN = `coffre_cli_${'g'.repeat(43)}`;

type Generation = { recipe: string; pair?: { private: string; public: string } };
type Held = { version: number; archived?: boolean; generated?: Generation | null };
type Written = { value: string; generated?: Generation };

/**
 * A coffre with one environment, app/prod, which lists its keys with their
 * recipes and keeps what each write sends. `unsaid` plays an instance
 * before 0.7, whose listing says nothing of recipes.
 */
async function instance(t: test.TestContext, held: Record<string, Held>, { unsaid = false } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-generate-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const writes: Record<string, Written>[] = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    const send = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    if (req.url !== '/api/secrets/app/prod') return send(404, { error: 'not_found', message: 'unknown project or environment' });
    if (req.method === 'GET') {
      return send(200, {
        permissions: ['secret.read', 'secret.write'],
        keys: Object.entries(held).map(([key, { version, archived = false, generated = null }]) => ({
          key, version, archived, reference: null, folder: null, updatedAt: null, updatedBy: null, ...(unsaid ? {} : { generated }),
        })),
        rotateAfterDays: null,
      });
    }
    const patch = JSON.parse(body) as Record<string, Written>;
    writes.push(patch);
    const keys: Record<string, { version: number }> = {};
    for (const [key, written] of Object.entries(patch)) {
      held[key] = { version: (held[key]?.version ?? 0) + 1, generated: written.generated ?? null };
      keys[key] = { version: held[key].version };
    }
    send(200, { operationId: 'op', keys });
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  signedInWithToken(home, `http://127.0.0.1:${address.port}`, TOKEN);

  return {
    writes,
    async coffre(args: string[]) {
      const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
      Object.assign(env, { COFFRE_STATE_DIR: home, HOME: home });
      const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
      child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
      const [code] = await once(child, 'close');
      return { code, stdout, stderr };
    },
  };
}

/** No value written went to the terminal. */
function unseen(run: { stdout: string; stderr: string }, writes: readonly Record<string, Written>[]): void {
  for (const patch of writes) {
    for (const [key, { value }] of Object.entries(patch)) {
      assert.ok(!run.stdout.includes(value) && !run.stderr.includes(value), `${key}'s value was shown`);
    }
  }
}

test('set --generate writes a value made here, with its recipe, and shows only the recipe', async (t) => {
  const coffre = await instance(t, {});
  const run = await coffre.coffre(['set', 'app/prod/SESSION_SECRET', '--generate', 'bytes:32:hex']);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout, 'SESSION_SECRET generated as version 1: 32 random bytes as 64 hex characters (bytes:32:hex)\n');
  assert.equal(coffre.writes.length, 1);
  const { SESSION_SECRET } = coffre.writes[0]!;
  assert.match(SESSION_SECRET!.value, /^[0-9a-f]{64}$/);
  assert.deepEqual(SESSION_SECRET!.generated, { recipe: 'bytes:32:hex' });
  unseen(run, coffre.writes);

  // The shortest recipe, in any case, is sent canonical.
  const again = await coffre.coffre(['set', 'app/prod/SESSION_SECRET', '--generate', 'BYTES:24']);
  assert.equal(again.code, 0, again.stderr);
  assert.match(coffre.writes[1]!.SESSION_SECRET!.value, /^[0-9A-Za-z]{33}$/);
  assert.deepEqual(coffre.writes[1]!.SESSION_SECRET!.generated, { recipe: 'bytes:24:base62' });
  assert.notEqual(coffre.writes[1]!.SESSION_SECRET!.value, SESSION_SECRET!.value);
});

test('set --generate of a key pair writes both keys in one patch, each naming both', async (t) => {
  const coffre = await instance(t, {});
  const run = await coffre.coffre(['set', 'app/prod/JWT_PRIVATE_KEY', '--generate', 'ecdsa:p-256']);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(
    run.stdout,
    'JWT_PRIVATE_KEY generated as version 1: the private key of a new ECDSA P-256 pair with JWT_PUBLIC_KEY (ecdsa:p-256)\n' +
      'JWT_PUBLIC_KEY generated as version 1: the public key of a new ECDSA P-256 pair with JWT_PRIVATE_KEY (ecdsa:p-256)\n',
  );
  const pair = { recipe: 'ecdsa:p-256', pair: { private: 'JWT_PRIVATE_KEY', public: 'JWT_PUBLIC_KEY' } };
  assert.deepEqual(Object.keys(coffre.writes[0]!), ['JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY']);
  for (const written of Object.values(coffre.writes[0]!)) assert.deepEqual(written.generated, pair);
  unseen(run, coffre.writes);

  const named = await coffre.coffre(['set', 'app/prod/SIGNER', '--generate', 'ecdh:p-384', '--public-key', 'SIGNER_PEER']);
  assert.equal(named.code, 0, named.stderr);
  assert.deepEqual(Object.keys(coffre.writes[1]!), ['SIGNER', 'SIGNER_PEER']);
});

test('set --generate refuses what makes no sense before anything is sent', async (t) => {
  const coffre = await instance(t, {});
  // A flag that cannot be used is a usage error, 2; two that cannot go together, 1, as --ref's.
  const refusals: [string[], number, RegExp][] = [
    [['--generate', 'bytes:0'], 2, /^coffre: --generate: bytes takes a length from 1 to 256, not "0": a recipe is bytes:<1-256>/],
    [['--generate', 'rsa:2048'], 2, /"rsa:2048" is no recipe/],
    [['--generate', 'bytes:32', '--public-key', 'KEY_PUBLIC'], 2, /this recipe makes one value/],
    [['--generate', 'ecdsa:p-256', '--public-key', 'KEY'], 2, /two keys need different names/],
    [['--generate', 'ecdsa:p-256', '--public-key', 'NOT-A-KEY'], 2, /"NOT-A-KEY" is no key name/],
    [['--generate', 'bytes:32', '--ref', 'app/dev/KEY'], 1, /--ref or --generate/],
    [['--public-key', 'KEY_PUBLIC'], 1, /--public-key goes with --generate/],
  ];
  for (const [flags, code, message] of refusals) {
    const run = await coffre.coffre(['set', 'app/prod/KEY', ...flags]);
    assert.equal(run.code, code, flags.join(' '));
    assert.match(run.stderr, message, flags.join(' '));
  }
  assert.deepEqual(coffre.writes, []);
});

test('regenerate makes a new value by the recipe the key has, and a key pair whole from either half', async (t) => {
  const pair = { recipe: 'ecdsa:p-384', pair: { private: 'SIGNING_KEY', public: 'VERIFY_KEY' } };
  const coffre = await instance(t, {
    TOKEN: { version: 4, generated: { recipe: 'bytes:16:base64url' } },
    SIGNING_KEY: { version: 2, generated: pair },
    VERIFY_KEY: { version: 2, generated: pair },
  });
  const run = await coffre.coffre(['regenerate', 'app/prod/TOKEN']);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.stdout, 'TOKEN regenerated as version 5: 16 random bytes as 22 base64 URL characters (bytes:16:base64url)\n');
  assert.match(coffre.writes[0]!.TOKEN!.value, /^[A-Za-z0-9_-]{22}$/);
  assert.deepEqual(coffre.writes[0]!.TOKEN!.generated, { recipe: 'bytes:16:base64url' });

  const halves = await coffre.coffre(['regenerate', 'app/prod/VERIFY_KEY']);
  assert.equal(halves.code, 0, halves.stderr);
  assert.equal(
    halves.stdout,
    'SIGNING_KEY regenerated as version 3: the private key of a new ECDSA P-384 pair with VERIFY_KEY (ecdsa:p-384)\n' +
      'VERIFY_KEY regenerated as version 3: the public key of a new ECDSA P-384 pair with SIGNING_KEY (ecdsa:p-384)\n',
  );
  assert.deepEqual(Object.keys(coffre.writes[1]!), ['SIGNING_KEY', 'VERIFY_KEY']);
  for (const written of Object.values(coffre.writes[1]!)) assert.deepEqual(written.generated, pair);
  unseen({ stdout: run.stdout + halves.stdout, stderr: run.stderr + halves.stderr }, coffre.writes);
});

test('regenerate of a key without a recipe says how it gets one, and writes nothing', async (t) => {
  const coffre = await instance(t, { TYPED: { version: 1 }, OLD: { version: 1, archived: true, generated: { recipe: 'aes:256' } } });
  const typed = await coffre.coffre(['regenerate', 'app/prod/TYPED']);
  assert.equal(typed.code, 1);
  assert.equal(
    typed.stderr,
    'coffre: app/prod/TYPED has no recipe: its value was typed, or written by hand since it was generated. `coffre set app/prod/TYPED --generate <recipe>` gives it one\n',
  );
  assert.match((await coffre.coffre(['regenerate', 'app/prod/OLD'])).stderr, /archived: unarchive it before regenerating it/);
  assert.match((await coffre.coffre(['regenerate', 'app/prod/NONE'])).stderr, /app\/prod has no key NONE/);
  const usage = await coffre.coffre(['regenerate', 'app/prod']);
  assert.match(usage.stderr, /usage: coffre regenerate/);
  assert.deepEqual(coffre.writes, []);
});

test('regenerate against an instance before recipes says to upgrade it', async (t) => {
  const coffre = await instance(t, { TOKEN: { version: 1 } }, { unsaid: true });
  const run = await coffre.coffre(['regenerate', 'app/prod/TOKEN']);
  assert.equal(run.code, 1);
  assert.match(run.stderr, /older than recipes \(coffre 0\.7\)/);
  assert.deepEqual(coffre.writes, []);
});

test('list says which values were generated, and that regenerate rotates them', async (t) => {
  const coffre = await instance(t, { TOKEN: { version: 2, generated: { recipe: 'bytes:32:base62' } }, TYPED: { version: 1 } });
  const run = await coffre.coffre(['list', 'app/prod']);
  assert.equal(run.code, 0, run.stderr);
  assert.match(run.stdout, /^TOKEN\tv2\t-\t-  \(generated, bytes:32:base62\)\n/m);
  assert.match(run.stdout, /^TYPED\tv1\t-\t-\n/m);
});
