// What 0.15's change path adds to each of the app's writes that makes or ends a credential, or writes an environment or
// a key (docs/design/0.15-plan.md, "As built: PR 4b", both parts): each write, `--n` times in turn, with 0.14's log and with 0.15's, its change sealed by a Node
// checkpointer over the same database (500 ms ticks, a change asking for its seal at once, no witness). Wall time of
// the call, as the API's handler would see it, p50 / p90 / p99. Not part of the suite. On a migrated scratch
// database, as `pnpm test` makes (COFFRE_TEST_DATABASE):
//
//   COFFRE_TEST_DATABASE=<db> node --conditions=coffre:source packages/server/test/bench/writes.ts [--n 100]
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import { defineSignin, github } from '@coffre/core/identity';
import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { runCheckpointer } from '@coffre/vault/node';
import { sql } from 'drizzle-orm';

import { SigninService } from '../../src/api/signin.ts';
import { clientFor, contextFor, holdSomething, openTestDatabase, resetDatabase, testDeps, testVault } from '../api-fixture.ts';
import { TEST_VAULT_DATABASE_URL } from '../db/connections.ts';

const { values } = parseArgs({ options: { n: { type: 'string', default: '100' } } });
const N = Number(values.n);
const ROOT = 'admin@acme.example';
const SERVICE = 'token:ci';
const SIGNIN = defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })] });
const meta = () => ({ requestId: randomUUID(), sourceIp: '203.0.113.7', label: 'Firefox' });

const db = await openTestDatabase();
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
await db.owner.execute(sql`SELECT make_day(${day(Date.now())}::date), make_day(${day(Date.now() + 86_400_000)}::date)`);
await db.owner.execute(sql`UPDATE log_fence SET at_floor = ${Date.now() - 3000}`);

const q = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
const shown = (xs: number[]) => `${q(xs, 0.5).toFixed(1)} / ${q(xs, 0.9).toFixed(1)} / ${q(xs, 0.99).toFixed(1)}`;
const results = new Map<string, Record<string, string>>();

for (const log of ['0.14', '0.15'] as const) {
  await resetDatabase(db.owner);
  await db.owner.execute(sql`DELETE FROM log_checkpoints`);
  await db.owner.execute(sql`DELETE FROM log_tiles`);
  const kek = randomBytes(32);
  const dir = mkdtempSync(join(tmpdir(), 'coffre-writes-bench-'));
  const pool = postgresClient(TEST_VAULT_DATABASE_URL, { max: 4 });
  // The seed the vault signs with, from its KEK, as the vault derives it.
  const probe = testVault([ROOT], {}, { kek });
  const checkpointer = log === '0.15' ? await runCheckpointer({ database: createDatabase(pool), signingKeys: [probe.signingKey], memory: join(dir, 'memory') }) : null;
  const vault = testVault([ROOT], {}, { kek }, {}, checkpointer === null ? { log: '0.14' } : { log: '0.15', sealThrough: checkpointer.sealThrough, heldOutside: checkpointer.heldOutside });
  const deps = testDeps(db.runtime, [ROOT], { vault });
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: SIGNIN });
  deps.signin = signin;
  const root = clientFor(deps, ROOT);
  await root.members.add(SERVICE);
  await holdSomething(db.owner, vault, SERVICE, `user:${ROOT}`);
  const people = Array.from({ length: N }, (_, i) => `p${i}@acme.example`);
  for (const person of people) await root.members.add(`user:${person}`);

  const timed = async (name: string, run: (i: number) => Promise<unknown>) => {
    const samples: number[] = [];
    for (let i = 0; i < N; i += 1) {
      const t0 = performance.now();
      await run(i);
      samples.push(performance.now() - t0);
    }
    results.set(name, { ...results.get(name), [log]: shown(samples) });
  };
  const tokens: string[] = [];
  await timed('service token issued (token.create)', async () => tokens.push((await root.tokens.issue(SERVICE, { label: 'ci', expiresInDays: 1 })).id));
  await timed('service token revoked (token.revoke)', async (i) => root.tokens.revoke(SERVICE, tokens[i]!));
  const sessions: string[] = [];
  await timed('browser sign-in (sign_in)', async (i) => {
    const done = await signin.completeSignin({ provider: 'github', subject: `s${i}`, emails: [people[i]!], name: null }, meta());
    if (!done.ok) throw new Error(JSON.stringify(done));
    sessions.push(done.credential.token);
  });
  const devices: string[] = [];
  for (const person of people) {
    const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: '203.0.113.7' });
    await signin.decideDevice(await contextFor(deps, person), started.userCode, true);
    devices.push(started.deviceCode);
  }
  await timed('device login collected (sign_in, cli)', async (i) => signin.pollDevice(devices[i]!, meta()));
  await timed('sign-out (sign_out)', async (i) => signin.signOut(sessions[i]!, meta()));
  await timed('member removed, its CLI session ended (member.remove)', async (i) => root.members.remove(`user:${people[i]}`));

  // Environments and keys (part 2): one project, each write on its own environment or key.
  await root.projects.create('market');
  await root.environments.create('market/dev');
  await timed('environment created (environment.create)', async (i) => root.environments.create(`market/e${i}`));
  await timed('environment renamed (environment.update)', async (i) => root.environments.update(`market/e${i}`, { slug: `r${i}` }));
  await timed('environment archived (environment.archive)', async (i) => root.environments.update(`market/r${i}`, { archived: true }));
  await timed('environment restored (environment.restore)', async (i) => root.environments.update(`market/r${i}`, { archived: false }));
  await timed('one key written (secret.write)', async (i) => root.secrets.set('market/dev', { [`K${i}`]: `value-${i}` }));
  await timed('ten keys written at once (secret.write ×10)', async (i) => root.secrets.set('market/dev', Object.fromEntries(Array.from({ length: 10 }, (_, j) => [`T${i}_${j}`, `v${j}`]))));
  await timed('key archived (secret.archive)', async (i) => root.secrets.update(`market/dev/K${i}`, { archived: true }));
  await timed('key unarchived (secret.unarchive)', async (i) => root.secrets.update(`market/dev/K${i}`, { archived: false }));
  await timed('version restored (secret.restore)', async (i) => root.secrets.restore(`market/dev/K${i}`, 1));
  for (let i = 0; i < N; i += 1) {
    await root.secrets.set(`market/r${i}`, { A: 'a', B: 'b' });
    await root.environments.update(`market/r${i}`, { archived: true });
  }
  await timed('environment of two keys deleted (environment.delete)', async (i) => root.environments.delete(`market/r${i}`));

  await checkpointer?.stop();
  await pool.end();
  rmSync(dir, { recursive: true, force: true });
}

console.log(`each write ${N} times in turn, local Postgres 16, ms p50 / p90 / p99`);
console.log('| write | 0.14 | 0.15 |\n|---|---|---|');
for (const [name, by] of results) console.log(`| ${name} | ${by['0.14']} | ${by['0.15']} |`);
await db.close();
