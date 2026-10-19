// What verifying the audit log costs, in CPU, as the log grows: a log of
// `--entries` built as an instance writes it (a heartbeat and a checkpoint
// every five minutes, reads and writes between), then the audit page's
// verification, and the scheduled beat, timed. Not part of the suite:
//
//   COFFRE_TEST_DATABASE=coffre_bench ./scripts/setup-test-database.sh
//   COFFRE_TEST_DATABASE=coffre_bench node --conditions=coffre:source packages/server/test/bench/audit-verify.ts --entries 7000
//
// `--keep` leaves the log in place, and `--measure` times one left by an earlier run, in a process that did not
// just write it.
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import { deriveLogKey } from '@coffre/core/audit';
import { appendEntries } from '@coffre/db/log';

import { appendAudit, type AuditEntry } from '../../src/db/audit.ts';
import { writeAuditHeartbeat } from '../../src/heartbeat.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, testVault } from '../api-fixture.ts';

const { values } = parseArgs({
  options: { entries: { type: 'string', default: '7000' }, runs: { type: 'string', default: '5' }, keep: { type: 'boolean' }, measure: { type: 'boolean' } },
});
const target = Number(values.entries);

const db = await openTestDatabase();
if (values.measure !== true) await resetDatabase(db.owner);
// The same keys each run, so that `--measure` reads what `--keep` left: a bench's, never a deployment's.
const deps = testDeps(db.runtime, ['root@acme.example'], { chainKey: Buffer.alloc(32, 7), vault: testVault(['root@acme.example'], {}, { kek: Buffer.alloc(32, 9) }) });
const root = clientFor(deps, 'root@acme.example');
await root.me();
const vaultKey = deriveLogKey('vault', deps.vault.signingKey);
const quiet = { warn: () => {} };

/** Six of the vault's reads and four of the app's entries a beat, then the beat: about twelve entries every five minutes. */
const read = (i: number) => ({
  actor: 'token:ci-deploy',
  action: 'secret.read',
  decision: 'allow' as const,
  operationId: randomUUID(),
  requestId: randomUUID(),
  metadata: JSON.stringify(i % 3 === 0
    ? { purpose: 'run', secrets: Array.from({ length: 12 }, (_, k) => ({ secretId: randomUUID(), subject: `market/prod/KEY_${k}`, version: 3 })) }
    : { subject: 'market/prod/DATABASE_URL', purpose: 'reveal', version: 7, secretId: randomUUID() }),
});
const write: AuditEntry = { actorType: 'user', actorId: 'ada@acme.example', action: 'secret.write', decision: 'allow', metadata: { key: 'DATABASE_URL', version: 8 } };

const started = Date.now();
for (let written = 0; values.measure !== true && written < target; written += 12) {
  await db.owner.transaction((tx) => appendEntries(tx, vaultKey, Array.from({ length: 6 }, (_, i) => read(written + i))));
  await db.runtime.transaction((tx) => appendAudit(tx, deps.chainKey, [write, write, write, write]));
  if (!(await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, quiet))) throw new Error('a beat failed');
  if (written % 12_000 === 0) process.stderr.write(`${written} entries, ${Math.round((Date.now() - started) / 1000)}s\n`);
}

const cpu = async (run: () => Promise<unknown>) => {
  const [usage, wall] = [process.cpuUsage(), performance.now()];
  const result = await run();
  const used = process.cpuUsage(usage);
  return { cpuMs: Math.round((used.user + used.system) / 100) / 10, wallMs: Math.round((performance.now() - wall) * 10) / 10, result };
};
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;

const runs = Number(values.runs);
// What any request costs, for scale: who is asking, checked by the app and the vault.
const me: { cpuMs: number; wallMs: number }[] = [];
for (let i = 0; i < runs; i++) {
  const { result: _, ...took } = await cpu(() => root.me());
  me.push(took);
}
const page: { cpuMs: number; wallMs: number }[] = [];
let verdict: unknown;
for (let i = 0; i < runs; i++) {
  const { result, ...took } = await cpu(() => root.audit.verify());
  page.push(took);
  verdict = result;
}
const beat: { cpuMs: number; wallMs: number }[] = [];
for (let i = 0; i < runs; i++) {
  await db.owner.transaction((tx) => appendEntries(tx, vaultKey, Array.from({ length: 6 }, (_, k) => read(k))));
  const { result, ...took } = await cpu(() => writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, quiet));
  if (result !== true) throw new Error('a beat failed');
  beat.push(took);
}
console.log(JSON.stringify({
  entries: target,
  me: { cpuMs: median(me.map((r) => r.cpuMs)), wallMs: median(me.map((r) => r.wallMs)) },
  page: { cpuMs: median(page.map((r) => r.cpuMs)), wallMs: median(page.map((r) => r.wallMs)) },
  beat: { cpuMs: median(beat.map((r) => r.cpuMs)), wallMs: median(beat.map((r) => r.wallMs)) },
  verdict,
}));
if (values.keep !== true) await resetDatabase(db.owner);
await db.close();
process.exit(0);
