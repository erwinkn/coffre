// The plan Postgres settles on for the reads a request makes, through the
// vault's own code and driver, the vault's memory off: `use` asking one key
// and asking 1,000 (an ask's most), then `caller` and `weigh`, `n` times each.
// The database runs auto_explain (run.ts --plans), so each execution's
// plan lands in Postgres's log: `$1` in it is the generic plan. Prints
// pg_stat_statements' plans, calls and times per statement.
//
//   BENCH_VAULT_KEY=… COFFRE_POSTGRES_PORT=57120 COFFRE_TEST_DATABASE=coffre_bench node --conditions=coffre:source plan-check.ts [n]

import { createHash } from 'node:crypto';

import { rowsOf } from '@coffre/db/dialect';
import { openConfiguredVault } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

const n = Number(process.argv[2] ?? 20);
const { world, vault } = await openConfiguredVault({ kek: { id: 'bench', key: process.env.BENCH_VAULT_KEY! }, owners: ['root@acme.example'], memorySeconds: 0 });
const shown = { token: createHash('sha256').update('bench-ci-token').digest('hex'), proof: null, request: null, ip: null };
const answers = new Map<string, number>();
const tally = (what: string, answer: object) => {
  const key = `${what} ${'refused' in answer ? String((answer as { refused: unknown }).refused) : 'answered'}`;
  answers.set(key, (answers.get(key) ?? 0) + 1);
};
const ask = (keys: number) => ({ ...shown, project: 'bench', environment: 'prod', mine: false, keys: Array.from({ length: keys }, (_, i) => `KEY_${i}`), purpose: 'reveal', upstream: null }) as never;
await rowsOf(world.owner, sql`SELECT pg_stat_statements_reset()`);
for (const keys of [1, 1000]) for (let i = 0; i < n; i++) tally(`use ${keys}`, await vault.use(ask(keys)));
for (let i = 0; i < n; i++) tally('caller', await vault.caller(shown));
for (let i = 0; i < n; i++) tally('weigh', await vault.weigh({ ...shown, op: 'secret.write', project: 'bench', environment: 'prod', keys: [{ key: `KEY_${i % 100}`, value: 'x', nature: 'secret' }] } as never));
const stats = await rowsOf<Record<string, unknown>>(world.owner, sql`
  SELECT calls, plans, round(mean_plan_time::numeric, 3) AS plan_ms, round(mean_exec_time::numeric, 3) AS exec_ms, rows, md5(query) AS text, left(regexp_replace(query, '[[:space:]]+', ' ', 'g'), 120) AS query
  FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND calls >= ${n} ORDER BY total_plan_time + total_exec_time DESC LIMIT 12`);
console.log(JSON.stringify({ n, answers: Object.fromEntries(answers), stats }, null, 1));
process.exit(0);
