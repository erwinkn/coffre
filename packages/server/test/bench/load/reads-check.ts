// The other reads a request may make, `caller` (a page's: who asks) and
// `weigh` (a change previewed: its read and decision), `n` times each, the
// vault's memory off, straight to Postgres: for pg_stat_statements to set
// each statement's planning beside its running. The rig's instance
// (world.ts): its service token, and a write to bench/prod it may not make,
// which reads all the same.
//
//   BENCH_VAULT_KEY=… COFFRE_POSTGRES_PORT=57120 COFFRE_TEST_DATABASE=coffre_bench node --conditions=coffre:source reads-check.ts [n]
import { createHash } from 'node:crypto';

import { openConfiguredVault } from '@coffre/vault/testing';

const n = Number(process.argv[2] ?? 2000);
const { vault } = await openConfiguredVault({ kek: { id: 'bench', key: process.env.BENCH_VAULT_KEY! }, owners: ['root@acme.example'], memorySeconds: 0 });
const shown = { token: createHash('sha256').update('bench-ci-token').digest('hex'), proof: null, request: null, ip: null };
const answers = new Map<string, number>();
const tally = (what: string, answer: object) => {
  const key = `${what} ${'refused' in answer ? (answer as { refused: string }).refused : 'answered'}`;
  answers.set(key, (answers.get(key) ?? 0) + 1);
};
for (let i = 0; i < n; i++) tally('caller', await vault.caller(shown));
for (let i = 0; i < n; i++) tally('weigh', await vault.weigh({ ...shown, op: 'secret.write', project: 'bench', environment: 'prod', keys: [{ key: `KEY_${i % 100}`, value: 'x', nature: 'secret' }] } as never));
console.log(JSON.stringify(Object.fromEntries(answers)));
process.exit(0);
