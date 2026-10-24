// What a core scheduled run costs, in CPU, with the audit watch and without
// it: the same log of `--entries`, the same twelve entries written
// before each run, as five minutes of an instance write them; then the
// run, timed, the vault in the same process. Not part of the suite:
//
//   COFFRE_TEST_DATABASE=coffre_bench ./scripts/setup-test-database.sh
//   COFFRE_TEST_DATABASE=coffre_bench node --conditions=coffre:source packages/server/test/bench/scheduled-tick.ts --entries 10000
import { parseArgs } from 'node:util';

import { github, signin } from '@coffre/core/identity';
import { appendEntries } from '@coffre/db/log';

import { runScheduled } from '../../src/app.ts';
import { appLogKey } from '../../src/db/audit.ts';
import { auditWatch } from '../../src/plugins/audit-watch.ts';
import type { CoffreRuntime } from '../../src/runtime.ts';
import { openTestDatabase, resetDatabase, testDeps, waitUntil } from '../api-fixture.ts';

const { values } = parseArgs({ options: { entries: { type: 'string', default: '10000' }, runs: { type: 'string', default: '10' } } });
const db = await openTestDatabase();
await resetDatabase(db.owner);
const deps = testDeps(db.runtime, ['root@acme.example']);
const runtime = (plugins: CoffreRuntime['plugins']): CoffreRuntime => ({
  db: deps.db,
  vault: deps.vault,
  chainKey: deps.chainKey,
  previousChainKeys: [],
  signin: null,
  workloads: null,
  mcp: null,
  auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }).resolve('https://coffre.test'),
  publicUrl: 'https://coffre.test',
  verifier: { verify: async () => { throw new Error('unused'); } },
  waitUntil,
  schema: { migrated: true }, appKey: { settled: true },
  rotateAfterDays: 365,
  plugins,
});
const watched = runtime([auditWatch({ anchor: deps.anchor })]);
const bare = runtime([]);

const append = async (count: number) => {
  for (let left = count; left > 0; left -= 1000) {
    const batch = Array.from({ length: Math.min(1000, left) }, () => ({ actor: 'token:ci-deploy', action: 'secret.read', decision: 'allow' as const, metadata: '{"subject":"market/prod/DATABASE_URL"}' }));
    await db.owner.transaction((tx) => appendEntries(tx, appLogKey(deps.chainKey), batch));
  }
};
await append(Number(values.entries));
// Caught up first, the vault and the watch: what each tick then costs is five minutes of the log.
for (let i = 0; i < 5; i++) await runScheduled(watched).catch(() => undefined);

const cpu = async (run: () => Promise<unknown>) => {
  const usage = process.cpuUsage();
  await run();
  const used = process.cpuUsage(usage);
  return (used.user + used.system) / 1000;
};
const median = (xs: number[]) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;
const measured: Record<string, number[]> = { 'without the audit watch': [], 'with the audit watch': [] };
for (let i = 0; i < Number(values.runs); i++) {
  for (const [name, rt] of [['without the audit watch', bare], ['with the audit watch', watched]] as const) {
    await append(12);
    measured[name]!.push(await cpu(() => runScheduled(rt)));
  }
}
console.log(`a scheduled run on a log of ${values.entries} entries, twelve written since the last, the vault in-process (ms CPU, median of ${values.runs}):`);
for (const [name, xs] of Object.entries(measured)) console.log(`  ${name}: ${median(xs).toFixed(1)}  (min ${Math.min(...xs).toFixed(1)}, max ${Math.max(...xs).toFixed(1)})`);
await db.close();
process.exit(0);
