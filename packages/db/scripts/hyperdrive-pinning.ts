// Whether a real Hyperdrive keeps each of coffre's transactions whole: every statement of one on one backend, in one
// transaction, and what it rolled back or failed kept nowhere. Hyperdrive pools connections by transaction, reading
// where one starts and ends from Postgres's ReadyForQuery; a change to how the driver sends a transaction (its BEGIN,
// its groups, its COMMIT: postgres-js/README.md) is checked here, on Cloudflare, before it ships. Local workerd runs no
// Hyperdrive, so no suite can.
//
//   pnpm build
//   node packages/db/scripts/hyperdrive-pinning.ts bundle <dir>
//       the Worker (hyperdrive-pinning.worker.ts), bundled as wrangler deploys it: <dir>/hyperdrive-pinning.worker.js
//   deploy it as a throwaway Worker with a Hyperdrive binding named HYPERDRIVE, caching off, to a throwaway Postgres
//   node packages/db/scripts/hyperdrive-pinning.ts run <worker url> [--transactions 10000] [--concurrency 50]
//
// `run` asks the Worker to make its table, then for `--transactions` transactions, `--concurrency` requests at once,
// each of 20 transactions on its call's one connection, every shape in turn; it prints each shape's count, the
// backends seen, and every transaction that did not hold, and fails if one did not. Delete the Worker, the
// Hyperdrive configuration and the database after.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import type { Outcome } from './hyperdrive-pinning.worker.ts';

const here = dirname(fileURLToPath(import.meta.url));
const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: { transactions: { type: 'string', default: '10000' }, concurrency: { type: 'string', default: '50' } },
});
const [command, target] = positionals;

if (command === 'bundle' && target !== undefined) {
  const out = resolve(target);
  mkdirSync(out, { recursive: true });
  // A configuration of its own, its Hyperdrive a placeholder: the deploy binds the real one.
  const config = join(out, 'wrangler.json');
  writeFileSync(config, JSON.stringify({
    name: 'coffre-hyperdrive-pinning', main: join(here, 'hyperdrive-pinning.worker.ts'), compatibility_date: '2026-09-01', compatibility_flags: ['nodejs_compat'],
    hyperdrive: [{ binding: 'HYPERDRIVE', id: '00000000000000000000000000000000', localConnectionString: 'postgresql://unused@127.0.0.1:1/unused' }],
  }, null, 2));
  execFileSync('pnpm', ['--filter', 'coffre-workers', 'exec', 'wrangler', 'deploy', '--dry-run', '--minify', '--config', config, '--outdir', out], { stdio: 'inherit' });
  console.log(`bundled: ${join(out, 'hyperdrive-pinning.worker.js')}`);
} else if (command === 'run' && target !== undefined) {
  const total = Number(values.transactions);
  const concurrency = Number(values.concurrency);
  const per = 20;
  const run = `r${Date.now().toString(36)}`;
  const setup = await fetch(new URL('/setup', target), { method: 'POST' });
  if (!setup.ok) throw new Error(`setup answered ${setup.status}: ${await setup.text()}`);
  const outcomes: Outcome[] = [];
  let next = 0;
  const started = performance.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    for (let from = next; from < total; from = next) {
      next += per;
      const url = new URL('/run', target);
      url.search = new URLSearchParams({ n: String(Math.min(per, total - from)), from: String(from), run }).toString();
      const answered = await fetch(url, { method: 'POST' });
      if (!answered.ok) {
        outcomes.push({ shape: 'request', ok: false, pid: null, why: `${answered.status}: ${(await answered.text()).slice(0, 300)}` });
        continue;
      }
      outcomes.push(...((await answered.json()) as { outcomes: Outcome[] }).outcomes);
    }
  }));
  const shapes = new Map<string, { held: number; not: number }>();
  for (const { shape, ok } of outcomes) {
    const count = shapes.get(shape) ?? { held: 0, not: 0 };
    count[ok ? 'held' : 'not'] += 1;
    shapes.set(shape, count);
  }
  const backends = new Set(outcomes.flatMap(({ pid }) => (pid === null ? [] : [pid])));
  console.table(Object.fromEntries(shapes));
  console.log(`${outcomes.length} transactions in ${((performance.now() - started) / 1000).toFixed(1)} s, ${concurrency} requests at once, on ${backends.size} backends`);
  const broken = outcomes.filter(({ ok }) => !ok);
  for (const { shape, why } of broken.slice(0, 20)) console.log(`did not hold: ${shape}: ${why}`);
  if (broken.length > 0 || outcomes.length !== total) process.exit(1);
} else {
  console.error('usage: hyperdrive-pinning.ts bundle <dir> | run <worker url> [--transactions <n>] [--concurrency <n>]');
  process.exit(2);
}
