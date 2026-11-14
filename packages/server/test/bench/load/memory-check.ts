// Does the vault's memory answer a repeat? One key asked every `--every` ms,
// `--n` times, through the app Worker: the vault's connections and the
// statements it made say how many were read again. The rig's bundles and
// keys (run.ts --dir), its own workerd and proxy.
//
//   node --conditions=coffre:source memory-check.ts --dir ~/scratch/<id>/v016 [--every 100] [--n 30] [--memory 2] [--keys 1]
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import './nodelay.ts';
import { parseArgs } from 'node:util';

import { postgresProxy } from '../../../../../scripts/postgres-proxy.ts';

const { values } = parseArgs({ options: { dir: { type: 'string' }, every: { type: 'string', default: '100' }, n: { type: 'string', default: '30' }, memory: { type: 'string', default: '2' }, keys: { type: 'string', default: '1' }, pool: { type: 'string', default: '57121' }, port: { type: 'string', default: '57390' } } });
const dir = values.dir!;
const { VAULT_KEY, APP_KEY } = JSON.parse(readFileSync(join(dir, 'keys.json'), 'utf8')) as Record<string, string>;
const script = (name: string) => join(dir, 'build', name, 'dist', `${name.replace('bench-', '')}-worker.js`);
const statements: string[][] = [];
const vaultProxy = await postgresProxy(`postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${values.pool}/coffre_bench`, { onSync: (s) => statements.push(s) });
const appProxy = await postgresProxy(`postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${values.pool}/coffre_bench`);
const req = createRequire(import.meta.url);
const { Miniflare, convertV4MiniflareOptions } = (await import(pathToFileURL(createRequire(req.resolve('wrangler')).resolve('miniflare')).href)) as typeof import('miniflare');
const common = { modules: true, compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'] };
const port = Number(values.port);
const mf = new Miniflare(convertV4MiniflareOptions({
  host: '127.0.0.1', port: 0,
  workers: [
    { ...common, name: 'bench-app', scriptPath: script('bench-app'), modulesRoot: dirname(script('bench-app')), bindings: { APP_KEY }, hyperdrives: { HYPERDRIVE: `${appProxy.url}?sslmode=disable` }, serviceBindings: { VAULT: 'bench-vault' }, unsafeDirectSockets: [{ host: '127.0.0.1', port }] },
    { ...common, name: 'bench-vault', scriptPath: script('bench-vault'), modulesRoot: dirname(script('bench-vault')), bindings: { VAULT_KEY, MEMORY_SECONDS: values.memory }, hyperdrives: { VAULT_HYPERDRIVE: `${vaultProxy.url}?sslmode=disable` }, durableObjects: { SIGNER: { className: 'CoffreSigner', useSQLite: true } }, unsafeEphemeralDurableObjects: true },
  ],
} as never));
await mf.ready;
const statuses: number[] = [];
const ms: number[] = [];
for (let i = 0; i < Number(values.n); i++) {
  const t0 = performance.now();
  const response = await fetch(`http://127.0.0.1:${port}/api/reveals`, { method: 'POST', headers: { authorization: 'Bearer bench-ci-token', 'content-type': 'application/json' }, body: JSON.stringify({ path: `bench/prod/KEY_${i % Number(values.keys)}` }) });
  await response.text();
  statuses.push(response.status);
  ms.push(Math.round((performance.now() - t0) * 10) / 10);
  await new Promise((resolve) => setTimeout(resolve, Number(values.every)));
}
const reads = statements.filter((s) => s.some((text) => text.includes('RECURSIVE'))).length;
console.log(JSON.stringify({ ms: ms.join(' '), requests: statuses.length, statuses: [...new Set(statuses)], vaultConnections: vaultProxy.opened, reads, syncs: vaultProxy.syncs, other: statements.filter((s) => !s.some((t) => t.includes("RECURSIVE"))).length }, null, 1));
await mf.dispose();
await Promise.all([vaultProxy.close(), appProxy.close()]);
process.exit(0);
