// What a use's read puts on the wire, call by call: `--n` reveals one after
// another through the app Worker, the vault's memory off, each a vault call
// with a connection of its own, as on Cloudflare. A proxy in front of the
// vault's login records each connection's messages, both ways, and counts
// the client's waits: each time it speaks again after the server answered.
// With PgBouncer's SHOW STATS around it: how many Parses the clients sent,
// and how many reached Postgres. Bundles from this checkout's sources, in
// <dir>/build-wire, apart from run.ts's.
//
//   node --conditions=coffre:source wire-check.ts --dir ~/scratch/<id>/v016 [--n 20] [--label named]
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { connect, createServer, type Socket } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import './nodelay.ts';

const { values } = parseArgs({ options: { dir: { type: 'string' }, n: { type: 'string', default: '20' }, label: { type: 'string', default: 'wire' }, pool: { type: 'string', default: '57121' }, port: { type: 'string', default: '57391' } } });
const here = dirname(fileURLToPath(import.meta.url));
const dir = values.dir!;
const { VAULT_KEY, APP_KEY } = JSON.parse(readFileSync(join(dir, 'keys.json'), 'utf8')) as Record<string, string>;

function bundle(name: string, main: string, more: Record<string, unknown> = {}): string {
  const out = join(dir, 'build-wire', name);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'wrangler.json'), JSON.stringify({ name, main: join(here, main), compatibility_date: '2026-08-06', compatibility_flags: ['nodejs_compat'], ...more }));
  execFileSync(join(here, '../../../node_modules/.bin/wrangler'), ['deploy', '--dry-run', '--outdir', join(out, 'dist'), '-c', join(out, 'wrangler.json')], {
    env: { ...process.env, WRANGLER_BUILD_CONDITIONS: 'coffre:source,workerd,worker,browser', WRANGLER_SEND_METRICS: 'false' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  const js = readdirSync(join(out, 'dist')).filter((file) => file.endsWith('.js'));
  return join(out, 'dist', js[0]!);
}

/** A connection's messages: each burst the client wrote after an answer (`>`), and the server's (`<`), by type. */
type Trace = { bursts: string[]; waits: number; syncs: number; parses: string[] };
const traces: Trace[] = [];

/** Each typed message in `buffer`, whole ones only; the rest is left for the next chunk. */
function messages(state: { unread: Buffer; started: boolean }, chunk: Buffer, untypedFirst: boolean): Buffer[] {
  state.unread = Buffer.concat([state.unread, chunk]);
  const out: Buffer[] = [];
  for (;;) {
    // A server's answer to an SSLRequest is one byte; the client's first message has no type.
    const head = state.started || !untypedFirst ? 1 : 0;
    if (state.unread.length < head + 4) break;
    const length = head + state.unread.readUInt32BE(head);
    if (state.unread.length < length) break;
    out.push(state.unread.subarray(0, length));
    if (untypedFirst && !state.started && state.unread.readUInt32BE(4) >> 16 === 3) state.started = true;
    state.unread = state.unread.subarray(length);
  }
  return out;
}

const cString = (buffer: Buffer, at: number) => buffer.toString('utf8', at, buffer.indexOf(0, at));

const proxy = createServer((client: Socket) => {
  client.setNoDelay(true);
  const trace: Trace = { bursts: [], waits: 0, syncs: 0, parses: [] };
  traces.push(trace);
  const upstream = connect({ port: Number(values.pool), host: '127.0.0.1' });
  upstream.setNoDelay(true);
  const from = { unread: Buffer.alloc(0), started: false };
  const to = { unread: Buffer.alloc(0), started: true };
  let answered = true;
  let speaking: string[] | null = null;
  let listening: string[] | null = null;
  client.on('data', (chunk: Buffer) => {
    if (answered) {
      trace.waits += 1;
      speaking = [];
      trace.bursts.push('');
      listening = null;
    }
    answered = false;
    upstream.write(chunk);
    for (const message of messages(from, chunk, true)) {
      const type = from.started && message.length > 0 && message[0]! >= 0x41 ? String.fromCharCode(message[0]!) : 'startup';
      if (type === 'S' || type === 'Q') trace.syncs += 1;
      // Parse: its statement's name ('' for unnamed), then its text.
      if (type === 'P') trace.parses.push(cString(message, 5) || '(unnamed)');
      const label = type === 'P' ? `P(${cString(message, 5) || '-'})` : type === 'B' ? `B(${cString(message, 5 + cString(message, 5).length + 1) || '-'})` : type === 'D' ? `D(${cString(message, 6) || '-'})` : type;
      speaking!.push(label);
      trace.bursts[trace.bursts.length - 1] = `> ${speaking!.join(' ')}`;
    }
  });
  upstream.on('data', (chunk: Buffer) => {
    answered = true;
    client.write(chunk);
    if (listening === null) {
      listening = [];
      trace.bursts.push('');
    }
    // A lone 'N' or 'S' answers an SSLRequest.
    if (chunk.length === 1) return void (trace.bursts[trace.bursts.length - 1] = `< ssl:${String.fromCharCode(chunk[0]!)}`);
    for (const message of messages(to, chunk, false)) listening.push(String.fromCharCode(message[0]!));
    trace.bursts[trace.bursts.length - 1] = `< ${listening.join(' ')}`;
  });
  const end = () => {
    if (!client.destroyed) client.resetAndDestroy();
    if (!upstream.destroyed) upstream.resetAndDestroy();
  };
  client.on('close', end).on('error', end);
  upstream.on('close', end).on('error', end);
});
await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
const proxyPort = (proxy.address() as { port: number }).port;

/** PgBouncer's own count of Parses: from its clients, and sent on to Postgres (SHOW STATS, 1.21 on). */
function bouncer(): { client: number; server: number; bind: number } {
  const out = execFileSync('psql', ['-h', '127.0.0.1', '-p', values.pool!, '-U', 'coffre_owner', '-d', 'pgbouncer', '-AF', '\t', '-c', 'SHOW STATS'], { env: { ...process.env, PGPASSWORD: 'local-dev-only' }, encoding: 'utf8' });
  const [head, ...rows] = out.trim().split('\n');
  const columns = head!.split('\t');
  const row = rows.map((line) => line.split('\t')).find((cells) => cells[0] === 'coffre_bench')!;
  const at = (name: string) => Number(row[columns.indexOf(name)]);
  return { client: at('total_client_parse_count'), server: at('total_server_parse_count'), bind: at('total_bind_count') };
}

const app = bundle('bench-app', 'app-worker.ts');
const vault = bundle('bench-vault', 'vault-worker.ts', { durable_objects: { bindings: [{ name: 'SIGNER', class_name: 'CoffreSigner' }] }, migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }] });
const req = createRequire(import.meta.url);
const { Miniflare, convertV4MiniflareOptions } = (await import(pathToFileURL(createRequire(req.resolve('wrangler')).resolve('miniflare')).href)) as typeof import('miniflare');
const common = { modules: true, compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'] };
const port = Number(values.port);
const mf = new Miniflare(convertV4MiniflareOptions({
  host: '127.0.0.1', port: 0,
  workers: [
    { ...common, name: 'bench-app', scriptPath: app, modulesRoot: dirname(app), bindings: { APP_KEY }, hyperdrives: { HYPERDRIVE: `postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${values.pool}/coffre_bench?sslmode=disable` }, serviceBindings: { VAULT: 'bench-vault' }, unsafeDirectSockets: [{ host: '127.0.0.1', port }] },
    { ...common, name: 'bench-vault', scriptPath: vault, modulesRoot: dirname(vault), bindings: { VAULT_KEY, MEMORY_SECONDS: '0' }, hyperdrives: { VAULT_HYPERDRIVE: `postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${proxyPort}/coffre_bench?sslmode=disable` }, durableObjects: { SIGNER: { className: 'CoffreSigner', useSQLite: true } }, unsafeEphemeralDurableObjects: true },
  ],
} as never));
await mf.ready;
const reveal = (i: number) => fetch(`http://127.0.0.1:${port}/api/reveals`, { method: 'POST', headers: { authorization: 'Bearer bench-ci-token', 'content-type': 'application/json' }, body: JSON.stringify({ path: `bench/prod/KEY_${i % 100}` }) });
// Warm: the signer's first wake, the isolate's first read.
for (let i = 0; i < 3; i++) await (await reveal(i)).text();
await new Promise((resolve) => setTimeout(resolve, 1500));
traces.length = 0;
const before = bouncer();
const statuses: number[] = [];
for (let i = 0; i < Number(values.n); i++) {
  const response = await reveal(i);
  await response.text();
  statuses.push(response.status);
}
await new Promise((resolve) => setTimeout(resolve, 300));
const after = bouncer();
// The calls' connections: those that read (a Parse of the use's statement, or a Bind of it by name).
const reads = traces.filter((trace) => trace.bursts.some((burst) => burst.includes('B(') || burst.includes('P(')));
const shapes = new Map<string, number>();
for (const trace of reads) {
  const shape = trace.bursts.filter((burst) => !burst.startsWith('< ') || burst.includes('Z')).join('  |  ');
  shapes.set(shape, (shapes.get(shape) ?? 0) + 1);
}
console.log(JSON.stringify({
  label: values.label,
  reveals: statuses.length,
  statuses: [...new Set(statuses)],
  connections: traces.length,
  waitsPerConnection: [...new Set(traces.map((trace) => trace.waits))],
  syncsPerConnection: [...new Set(traces.map((trace) => trace.syncs))],
  parses: [...new Set(traces.flatMap((trace) => trace.parses))],
  pgbouncer: { clientParses: after.client - before.client, serverParses: after.server - before.server, binds: after.bind - before.bind },
  shapes: Object.fromEntries(shapes),
}, null, 1));
await mf.dispose();
proxy.close();
process.exit(0);
