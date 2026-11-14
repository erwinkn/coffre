// The load rig's driver: the app and vault Workers in one workerd (Miniflare,
// no wrangler proxy in front), each Worker's Hyperdrive binding through a
// proxy that counts connections and round trips, then PgBouncer, then
// Postgres (rig.sh). For each log size, each vault memory and each rate, an
// open-loop run (load.ts), and around its measured window: Postgres's
// statements (pg_stat_statements), round trips, connections, CPU (workerd's
// threads, Postgres's container), and the signer's lag. One JSON per cell.
//
//   rig.sh up, then
//   taskset -c 86,87 node --conditions=coffre:source run.ts --dir ~/scratch/<id> --fresh \
//     [--sizes 0,100000,1000000] [--memory 2,0] [--rates 100,300,600,1000] [--warmup 10] [--duration 60] [--target app|probe]
import { execFile as execFileCallback, execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { loadavg } from 'node:os';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import './nodelay.ts';
import { parseArgs, promisify } from 'node:util';

import { postgresSession } from '@coffre/db/connect';


const execFile = promisify(execFileCallback);
const here = dirname(fileURLToPath(import.meta.url));
const { values } = parseArgs({
  options: {
    dir: { type: 'string' },
    fresh: { type: 'boolean', default: false },
    sizes: { type: 'string', default: '0' },
    memory: { type: 'string', default: '2,0' },
    rates: { type: 'string', default: '100,300,600,1000' },
    warmup: { type: 'string', default: '10' },
    duration: { type: 'string', default: '60' },
    target: { type: 'string', default: 'app' },
    // 0.14.7: the Workers example of a v0.14.7 export, built (`pnpm build`, `pnpm --filter coffre-workers build`), and
    // its database seeded by v014/seed.ts, whose service token --token names.
    version: { type: 'string', default: '0.16' },
    src: { type: 'string' },
    token: { type: 'string', default: 'bench-ci-token' },
    // The proxy run (W422's credential proxy): its app Worker (proxy/app-worker.ts) and instance (proxy/world.ts), one
    // workload session per service, the request shape load.ts sends (--mode), and the vault's outageSeconds.
    app: { type: 'string', default: 'reveal' },
    mode: { type: 'string', default: 'reveal' },
    services: { type: 'string', default: '1' },
    'outage-seconds': { type: 'string' },
    // An outage of Postgres within each measured window: `<second it stops>,<seconds it stays down>`.
    outage: { type: 'string', default: '' },
    // 0.14.7's credential proxy: its cacheSeconds (the bench build's PROXY_CACHE_SECONDS; its own default, 60, unless set).
    'proxy-cache': { type: 'string' },
    // The vault's deadline on each statement's wait and answer, in ms (hyperdrive.ts's bench-only COFFRE_BENCH_DEADLINE_MS).
    deadline: { type: 'string' },
    label: { type: 'string', default: '' },
    // After each size's growth: plan-check.ts, <n> of each read, under auto_explain; its stats and the plans Postgres logged, in <dir>/plans.
    plans: { type: 'string', default: '0' },
    // The generator's keep-alive pool (load.ts --connections): a request due while it is full is shed by the client.
    connections: { type: 'string', default: '256' },
    database: { type: 'string', default: 'coffre_bench' },
    'pg-port': { type: 'string', default: process.env.BENCH_PG_PORT ?? '57120' },
    'pool-port': { type: 'string', default: process.env.BENCH_POOL_PORT ?? '57121' },
    'app-port': { type: 'string', default: '57140' },
    'workerd-cpus': { type: 'string', default: '83-85' },
    'load-cpus': { type: 'string', default: '88,89' },
    'proxy-cpus': { type: 'string', default: '87' },
  },
});
const dir = resolve(values.dir!);
const list = (text: string) => text.split(',').filter(Boolean).map(Number);
const [pgPort, poolPort, appPort] = [values['pg-port']!, values['pool-port']!, Number(values['app-port'])];
// Each boot takes three ports of its own, from --app-port on: workerd's listeners do not reuse an address, and the
// last run's connections hold the one before in TIME_WAIT for a minute.
// A run starts at an offset of its own, so the run before it does not hold its first ports either.
let boots = (process.pid % 40) * 2;
let [port, probePort, controlPort] = [appPort, appPort + 1, appPort + 2];
const database = values.database!;
const owner = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${pgPort}/${database}`;
mkdirSync(join(dir, 'cells'), { recursive: true });

// --- keys, shared by the Workers and world.ts ---------------------------------------------------------------------
const keysFile = join(dir, 'keys.json');
if (values.fresh || !existsSync(keysFile)) writeFileSync(keysFile, JSON.stringify({ VAULT_KEY: randomBytes(32).toString('base64'), APP_KEY: randomBytes(32).toString('base64') }));
const old = values.version === '0.14.7';
// 0.14.7's are its conformance harness's (packages/conformance/src/fixtures.ts), which seeded its database.
const { VAULT_KEY, APP_KEY } = old
  ? { VAULT_KEY: 'Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE=', APP_KEY: 'Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI=' }
  : (JSON.parse(readFileSync(keysFile, 'utf8')) as { VAULT_KEY: string; APP_KEY: string });
const src = old ? resolve(values.src!) : '';

// --- the Workers, bundled from the packages' sources, as the Workers tests read them --------------------------------
const build = join(dir, 'build');
function bundle(name: string, main: string, more: Record<string, unknown> = {}): string {
  const out = join(build, name);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'wrangler.json'), JSON.stringify({ name, main: join(here, main), compatibility_date: '2026-08-06', compatibility_flags: ['nodejs_compat'], ...more }));
  execFileSync(join(here, '../../../node_modules/.bin/wrangler'), ['deploy', '--dry-run', '--outdir', join(out, 'dist'), '-c', join(out, 'wrangler.json')], {
    env: { ...process.env, WRANGLER_BUILD_CONDITIONS: 'coffre:source,workerd,worker,browser', WRANGLER_SEND_METRICS: 'false' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  const js = readdirSync(join(out, 'dist')).filter((file) => file.endsWith('.js'));
  if (js.length !== 1) throw new Error(`${name}: expected one module, got ${js.join(', ')}`);
  return join(out, 'dist', js[0]!);
}
function bundle014(): string {
  const out = join(build, 'coffre-vault-0.14.7');
  execFileSync(join(src, 'examples/workers/node_modules/.bin/wrangler'), ['deploy', '--dry-run', '--outdir', out, '-c', join(src, 'examples/workers/vault/wrangler.jsonc')], {
    cwd: join(src, 'examples/workers'), env: { ...process.env, WRANGLER_SEND_METRICS: 'false' }, stdio: ['ignore', 'ignore', 'inherit'],
  });
  return join(out, 'worker.js');
}
const scripts = old ? { app: join(src, 'examples/workers/app/dist/server/index.js'), vault: bundle014(), probe: '' } : {
  app: values.app === 'proxy' ? bundle('bench-app', 'proxy/app-worker.ts') : bundle('bench-app', 'app-worker.ts'),
  vault: bundle('bench-vault', 'vault-worker.ts', { durable_objects: { bindings: [{ name: 'SIGNER', class_name: 'CoffreSigner' }] }, migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }] }),
  probe: bundle('bench-probe', 'probe-worker.ts'),
};

// --- the counting proxies, one per Worker's login, in front of PgBouncer: a process of their own (proxy.ts) ----------
const countersPort = appPort - 1;
const proxyProcess = spawn('taskset', ['-c', values['proxy-cpus']!, process.execPath, '--conditions=coffre:source', join(here, 'proxy.ts'), '--pool', poolPort, '--database', database, '--port', String(countersPort)], { stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise<void>((resolve) => proxyProcess.stdout.once('data', () => resolve()));
type Counted = { url: string; opened: number; trips: number; syncs: number; open: number; peak: number };
const counters = async () => (await (await fetch(`http://127.0.0.1:${countersPort}/`)).json()) as { app: Counted; vault: Counted };
const proxies = await counters();

// --- workerd, through Miniflare -----------------------------------------------------------------------------------
const requireHere = createRequire(import.meta.url);
const { Miniflare, convertV4MiniflareOptions } = (await import(pathToFileURL(createRequire(requireHere.resolve('wrangler')).resolve('miniflare')).href)) as typeof import('miniflare');
type MF = InstanceType<typeof Miniflare>;
let mf: MF | null = null;
let workerd: number[] = [];
const persist = join(dir, 'persist');

// 0.14.7's app is Vite's build, a module and the chunks it imports, some by `import()`: every one listed, its entry first.
function modules014(main: string): { type: 'ESModule'; path: string }[] {
  const all = (readdirSync(dirname(main), { recursive: true }) as string[]).filter((file) => file.endsWith('.js')).map((file) => join(dirname(main), file));
  return [main, ...all.filter((file) => file !== main)].map((path) => ({ type: 'ESModule', path }));
}
async function boot(memory: number): Promise<void> {
  if (mf !== null) await mf.dispose();
  // Three ports no socket uses, listening or in TIME_WAIT.
  const used = (candidate: number) => execFileSync('ss', ['-Htan', `( sport = :${candidate} )`], { encoding: 'utf8' }).trim() !== '';
  do {
    [port, probePort, controlPort] = [appPort + 3 * boots, appPort + 3 * boots + 1, appPort + 3 * boots + 2];
    boots = (boots + 1) % 80;
  } while ([port, probePort, controlPort].some(used));
  worldEnv.BENCH_CONTROL_URL = `http://127.0.0.1:${controlPort}`;
  const common = { modules: true, compatibilityDate: '2026-08-06', compatibilityFlags: ['nodejs_compat'] };
  const workers014 = [
    {
      ...common, name: 'coffre', scriptPath: scripts.app, modulesRoot: dirname(scripts.app), modules: modules014(scripts.app),
      bindings: { PUBLIC_URL: `http://127.0.0.1:${port}`, GITHUB_CLIENT_ID: 'bench', GITHUB_CLIENT_SECRET: 'bench', APP_KEY, ...(values['proxy-cache'] === undefined ? {} : { PROXY_CACHE_SECONDS: values['proxy-cache'] }) },
      hyperdrives: { HYPERDRIVE: `${proxies.app.url}?sslmode=disable` }, serviceBindings: { VAULT: 'coffre-vault' },
      durableObjects: { SOCKETS: { className: 'CoffreSockets', useSQLite: true }, GATES: { className: 'CoffreGates', useSQLite: true }, ANCHOR: { className: 'CoffreAnchor', useSQLite: true } },
      ratelimits: Object.fromEntries([['WORKLOADS_PER_SOURCE', 30], ['WORKLOADS_TOTAL', 300], ['MCP_PER_SOURCE', 30], ['MCP_PER_CONNECTION', 120], ['MCP_TOTAL', 300]].map(([name, limit], i) => [name, { namespace_id: String(1001 + i), simple: { limit, period: 60 } }])),
      unsafeDirectSockets: [{ host: '127.0.0.1', port }],
    },
    {
      ...common, name: 'coffre-vault', scriptPath: scripts.vault, modulesRoot: dirname(scripts.vault),
      bindings: { VAULT_KEY_ID: 'vault-conformance-1', VAULT_KEY, OWNERS: 'root@conformance.example' }, hyperdrives: { VAULT_HYPERDRIVE: `${proxies.vault.url}?sslmode=disable` },
    },
  ];
  mf = new Miniflare(convertV4MiniflareOptions({
    host: '127.0.0.1',
    port: 0,
    resourcePersistencePath: persist,
    workers: old ? workers014 : [
      {
        ...common, name: 'bench-app', scriptPath: scripts.app, modulesRoot: dirname(scripts.app), bindings: { APP_KEY }, hyperdrives: { HYPERDRIVE: `${proxies.app.url}?sslmode=disable` }, serviceBindings: { VAULT: 'bench-vault' },
        ...(values.app === 'proxy' ? { durableObjects: { GATES: { className: 'CoffreGates', useSQLite: true } } } : {}), unsafeDirectSockets: [{ host: '127.0.0.1', port }],
      },
      {
        ...common, name: 'bench-vault', scriptPath: scripts.vault, modulesRoot: dirname(scripts.vault),
        bindings: { VAULT_KEY, MEMORY_SECONDS: String(memory), ...(values.app === 'proxy' ? { WORKLOADS: '1' } : {}), ...(values['outage-seconds'] === undefined ? {} : { OUTAGE_SECONDS: values['outage-seconds'] }), ...(values.deadline === undefined ? {} : { DEADLINE_MS: values.deadline }) }, hyperdrives: { VAULT_HYPERDRIVE: `${proxies.vault.url}?sslmode=disable` },
        durableObjects: { SIGNER: { className: 'CoffreSigner', useSQLite: true } }, unsafeDirectSockets: [{ host: '127.0.0.1', port: controlPort, entrypoint: 'Control' }],
      },
      { ...common, name: 'bench-probe', scriptPath: scripts.probe, modulesRoot: dirname(scripts.probe), serviceBindings: { VAULT: 'bench-vault' }, unsafeDirectSockets: [{ host: '127.0.0.1', port: probePort }] },
    ],
  } as never));
  await mf.ready;
  workerd = readdirSync('/proc').filter((pid) => /^\d+$/.test(pid)).filter((pid) => {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      return stat.slice(stat.indexOf('(') + 1, stat.lastIndexOf(')')) === 'workerd' && Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]) === process.pid;
    } catch {
      return false;
    }
  }).map(Number);
  if (workerd.length !== 1) throw new Error(`expected one workerd of ours, found ${workerd.length}`);
  execFileSync('taskset', ['-apc', values['workerd-cpus']!, String(workerd[0])], { stdio: 'ignore' });
  console.error(`workerd ${workerd[0]} on cpus ${values['workerd-cpus']}, vault memory ${memory}s`);
}

// --- what is read around a window ---------------------------------------------------------------------------------
// The owner's session, opened again once lost (an outage cell stops Postgres): a session never reconnects by itself.
let session = postgresSession(owner);
const pg = {
  async unsafe(text: string, params?: unknown[]): Promise<Record<string, unknown>[]> {
    try {
      return (await session.unsafe(text, params as never)) as unknown as Record<string, unknown>[];
    } catch (error) {
      void session.end().catch(() => {});
      session = postgresSession(owner);
      throw error;
    }
  },
  end: () => session.end(),
};
const containerCpu = (name: string) => {
  const id = execFileSync('docker', ['inspect', '-f', '{{.Id}}', name], { encoding: 'utf8' }).trim();
  // A stopped container has no cgroup, and a started one counts from zero again: carry what it had used.
  let base = 0;
  let last = 0;
  return () => {
    let now: number;
    try {
      now = Number(/usage_usec (\d+)/.exec(readFileSync(`/sys/fs/cgroup/system.slice/docker-${id}.scope/cpu.stat`, 'utf8'))![1]) / 1000;
    } catch {
      return base + last;
    }
    if (now < last) base += last;
    last = now;
    return base + now;
  };
};
const project = process.env.COMPOSE_PROJECT_NAME!;
{
  const [stop = 0, down = 0] = values.outage!.split(',').filter(Boolean).map(Number);
  if (stop + down >= Number(values.duration)) throw new Error(`the outage (${values.outage}) must end within the measured ${values.duration} s`);
}
const postgresCpu = containerCpu(`${project}-postgres-1`);
const poolCpu = containerCpu(`${project}-pgbouncer`);
function workerdCpu(): number {
  let ns = 0;
  for (const pid of workerd) {
    for (const task of readdirSync(`/proc/${pid}/task`)) {
      try {
        ns += Number(readFileSync(`/proc/${pid}/task/${task}/schedstat`, 'utf8').split(' ')[0]);
      } catch {
        // A thread that ended meanwhile.
      }
    }
  }
  return ns / 1e6;
}
async function bouncer(command: string): Promise<Record<string, string>[]> {
  // An overloaded cell fills PgBouncer's accept queue, and its admin console with it: ask again a few times,
  // then go without its counters rather than lose the cell (the cell records them as missing).
  let out = '';
  for (let attempt = 1; ; attempt++) {
    try {
      out = (await execFile('psql', ['-h', '127.0.0.1', '-p', poolPort, '-U', 'coffre_owner', '-d', 'pgbouncer', '-A', '-F', '\t', '-c', command], { env: { ...process.env, PGPASSWORD: 'local-dev-only', PGCONNECT_TIMEOUT: '5' }, encoding: 'utf8', timeout: 15_000 })).stdout;
      break;
    } catch (error) {
      if (attempt >= 4) {
        console.error(`pgbouncer ${command}: unreachable, counters missing: ${String(error).split('\n')[1] ?? error}`);
        return [];
      }
      console.error(`pgbouncer ${command}: attempt ${attempt} failed, retrying`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
  const [head, ...rows] = out.trim().split('\n').filter((line) => !/^\(\d+ rows?\)$/.test(line));
  const names = head!.split('\t');
  return rows.map((row) => Object.fromEntries(row.split('\t').map((value, i) => [names[i]!, value])));
}
const bouncerStats = async () => Object.fromEntries((await bouncer('SHOW STATS')).filter((row) => row.database === database).map((row) => [row.database, { xacts: Number(row.total_xact_count), queries: Number(row.total_query_count), waitUs: Number(row.total_wait_time) }]));
async function lag(): Promise<{ pending: number; oldestMs: number | null }> {
  // 0.14.7 has no signer: its appends are the log.
  if (old) return { pending: 0, oldestMs: null };
  const [row] = await pg.unsafe(`SELECT count(*)::int AS n, (extract(epoch FROM clock_timestamp()) * 1000 - min((body::jsonb->>'at')::bigint))::int AS oldest FROM log_pending`);
  return { pending: row!.n as number, oldestMs: (row!.oldest as number | null) ?? null };
}
// The host's TCP sockets, as `ss -s` counts them: other agents' runs share these ports.
function tcpSummary() {
  const line = execFileSync('ss', ['-s'], { encoding: 'utf8' }).split('\n').find((l) => l.startsWith('TCP:')) ?? '';
  const n = (key: string) => Number(new RegExp(`${key} (\\d+)`).exec(line)?.[1] ?? NaN);
  return { estab: n('estab'), timewait: n('timewait') };
}
async function sample() {
  const backends = await pg.unsafe(`SELECT usename, state, count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid() GROUP BY 1, 2`, [database]);
  const pools = (await bouncer('SHOW POOLS')).filter((row) => row.database === database).map((row) => ({ user: row.user, clActive: Number(row.cl_active), clWaiting: Number(row.cl_waiting), svActive: Number(row.sv_active), svIdle: Number(row.sv_idle), maxwaitMs: Number(row.maxwait) * 1000 + Number(row.maxwait_us) / 1000 }));
  return { at: Date.now(), load: loadavg()[0], tcp: tcpSummary(), backends: backends.map((b) => ({ user: b.usename, state: b.state, n: b.n })), pools, proxies: await counters(), signer: await lag() };
}
async function statements() {
  return pg.unsafe(`SELECT r.rolname AS login, s.calls::int, round(s.total_exec_time::numeric, 1)::float AS total_ms, round(s.mean_exec_time::numeric, 3)::float AS mean_ms,
    s.rows::int, s.plans::int, round(s.total_plan_time::numeric, 1)::float AS plan_ms, s.shared_blks_hit::int AS hit, s.shared_blks_read::int AS read, left(regexp_replace(s.query, '\\s+', ' ', 'g'), 240) AS query
    FROM pg_stat_statements s JOIN pg_roles r ON r.oid = s.userid
    WHERE s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND r.rolname <> 'coffre_owner' ORDER BY s.calls DESC`);
}
const cellName = (size: number | string, memory: number | string, rate: number | string) =>
  `${values.label}${old ? 'v0147-' : ''}${values.mode === 'reveal' ? values.target : values.mode}${values.mode === 'workload' ? `-s${values.services}` : ''}${values.outage === '' ? '' : `-outage${values['outage-seconds'] ?? 0}`}-log${size}-mem${old ? 'na' : memory}-rate${rate}`;
async function snapshot() {
  const [proxied, bounced] = await Promise.all([counters(), bouncerStats()]);
  return { at: performance.now(), workerd: workerdCpu(), postgres: postgresCpu(), pool: poolCpu(), proxies: proxied, bouncer: bounced, load: loadavg() };
}

// --- the instance and its log ---------------------------------------------------------------------------------------
const worldEnv: NodeJS.ProcessEnv = { ...process.env, BENCH_VAULT_KEY: VAULT_KEY, BENCH_CONTROL_URL: `http://127.0.0.1:${controlPort}`, COFFRE_TEST_DATABASE: database, COFFRE_POSTGRES_PORT: pgPort };
// A child, never a synchronous one: this process carries Miniflare's side of every Hyperdrive connection.
async function world(...args: string[]): Promise<void> {
  // 0.14.7's instance is seeded through its API beforehand (v014/seed.ts), and its log grown by its own appends (v014/grow.ts).
  if (old && args[0] === 'setup') return;
  const child = values.app === 'proxy' && args[0] === 'setup'
    ? spawn(process.execPath, ['--conditions=coffre:source', join(here, 'proxy/world.ts'), dir, values.services!], { env: worldEnv, stdio: 'inherit' })
    : old
    ? spawn(process.execPath, ['--conditions=coffre:source', join(src, 'packages/db/scripts/grow.ts'), owner, args[1]!, APP_KEY], { cwd: join(src, 'packages/db'), stdio: 'inherit' })
    : spawn(process.execPath, ['--conditions=coffre:source', join(here, 'world.ts'), ...args], { env: worldEnv, stdio: 'inherit' });
  const code = await new Promise<number | null>((resolve) => child.on('exit', resolve));
  if (code !== 0) throw new Error(`world.ts ${args.join(' ')} exited ${code}`);
}
async function plans(size: number): Promise<void> {
  const out = join(dir, 'plans');
  mkdirSync(out, { recursive: true });
  const settings = ["session_preload_libraries = 'auto_explain'", 'auto_explain.log_min_duration = 0', 'auto_explain.log_analyze = on', 'auto_explain.log_buffers = on'];
  for (const setting of settings) await pg.unsafe(`ALTER DATABASE ${database} SET ${setting}`);
  const since = new Date().toISOString();
  const child = spawn(process.execPath, ['--conditions=coffre:source', join(here, 'plan-check.ts'), values.plans!], { env: worldEnv, stdio: ['ignore', 'pipe', 'inherit'] });
  let text = '';
  child.stdout.on('data', (chunk) => (text += chunk));
  const code = await new Promise<number | null>((resolve) => child.on('exit', resolve));
  for (const setting of ['session_preload_libraries', 'auto_explain.log_min_duration', 'auto_explain.log_analyze', 'auto_explain.log_buffers']) await pg.unsafe(`ALTER DATABASE ${database} RESET ${setting}`);
  if (code !== 0) throw new Error(`plan-check.ts exited ${code}`);
  writeFileSync(join(out, `log${size}.json`), text);
  const { stderr } = await execFile('docker', ['logs', '--since', since, `${project}-postgres-1`], { maxBuffer: 1 << 28 });
  writeFileSync(join(out, `log${size}.plans.txt`), stderr);
  console.error(`plans at ${size}: ${text.length} bytes of stats, ${stderr.length} of plans`);
}
async function settle(): Promise<void> {
  const until = Date.now() + 120_000;
  for (let quiet = 0; quiet < 3; ) {
    if (Date.now() > until) throw new Error(`the signer has not drained log_pending in 120 s: ${JSON.stringify(await lag())}`);
    quiet = (await lag().catch(() => ({ pending: -1 }))).pending === 0 ? quiet + 1 : 0;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}
async function reveal(port: number): Promise<string> {
  if (values.app === 'proxy' || values.mode !== 'reveal') {
    const { handle } = JSON.parse(readFileSync(join(dir, 'callers.json'), 'utf8')) as { handle: string };
    const used = await fetch(`http://127.0.0.1:${port}/use/market/apis/echo/ping`, { headers: { authorization: `Bearer ${handle}` } });
    return `${used.status} ${(await used.text()).slice(0, 300)}`;
  }
  const response = await fetch(`http://127.0.0.1:${port}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${values.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path: 'bench/prod/KEY_0' }) });
  return `${response.status} ${(await response.text()).slice(0, 300)}`;
}

/** What the vault's entries said of uses answered while the database could not be reached (`detail.unlogged`), newest first. */
async function unlogged(): Promise<unknown[]> {
  await settle();
  const rows = await pg.unsafe(`SELECT body FROM log WHERE body LIKE '%"unlogged"%' UNION ALL SELECT body FROM log_pending WHERE body LIKE '%"unlogged"%'`);
  return rows.map((row) => (JSON.parse(row.body as string) as { detail: { unlogged: unknown } }).detail.unlogged);
}

// --- a cell ---------------------------------------------------------------------------------------------------------
async function cell(size: number, memory: number, rate: number): Promise<void> {
  const name = cellName(size, memory, rate);
  await settle();
  // Idle first, the sampler on: what Postgres and workerd spend with no request, per second, which the window's totals carry too.
  const idleSamples: unknown[] = [];
  const idleFrom = await snapshot();
  for (let i = 0; i < 5; i++) {
    idleSamples.push(await sample());
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  const idleTo = await snapshot();
  const idleSeconds = (idleTo.at - idleFrom.at) / 1000;
  const idle = { workerdMsPerS: (idleTo.workerd - idleFrom.workerd) / idleSeconds, postgresMsPerS: (idleTo.postgres - idleFrom.postgres) / idleSeconds, poolMsPerS: (idleTo.pool - idleFrom.pool) / idleSeconds };
  const target = values.target === 'probe' ? probePort : port;
  const child = spawn('taskset', ['-c', values['load-cpus']!, process.execPath, '--conditions=coffre:source', join(here, 'load.ts'), '--url', `http://127.0.0.1:${target}`, '--rate', String(rate), '--warmup', values.warmup!, '--duration', values.duration!, '--token', values.token!, '--mode', values.mode!, '--connections', values.connections!, ...(values.mode === 'reveal' ? [] : ['--callers', join(dir, 'callers.json')]), '--at', values.outage!.split(',').filter(Boolean).map((n, i, [stop]) => (i === 0 ? n : String(Number(stop) + Number(n)))).join(',')], { stdio: ['ignore', 'pipe', 'inherit'] });
  let before: Awaited<ReturnType<typeof snapshot>> | null = null;
  let after: Awaited<ReturnType<typeof snapshot>> | null = null;
  const samples: Awaited<ReturnType<typeof sample>>[] = [];
  let timer: NodeJS.Timeout | null = null;
  let result: Record<string, unknown> | null = null;
  let sampling = Promise.resolve();
  const marks: { at: number; what: string }[] = [];
  for await (const line of createInterface({ input: child.stdout })) {
    const parsed = JSON.parse(line) as { mark?: string } & Record<string, unknown>;
    if (parsed.mark === 'start') {
      await pg.unsafe('SELECT pg_stat_statements_reset()');
      before = await snapshot();
      timer = setInterval(() => {
        sampling = sampling.then(async () => void samples.push(await sample())).catch((error) => console.error('sample', error));
      }, 1000);
    } else if (parsed.mark === 'at') {
      // The outage: Postgres's container stopped, then started again.
      const stopping = marks.length === 0;
      marks.push({ at: performance.now(), what: stopping ? 'stop' : 'start' });
      void execFile('docker', [stopping ? 'stop' : 'start', `${project}-postgres-1`]).then(() => marks.push({ at: performance.now(), what: stopping ? 'stopped' : 'started' }));
    } else if (parsed.mark === 'end') {
      clearInterval(timer!);
      after = await snapshot();
    } else result = parsed;
  }
  await sampling;
  const used = await statements();
  // The signer after the run: what waits, until nothing does, or 30 s.
  const tail: Awaited<ReturnType<typeof lag>>[] = [];
  for (let i = 0; i < 30; i++) {
    const now = await lag();
    tail.push(now);
    if (now.pending === 0) break;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  if (result === null) throw new Error(`${name}: the load generator gave no result`);
  const n = (result.measured as number) || 1;
  const per = (a: number, b: number) => Math.round(((b - a) / n) * 1000) / 1000;
  const calls = used.reduce((sum, row) => sum + (row.calls as number), 0);
  const summary = {
    name, size, memory, rate, target: values.target, load: result,
    perRequest: {
      workerdCpuMs: per(before!.workerd, after!.workerd),
      postgresCpuMs: per(before!.postgres, after!.postgres),
      pgbouncerCpuMs: per(before!.pool, after!.pool),
      statements: Math.round((calls / n) * 1000) / 1000,
      appSyncs: per(before!.proxies.app!.syncs, after!.proxies.app!.syncs),
      vaultSyncs: per(before!.proxies.vault!.syncs, after!.proxies.vault!.syncs),
      appTrips: per(before!.proxies.app!.trips, after!.proxies.app!.trips),
      vaultTrips: per(before!.proxies.vault!.trips, after!.proxies.vault!.trips),
      appConnections: per(before!.proxies.app!.opened, after!.proxies.app!.opened),
      vaultConnections: per(before!.proxies.vault!.opened, after!.proxies.vault!.opened),
    },
    idle,
    netPerRequest: {
      workerdCpuMs: Math.round((per(before!.workerd, after!.workerd) - (idle.workerdMsPerS * (after!.at - before!.at)) / 1000 / n) * 1000) / 1000,
      postgresCpuMs: Math.round((per(before!.postgres, after!.postgres) - (idle.postgresMsPerS * (after!.at - before!.at)) / 1000 / n) * 1000) / 1000,
    },
    windowSeconds: Math.round((after!.at - before!.at) / 100) / 10,
    hostLoad: { before: before!.load, after: after!.load, max: Math.max(...samples.map((s) => s.load)) },
    peaks: {
      hostTcpEstab: Math.max(...samples.map((s) => s.tcp.estab)),
      hostTcpTimewait: Math.max(...samples.map((s) => s.tcp.timewait)),
      workerdConnectionsOpen: Math.max(...samples.map((s) => (s.proxies.app!.open as number) + (s.proxies.vault!.open as number))),
      // Database connections the proxies closed at once, past their cap (proxy.ts --most).
      proxyRefused: Math.max(0, ...samples.map((s) => ((s.proxies.app!.refused as number | undefined) ?? 0) + ((s.proxies.vault!.refused as number | undefined) ?? 0))),
      postgresBackends: Math.max(...samples.map((s) => s.backends.reduce((sum, b) => sum + b.n, 0))),
      postgresActive: Math.max(...samples.map((s) => s.backends.filter((b) => b.state === 'active').reduce((sum, b) => sum + b.n, 0))),
      poolClientsWaiting: Math.max(...samples.map((s) => s.pools.reduce((sum, p) => sum + p.clWaiting, 0))),
      poolMaxwaitMs: Math.max(...samples.map((s) => Math.max(0, ...s.pools.map((p) => p.maxwaitMs)))),
      signerPending: Math.max(...samples.map((s) => s.signer.pending)),
      signerOldestMs: Math.max(0, ...samples.map((s) => s.signer.oldestMs ?? 0)),
    },
    signerAfter: tail,
    outage: marks.length === 0 ? null : { marks: marks.map((m) => ({ what: m.what, second: Math.round((m.at - before!.at) / 100) / 10 })), unlogged: await unlogged() },
    bouncer: { before: before!.bouncer, after: after!.bouncer },
    statements: used,
    samples,
  };
  writeFileSync(join(dir, 'cells', `${name}.json`), JSON.stringify(summary, null, 1));
  const l = result as Record<string, unknown>;
  console.log(`${name}: p50 ${l.p50} p99 ${l.p99} max ${l.max} ms, ${JSON.stringify(l.codes)}, stmts/req ${summary.perRequest.statements}, syncs/req app ${summary.perRequest.appSyncs} vault ${summary.perRequest.vaultSyncs}, cpu/req workerd ${summary.perRequest.workerdCpuMs} (net ${summary.netPerRequest.workerdCpuMs}) pg ${summary.perRequest.postgresCpuMs} (net ${summary.netPerRequest.postgresCpuMs}) ms, load ${summary.hostLoad.max.toFixed(0)}, sendLateMax ${l.sendLateMaxMs}`);
}

// --- the matrix -----------------------------------------------------------------------------------------------------
try {
  if (values.fresh) {
    rmSync(persist, { recursive: true, force: true });
    await world('setup');
  }
  const memories = list(values.memory!);
  await boot(memories[0]!);
  // The first reveal's entry wakes the signer, which adopts what setup wrote.
  console.error(`first reveal: ${await reveal(port)}`);
  await settle();
  let booted = memories[0]!;
  for (const size of list(values.sizes!)) {
    await world('grow', String(size));
    await settle();
    if (Number(values.plans) > 0) await plans(size);
    for (const memory of memories) {
      if (memory !== booted) {
        await boot(memory);
        booted = memory;
      }
      for (const rate of list(values.rates!)) {
        // A rerun without --fresh resumes: a cell already written stands.
        if (!values.fresh && existsSync(join(dir, 'cells', `${cellName(size, memory, rate)}.json`))) continue;
        await cell(size, memory, rate);
      }
    }
  }
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  proxyProcess.kill();
  await Promise.race([Promise.allSettled([mf?.dispose(), pg.end()]), new Promise((resolve) => setTimeout(resolve, 5000))]);
  process.exit(process.exitCode ?? 0);
}
