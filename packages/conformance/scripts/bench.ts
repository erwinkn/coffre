// The CPU each request costs a deployment, as conformance boots it: on
// Workers, both Workers' workerd; on Node, the server and the vault apart.
// Each path is asked in a new isolate or process first (cold), then again
// (warm), on a log as large as `--entries` and as many members as
// `--members`. A request's CPU is the processes' own, read from Linux's
// per-thread counters until they are quiet again, so the work it leaves
// behind (`waitUntil`) counts too. `/livez`, which does nothing, is the
// floor: what any request costs the runtime itself.
//
//   pnpm build, then
//   pnpm bench:workers [--entries 10000] [--members 200]
//   pnpm bench:node [--entries 10000]
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as sleep } from 'node:timers/promises';

import type { CoffreClient } from '@coffre/client';

import { bearer, Browser } from '../src/browser.ts';
import { deviceLogin, personaOn, signIn, signInAdmin } from '../src/checks/people.ts';
import { boot, type Deployment, type Kind } from '../src/harness.ts';

const USAGE = `usage: bench.ts workers|node <dir> [--entries <n>] [--members <n>] [--keys <n>] [--warm <n>] [--cold <n>] [--port <n>]
  [--postgres <url> --runtime <url> --vault-runtime <url>]   workers: as coffre-conformance takes them`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    entries: { type: 'string', default: '0' },
    members: { type: 'string', default: '0' },
    keys: { type: 'string', default: '30' },
    warm: { type: 'string', default: '8' },
    cold: { type: 'string', default: '3' },
    only: { type: 'string' },
    port: { type: 'string', default: '3182' },
    postgres: { type: 'string' },
    runtime: { type: 'string' },
    'vault-runtime': { type: 'string' },
  },
});
const [kind, dir] = positionals as [Kind, string];
if ((kind !== 'workers' && kind !== 'node') || dir === undefined) {
  console.error(USAGE);
  process.exit(2);
}
if (!readdirSync('/proc').includes('self')) {
  console.error('bench.ts reads Linux per-thread CPU counters (/proc/<pid>/task/*/schedstat): run it on Linux');
  process.exit(2);
}
const count = (name: keyof typeof values) => Number(values[name]);
for (const name of ['entries', 'members', 'keys', 'warm', 'cold', 'port'] as const) {
  if (!Number.isInteger(count(name)) || count(name) < (name === 'keys' || name === 'port' ? 1 : 0)) {
    console.error(`--${name} takes a whole number${name === 'keys' || name === 'port' ? ' above zero' : ''}\n${USAGE}`);
    process.exit(2);
  }
}
// The environment's reveals read every key, each sample as the same reader and the same service account, and the
// examples' vault keeps its default bulk limit: 1000 keys per principal in 15 minutes, which a restart does not reset.
const released = count('keys') * (count('cold') + 1 + count('warm'));
if (released > 1000) {
  console.error(`--keys ${count('keys')} over ${count('cold')} cold and ${count('warm') + 1} warm samples reads ${released} keys as one reader, past the vault's bulk limit of 1000 in 15 minutes: lower one of them`);
  process.exit(2);
}

// --- CPU, from /proc ---------------------------------------------------------

/**
 * Every process in these process groups, by group name. On Workers, the
 * workerd that runs the app and the vault, and not wrangler's own, which
 * answers on the port and hands each request on, as no deployment does.
 */
function processes(groups: Record<string, number>): Map<string, number[]> {
  const proxy = `--socket-addr=entry=127.0.0.1:${values.port}`;
  const found = new Map<string, number[]>(Object.keys(groups).map((name) => [name, []]));
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let stat: string;
    try {
      stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
    } catch {
      continue;
    }
    const command = stat.slice(stat.indexOf('(') + 1, stat.lastIndexOf(')'));
    const group = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[2]);
    for (const [name, pgid] of Object.entries(groups)) {
      if (group !== pgid) continue;
      if (kind === 'workers' && (command !== 'workerd' || cmdline(entry).includes(proxy))) continue;
      found.get(name)!.push(Number(entry));
    }
  }
  for (const [name, pids] of found) {
    if (pids.length === 0) throw new Error(`no ${kind === 'workers' ? 'workerd running the Workers' : 'process'} in ${name}'s process group to measure`);
  }
  return found;
}

function cmdline(pid: string): string[] {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
  } catch {
    return [];
  }
}

/**
 * Milliseconds on CPU so far, by group: every thread's, from its schedstat,
 * in nanoseconds. A process that is gone, or whose counters cannot be read,
 * fails the measurement; a thread that ended between listing and reading is
 * passed over, as it no longer runs.
 */
function cpu(of: Map<string, number[]>): Record<string, number> {
  const total = (pid: number) => {
    let ns = 0;
    for (const task of readdirSync(`/proc/${pid}/task`)) {
      let schedstat: string;
      try {
        schedstat = readFileSync(`/proc/${pid}/task/${task}/schedstat`, 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT' || (error as NodeJS.ErrnoException).code === 'ESRCH') continue;
        throw error;
      }
      const onCpu = Number(schedstat.split(' ')[0]);
      if (!Number.isFinite(onCpu)) throw new Error(`unreadable CPU counter for thread ${task} of process ${pid}: ${schedstat}`);
      ns += onCpu;
    }
    return ns / 1e6;
  };
  return Object.fromEntries([...of].map(([name, pids]) => [name, pids.reduce((sum, pid) => sum + total(pid), 0)]));
}

/** The CPU `request` costs, by group, counted until the processes are quiet: 150ms without a tenth of a millisecond more. */
async function measure(deployment: Deployment, request: () => Promise<unknown>): Promise<Record<string, number>> {
  const of = processes(deployment.serving());
  const before = cpu(of);
  await request();
  let last = cpu(of);
  for (let quiet = 0; quiet < 3; ) {
    await sleep(50);
    const now = cpu(of);
    const moved = Object.keys(now).reduce((sum, name) => sum + now[name] - last[name], 0);
    quiet = moved < 0.1 ? quiet + 1 : 0;
    last = now;
  }
  return Object.fromEntries(Object.keys(last).map((name) => [name, last[name] - before[name]]));
}

// --- what is asked -------------------------------------------------------------

const PROJECT = 'bench';
const APP = `${PROJECT}/app`;
const GROW = `${PROJECT}/grow`;

type Who = { browser: Browser; api: CoffreClient };
type Path = { name: string; request: () => Promise<unknown>; workersOnly?: boolean };

async function ok(response: Response): Promise<void> {
  const body = await response.text();
  if (!response.ok && response.status !== 307) throw new Error(`${response.url} answered ${response.status}: ${body.slice(0, 300)}`);
}

function paths(deployment: Deployment, people: { admin: Who; reader: Who; service: string; cli: string }): Path[] {
  const { origin } = deployment;
  const as = (token: string) => ({ authorization: `Bearer ${token}`, 'content-type': 'application/json' });
  const reveal = (path: string) => ({ method: 'POST', body: JSON.stringify({ path }) });
  return [
    { name: 'GET /livez (the floor)', request: async () => ok(await fetch(`${origin}/livez`)) },
    { name: 'GET /api/me, browser session', request: async () => ok(await people.admin.browser.send('GET', '/api/me')) },
    { name: 'GET /api/me, CLI session', request: async () => ok(await fetch(`${origin}/api/me`, { headers: as(people.cli) })) },
    { name: 'POST /api/reveals, one key', request: async () => ok(await people.admin.browser.send('POST', '/api/reveals', { path: `${APP}/KEY_0` })) },
    { name: `POST /api/reveals, ${count('keys')} keys`, request: async () => ok(await people.reader.browser.send('POST', '/api/reveals', { path: APP })) },
    { name: 'export: reveals as a service', request: async () => ok(await fetch(`${origin}/api/reveals`, { ...reveal(APP), headers: as(people.service) })) },
    { name: 'export --watch: version', request: async () => ok(await fetch(`${origin}/api/projects/${APP}/version`, { headers: as(people.service) })) },
    { name: 'GET /api/secrets (list)', request: async () => ok(await people.admin.browser.send('GET', `/api/secrets/${APP}`)) },
    { name: 'page: environment', request: async () => ok(await people.admin.browser.fetch(`/projects/${APP}`)) },
    { name: 'page: project', request: async () => ok(await people.admin.browser.fetch(`/projects/${PROJECT}`)) },
    { name: 'GET /api/audit', request: async () => ok(await people.admin.browser.send('GET', '/api/audit')) },
    { name: 'page: audit', request: async () => ok(await people.admin.browser.fetch('/audit')) },
    {
      name: 'sign-in (GitHub, both legs)',
      request: async () => {
        const signed = await signIn(deployment, new Browser(origin), deployment.owner);
        if (!signed.ok) throw new Error(`sign-in refused: ${signed.error}`);
      },
    },
    { name: 'cron: heartbeat + checkpoint', workersOnly: true, request: () => deployment.scheduled() },
  ];
}

// --- the deployment, and its data -----------------------------------------------

async function populate(deployment: Deployment) {
  const { value: admin } = await signInAdmin(deployment);
  await admin.api.projects.create(PROJECT, { name: 'Bench' });
  for (const path of [APP, GROW]) await admin.api.environments.create(path, { name: path });
  await admin.api.secrets.set(APP, Object.fromEntries(Array.from({ length: count('keys') }, (_, i) => [`KEY_${i}`, `fake-value-${i}`])));
  const reader = await personaOn(deployment, admin, 'reader', { [APP]: 'viewer' });
  // An instance in use: its policy changed now and then, and the reader's access too, which each check reads the newest of.
  for (let i = 0; i < 20; i++) {
    await admin.api.environments.protect(GROW, i % 2 === 0);
    await admin.api.access.set(reader.member, { [APP]: i % 2 === 0 ? 'developer' : 'viewer' });
  }
  const service = 'token:bench-ci';
  await admin.api.members.add(service);
  await admin.api.access.set(service, { [APP]: 'viewer' });
  const { token } = await admin.api.tokens.issue(service, { label: 'bench', expiresInDays: 1 });
  const cli = await deviceLogin(deployment, admin.browser);
  for (let i = 0; i < count('members'); i++) {
    const member = `user:member-${i}@bench.example`;
    await admin.api.members.add(member);
    await admin.api.access.set(member, { [APP]: 'viewer' });
  }
  // The log grown to size by writes, each an entry of the app's and one of the vault's, eight at a time.
  const sql = await deployment.database();
  const entries = async () => Number((await sql.query<{ n: string }>('SELECT count(*) AS n FROM audit_log'))[0].n);
  let written = await entries();
  while (written < count('entries')) {
    let next = 0;
    const writes = Math.ceil((count('entries') - written) / 2);
    await Promise.all(Array.from({ length: 8 }, async () => {
      for (let i = next++; i < writes; i = next++) await admin.api.secrets.set(GROW, { [`GROW_${i % 100}`]: `fake-${written}-${i}` });
    }));
    written = await entries();
  }
  await sql.close();
  // A checkpoint over all of it, as the cron would have signed by now.
  await deployment.scheduled();
  return { admin, reader, service: token, cli, entries: written };
}

const deployment = await boot(kind, resolve(dir), {
  port: Number(values.port),
  postgres: values.postgres,
  runtime: values.runtime,
  vaultRuntime: values['vault-runtime'],
});
try {
  const people = await populate(deployment);
  console.log(`${kind}: ${people.entries} log entries, ${count('members')} more members, ${count('keys')} keys`);
  const asked = paths(deployment, people).filter((path) => (kind === 'workers' || !path.workersOnly) && (values.only === undefined || path.name.includes(values.only)));
  const cold = new Map<string, Record<string, number>[]>();
  for (let round = 0; round < count('cold'); round++) {
    for (const path of asked) {
      await deployment.restart();
      // A new browser session's sign-in, so that the restart is the request's only news.
      cold.set(path.name, [...(cold.get(path.name) ?? []), await measure(deployment, path.request)]);
    }
  }
  const warm = new Map<string, Record<string, number>[]>();
  for (const path of asked) {
    await measure(deployment, path.request);
    for (let i = 0; i < count('warm'); i++) warm.set(path.name, [...(warm.get(path.name) ?? []), await measure(deployment, path.request)]);
  }
  report(asked, cold, warm);
} finally {
  await deployment.stop();
}

function report(asked: Path[], cold: Map<string, Record<string, number>[]>, warm: Map<string, Record<string, number>[]>): void {
  const median = (xs: number[]) => {
    const sorted = [...xs].sort((a, b) => a - b);
    return sorted.length === 0 ? NaN : sorted[Math.floor((sorted.length - 1) / 2)];
  };
  const max = (xs: number[]) => Math.max(...xs);
  const groups = Object.keys(deployment.serving());
  const cell = (samples: Record<string, number>[] | undefined, of: (xs: number[]) => number) =>
    samples === undefined || samples.length === 0
      ? '-'
      : groups.map((group) => of(samples.map((sample) => sample[group] ?? 0)).toFixed(1)).join(' + ');
  const unit = groups.length === 1 ? 'ms CPU' : `ms CPU (${groups.join(' + ')})`;
  console.log(`\n| path | cold, median | warm, median | warm, max |\n|---|---|---|---|`);
  for (const path of asked) console.log(`| ${path.name} | ${cell(cold.get(path.name), median)} | ${cell(warm.get(path.name), median)} | ${cell(warm.get(path.name), max)} |`);
  console.log(`\n${unit}; cold: the first request after a restart, ${count('cold')} times; warm: ${count('warm')} times after one more.`);
}
