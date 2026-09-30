// Run a deployment made like `coffre init` makes one, unedited: settings go
// in as the environment its wrangler.jsonc or server.env would give it, with
// GitHub's URLs pointed at a stand-in IdP running in this process.
//
//   workers  two Workers under `wrangler dev`, on a Postgres database of
//            their own, created for the run and dropped after
//   node     the server and its vault process, on SQLite in a temp dir
//
// Ports: coffre on `port`, the IdP on the next, wrangler's inspector on the
// one after.
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import { postgres, sqlite, using, type Sql } from './database.ts';
import { DevIdp } from './idp/index.ts';
import { Failure, until } from './report.ts';

export type Kind = 'workers' | 'node';

export type HarnessOptions = {
  port: number;
  /** Postgres as a login that may create databases; workers only. */
  postgres?: string;
  /** The same server as coffre_runtime, the login the app runs as; workers only. */
  runtime?: string;
};

export type Deployment = {
  kind: Kind;
  origin: string;
  idp: DevIdp;
  /** The one root admin the vault is told of. */
  rootAdmin: string;
  /** Whether the heartbeat was made an hour old, so /readyz fails until `scheduled` runs. */
  staleHeartbeat: boolean;
  /** What the Cron trigger does every five minutes. */
  scheduled(): Promise<void>;
  /** The app's database, as its owner. */
  database(): Promise<Sql>;
  /** The app's database as the login the app runs as, on an engine that has logins. */
  runtime: (() => Promise<Sql>) | null;
  /** The file holding the app's database, when it is one. */
  databaseFile: string | null;
  /** The vault's SQLite file, when it can be found: the Durable Object's lives in wrangler's state. */
  vaultStore(): string | null;
  /** The processes' output: all of it, or the last `tail` characters of each. */
  output(tail?: number): string;
  stop(): Promise<void>;
};

// Local fixtures, as in .env.dev: none of them is a secret anywhere else.
const KEYS = {
  KEK_ID: 'conformance-1',
  KEK: 'Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE=',
  SIGNING_KEY: 'Y29mZnJlLWxvY2FsLXZhdWx0LXNpZ25pbmctc2VlZCE=',
  AUDIT_CHAIN_KEY: 'Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI=',
};
const ROOT_ADMIN = 'root@conformance.example';

type Child = { name: string; child: ChildProcess; daemon: boolean; exited: boolean; output: Buffer[] };

export async function boot(kind: Kind, at: string, options: HarnessOptions): Promise<Deployment> {
  const { port } = options;
  const dir = resolve(at);
  const origin = `http://127.0.0.1:${port}`;
  for (const taken of [port, port + 1, port + 2]) {
    const busy = await fetch(`http://127.0.0.1:${taken}/`).then(
      () => true,
      () => false,
    );
    if (busy) throw new Failure(`port ${taken} is taken; pass --port for a free run of three`);
  }
  if (kind === 'workers' && (options.postgres === undefined || options.runtime === undefined)) {
    throw new Failure('workers run on Postgres: pass --postgres <owner URL> and --runtime <coffre_runtime URL>');
  }

  const scratch = mkdtempSync(join(tmpdir(), `coffre-conformance-${kind}-`));
  // The shell's own COFFRE_* (a sourced .env.dev, say) must not reach the
  // deployment: it gets what it is handed here, and nothing else.
  const shell = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
  const children: Child[] = [];
  const output = (tail = Infinity) =>
    children.map((entry) => `--- ${entry.name}\n${Buffer.concat(entry.output).toString('utf8').slice(-tail)}`).join('\n');
  const logs = () => output(4000);
  const alive = () => !children.some((entry) => entry.daemon && entry.exited);

  function start(name: string, command: string, args: string[], env: Record<string, string>, daemon = true): Child {
    const child = spawn(command, args, {
      cwd: dir,
      env: { ...shell, ...env },
      // Its own process group, so stopping it stops what it started (workerd).
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const entry: Child = { name, child, daemon, exited: false, output: [] };
    child.stdout!.on('data', (chunk: Buffer) => entry.output.push(chunk));
    child.stderr!.on('data', (chunk: Buffer) => entry.output.push(chunk));
    child.once('exit', () => (entry.exited = true));
    // Not started at all: no 'exit' may follow.
    child.once('error', (error) => {
      entry.output.push(Buffer.from(`${error.message}\n`));
      entry.exited = true;
    });
    children.push(entry);
    return entry;
  }

  async function run(command: string, args: string[]): Promise<void> {
    const entry = start(args[0] ?? command, command, args, {}, false);
    const code = await new Promise((done) => {
      entry.child.once('exit', done);
      entry.child.once('error', done);
    });
    if (code !== 0) throw new Failure(`${command} ${args.join(' ')} failed`, Buffer.concat(entry.output).toString('utf8'));
  }

  function bin(name: string): string {
    const path = join(dir, 'node_modules/.bin', name);
    if (!existsSync(path)) throw new Failure(`${path} is missing: install ${dir} first`);
    return path;
  }

  const idp = new DevIdp();
  idp.listenPort = port + 1;
  await idp.start();
  const github = {
    GITHUB_CLIENT_ID: 'coffre-local',
    GITHUB_CLIENT_SECRET: 'coffre-local-secret',
    GITHUB_URL: `${idp.origin}/github`,
    GITHUB_API_URL: `${idp.origin}/github/api`,
  };

  let cleanup = async () => {};
  async function stop(): Promise<void> {
    for (const signal of ['SIGTERM', 'SIGKILL'] as const) {
      for (const { child, exited } of children) {
        if (!exited) {
          try {
            process.kill(-child.pid!, signal);
          } catch {}
        }
      }
      await sleep(500);
    }
    await idp.stop().catch(() => {});
    await cleanup().catch(() => {});
    rmSync(scratch, { recursive: true, force: true });
  }

  try {
    const deployment =
      kind === 'workers'
        ? await startWorkers()
        : await startNode();
    await until(`${origin}/livez`, async () => (await fetch(`${origin}/livez`)).ok, 120, alive);
    return deployment;
  } catch (error) {
    const seen = logs();
    await stop();
    if (error instanceof Failure) throw new Failure(error.message, `${error.detail ?? ''}\n${seen}`.trim());
    throw error;
  }

  async function startWorkers(): Promise<Deployment> {
    const name = `coffre_conformance_${randomBytes(4).toString('hex')}`;
    const owner = withDatabase(options.postgres!, name);
    const runtime = withDatabase(options.runtime!, name);
    await using(postgres(withDatabase(options.postgres!, 'postgres')), (sql) => sql.exec(`CREATE DATABASE ${name}`));
    cleanup = () =>
      using(postgres(withDatabase(options.postgres!, 'postgres')), (sql) =>
        sql.exec(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`),
      );
    await run(bin('coffre-server'), ['migrate', owner]);
    // The migration stamps the heartbeat as it runs; make it an hour old, so
    // only the scheduled job can make /readyz pass.
    await using(postgres(owner), (sql) =>
      sql.exec("UPDATE audit_heartbeat SET last_beat_at = now() - interval '1 hour' WHERE only_row"),
    );
    const state = join(scratch, 'state');
    start('wrangler', bin('wrangler'), [
      'dev',
      ...['-c', 'app/wrangler.jsonc', '-c', 'vault/wrangler.jsonc'],
      ...['--ip', '127.0.0.1', '--port', String(port), '--inspector-port', String(port + 2)],
      ...['--persist-to', state, '--show-interactive-dev-session=false'],
      // Not in wrangler.jsonc's vars, so not taken from the environment.
      ...['--var', `GITHUB_URL:${github.GITHUB_URL}`, '--var', `GITHUB_API_URL:${github.GITHUB_API_URL}`],
    ], {
      // Wrangler hands each Worker the vars and secrets its own
      // wrangler.jsonc declares, from here: the app never sees a KEK.
      PUBLIC_URL: origin,
      GITHUB_CLIENT_ID: github.GITHUB_CLIENT_ID,
      GITHUB_CLIENT_SECRET: github.GITHUB_CLIENT_SECRET,
      AUDIT_CHAIN_KEY: KEYS.AUDIT_CHAIN_KEY,
      KEK_ID: KEYS.KEK_ID,
      KEK: KEYS.KEK,
      SIGNING_KEY: KEYS.SIGNING_KEY,
      ROOT_ADMINS: ROOT_ADMIN,
      CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE: runtime,
      WRANGLER_SEND_METRICS: 'false',
    });
    return {
      kind,
      origin,
      idp,
      rootAdmin: ROOT_ADMIN,
      staleHeartbeat: true,
      async scheduled() {
        const response = await fetch(`${origin}/cdn-cgi/local/scheduled?cron=*/5+*+*+*+*`);
        if (!response.ok) throw new Failure(`the scheduled handler answered ${response.status}`, `${await response.text()}\n${logs()}`);
      },
      database: () => postgres(owner),
      runtime: () => postgres(runtime),
      databaseFile: null,
      vaultStore: () => durableObjectFile(join(state, 'v3', 'do'), 'VaultObject'),
      output,
      stop,
    };
  }

  async function startNode(): Promise<Deployment> {
    const database = join(scratch, 'coffre.db');
    const socket = join(scratch, 'vault.sock');
    const store = join(scratch, 'vault.db');
    await run(bin('coffre-server'), ['migrate', `file:${database}`]);
    start('vault', process.execPath, ['src/vault.ts'], {
      VAULT_SOCKET: socket,
      VAULT_STORE: store,
      KEK_ID: KEYS.KEK_ID,
      KEK: KEYS.KEK,
      SIGNING_KEY: KEYS.SIGNING_KEY,
      ROOT_ADMINS: ROOT_ADMIN,
    });
    await until('the vault socket', async () => existsSync(socket), 30, alive);
    const startServer = () =>
      start('server', process.execPath, ['src/server.ts'], {
        PORT: String(port),
        PUBLIC_URL: origin,
        DATABASE_URL: `file:${database}`,
        VAULT_SOCKET: socket,
        AUDIT_CHAIN_KEY: KEYS.AUDIT_CHAIN_KEY,
        ...github,
      });
    let server = startServer();
    return {
      kind,
      origin,
      idp,
      rootAdmin: ROOT_ADMIN,
      staleHeartbeat: false,
      // `serve` runs the job as it starts, and every five minutes after:
      // so restart the server.
      async scheduled() {
        const exited = new Promise((done) => server.child.once('exit', done));
        server.daemon = false;
        process.kill(-server.child.pid!, 'SIGTERM');
        await exited;
        server = startServer();
        await until('the restarted server', async () => (await fetch(`${origin}/readyz`)).ok, 30, alive);
      },
      database: async () => sqlite(database),
      runtime: null,
      databaseFile: database,
      vaultStore: () => store,
      output,
      stop,
    };
  }
}

function withDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.href;
}

/** Where miniflare keeps a Durable Object's SQLite: `<class dir>/<id>.sqlite`. */
function durableObjectFile(root: string, className: string): string | null {
  if (!existsSync(root)) return null;
  for (const entry of readdirSync(root)) {
    if (!entry.endsWith(`-${className}`)) continue;
    const files = readdirSync(join(root, entry)).filter((file) => file.endsWith('.sqlite') && file !== 'metadata.sqlite');
    if (files.length === 1) return join(root, entry, files[0]!);
  }
  return null;
}
