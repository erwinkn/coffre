// Stand-ins for what `coffre setup` reaches on Workers: Cloudflare's API,
// GitHub, wrangler, a browser, and a terminal in memory. No test reaches
// the real ones.
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';

import { stopWranglers } from '../src/cloudflare.ts';
import { templateDir } from '../src/init.ts';

async function body(request: IncomingMessage): Promise<string> {
  let text = '';
  for await (const chunk of request) text += String(chunk);
  return text;
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as { port: number }).port}`)));
}

export type Origin = { scheme?: string; host: string; port: number; database: string; user: string; password: string };
export type FakeConfig = { id: string; name: string; origin: Origin; caching: { disabled: boolean } };

/** Cloudflare's API, as setup and wrangler call it, under one token. */
export async function fakeCloudflare(token: string) {
  const state = {
    accounts: [
      { id: 'acc-acme', name: 'Acme' },
      { id: 'acc-home', name: 'Home' },
    ],
    zones: { 'acc-acme': [{ id: 'zone-1', name: 'acme.test' }], 'acc-home': [] } as Record<string, { id: string; name: string }[]>,
    configs: new Map<string, FakeConfig[]>(),
    /** Each Worker deployed, `<account>/<name>`: the names of its secrets, and its bindings. */
    scripts: new Map<string, { secrets: Set<string>; bindings: unknown[] }>(),
    requests: [] as { method: string; path: string; body: string }[],
    email: 'ops@acme.test' as string | null,
  };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');
    const text = await body(request);
    state.requests.push({ method: request.method ?? '', path: url.pathname + url.search, body: text });
    const send = (status: number, result: unknown, errors: { code: number; message: string }[] = [], info?: unknown) =>
      response.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ success: status < 400, errors, messages: [], result, result_info: info }));
    /** A list a page at a time, as Cloudflare gives one. */
    const page = (all: unknown[]) => {
      const size = Number(url.searchParams.get('per_page') ?? 20);
      const at = Number(url.searchParams.get('page') ?? 1);
      return send(200, all.slice((at - 1) * size, at * size), [], { page: at, per_page: size, total_count: all.length, total_pages: Math.ceil(all.length / size) });
    };
    if (request.headers.authorization !== `Bearer ${token}`) return send(401, null, [{ code: 10000, message: 'Authentication error' }]);
    const path = url.pathname.replace(/^\/client\/v4/, '');
    let match: RegExpExecArray | null;
    if (path === '/accounts') return page(state.accounts);
    if (path === '/user') return state.email === null ? send(403, null, [{ code: 9109, message: 'Unauthorized' }]) : send(200, { email: state.email });
    if (path === '/zones') return page(state.zones[url.searchParams.get('account.id') ?? ''] ?? []);
    if ((match = /^\/accounts\/([^/]+)\/hyperdrive\/configs(?:\/([^/]+))?$/.exec(path)) !== null) {
      const [, account, id] = match;
      const configs = state.configs.get(account!) ?? [];
      state.configs.set(account!, configs);
      const visible = ({ origin: { password: _password, ...origin }, ...config }: FakeConfig) => ({ ...config, origin });
      if (id === undefined && request.method === 'GET') return send(200, configs.map(visible));
      if (id === undefined && request.method === 'POST') {
        const made = { id: `hd-${randomBytes(4).toString('hex')}`, caching: { disabled: false }, ...JSON.parse(text) } as FakeConfig;
        configs.push(made);
        return send(200, visible(made));
      }
      const config = configs.find((each) => each.id === id);
      if (config === undefined) return send(404, null, [{ code: 2008, message: 'Hyperdrive config not found' }]);
      if (request.method === 'PUT') Object.assign(config, JSON.parse(text));
      else if (request.method === 'PATCH') Object.assign(config, JSON.parse(text));
      return send(200, visible(config));
    }
    if ((match = /^\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)(\/secrets|\/settings)?$/.exec(path)) !== null) {
      const [, account, name, part] = match;
      const key = `${account}/${name}`;
      const script = state.scripts.get(key);
      if (part !== undefined && request.method === 'GET') {
        if (script === undefined) return send(404, null, [{ code: 10007, message: 'This Worker does not exist on your account.' }]);
        if (part === '/settings') return send(200, { bindings: script.bindings, compatibility_date: '2026-08-06' });
        return send(200, [...script.secrets].map((each) => ({ name: each, type: 'secret_text' })));
      }
      // Only the fake wrangler's deploy: the Worker, its bindings, and the secrets it was given, which stay.
      if (part === undefined && request.method === 'PUT') {
        const deployed = JSON.parse(text) as { secrets: string[]; bindings: unknown[] };
        const secrets = script?.secrets ?? new Set<string>();
        for (const each of deployed.secrets) secrets.add(each);
        state.scripts.set(key, { secrets, bindings: deployed.bindings });
        return send(200, { id: name });
      }
    }
    send(404, null, [{ code: 7003, message: 'No route for that URI' }]);
  });
  const url = `${await listen(server)}/client/v4`;
  return { url, state, close: () => (server.closeAllConnections(), server.close()) };
}

/** GitHub, as its App manifest flow goes: the form posted, Create clicked at once, the code converted, once. */
export async function fakeGitHub() {
  const state = {
    manifests: [] as Record<string, unknown>[],
    codes: new Map<string, { client_id: string; client_secret: string; slug: string }>(),
  };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');
    if (request.method === 'POST' && url.pathname === '/settings/apps/new') {
      const manifest = JSON.parse(new URLSearchParams(await body(request)).get('manifest')!) as Record<string, unknown>;
      // A manifest's permissions go by the form's names, as GitHub checks them: `emails`, not the API's `email_addresses`.
      const unknown = Object.keys((manifest.default_permissions ?? {}) as object).filter((name) => !['emails', 'members', 'metadata'].includes(name));
      if (unknown.length > 0) return response.writeHead(422).end('Default permission records resource is not included in the list');
      state.manifests.push(manifest);
      const code = randomBytes(10).toString('hex');
      state.codes.set(code, { client_id: `Iv23li${randomBytes(7).toString('hex')}`, client_secret: randomBytes(20).toString('hex'), slug: String(manifest.name) });
      const back = new URL(String(manifest.redirect_url));
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state') ?? '');
      return response.writeHead(302, { location: back.href }).end();
    }
    const conversion = /^\/api\/v3\/app-manifests\/([^/]+)\/conversions$/.exec(url.pathname);
    if (request.method === 'POST' && conversion !== null) {
      const app = state.codes.get(conversion[1]!);
      state.codes.delete(conversion[1]!);
      if (app === undefined) return response.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ message: 'Not Found' }));
      return response.writeHead(201, { 'content-type': 'application/json' }).end(
        JSON.stringify({ ...app, id: 1, pem: '-----BEGIN RSA PRIVATE KEY-----', webhook_secret: 'whsec', html_url: `https://github.com/apps/${app.slug}` }),
      );
    }
    response.writeHead(404).end();
  });
  const web = await listen(server);
  return { github: { web, api: `${web}/api/v3` }, state, close: () => (server.closeAllConnections(), server.close()) };
}

const unescape = (text: string) => text.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&amp;/g, '&');

/** The manifest form in a page, as a browser reads it: where it posts, and what. */
export function manifestForm(html: string): { action: string; manifest: string } {
  const action = /<form method="?post"? action="([^"]+)"/.exec(html)![1]!;
  const manifest = /name="?manifest"? value=(?:"([^"]*)"|'([^']*)')/.exec(html)!;
  return { action: unescape(action), manifest: unescape(manifest[1] ?? manifest[2]!) };
}

/** A browser on this machine: the page loaded, its form posted, GitHub followed back. Returns where GitHub sent it. */
export async function submitManifest(html: string): Promise<string> {
  const { action, manifest } = manifestForm(html);
  const created = await fetch(action, { method: 'POST', body: new URLSearchParams({ manifest }), redirect: 'manual' });
  return created.headers.get('location')!;
}

/** The real wrangler, the version the Workers template pins, as the repository installed it for the example. */
export function realWrangler(): string {
  const require = createRequire(join(templateDir('workers'), 'package.json'));
  return join(dirname(require.resolve('wrangler/package.json')), 'bin', 'wrangler.js');
}

/**
 * wrangler, in a deployment's node_modules/.bin, as setup runs it: each call
 * in `<state>/calls.jsonl`, with what came on its stdin. `login` listens
 * for its callback as wrangler does, and says where in `<state>/login`;
 * `deploy` tells the fake API the Worker exists, with its bindings and the
 * secrets it got, unless `<state>/fail-<name>` says to fail. With `real`,
 * the real wrangler first deploys the same files with the same stdin, in a
 * dry run, with a stub for the Worker's code and no assets: what it says
 * is in `<state>/dry-<name>`, and a refusal fails the deploy. Each call
 * says its pid in `<state>/pid-<command>`. With `<state>/listen-late`,
 * `login` answers nothing for a while after printing its link, as the real
 * one, which prints it before it listens, may not: the file says how long,
 * in milliseconds (700 when empty). With `<state>/slow`, `deploy` takes a
 * minute.
 */
export function fakeWrangler(dir: string, state: string, token: string, real?: string): void {
  mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
  mkdirSync(join(state, 'assets'), { recursive: true });
  writeFileSync(join(state, 'stub.js'), 'export default { fetch: () => new Response("ok") };\n');
  const jsonc = createRequire(import.meta.url).resolve('jsonc-parser');
  const script = `#!${process.execPath}
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import jsonc from ${JSON.stringify(jsonc)};
const STATE = ${JSON.stringify(state)};
const REAL = ${JSON.stringify(real ?? null)};
const args = process.argv.slice(2);
// What a test waits for, whole the moment it exists: written beside it, then renamed, never seen empty.
const publish = (path, text) => {
  writeFileSync(path + '.partial', text);
  renameSync(path + '.partial', path);
};
publish(STATE + '/pid-' + args[0], String(process.pid));
// The secrets file by its path, as wrangler reads it: /dev/stdin must open as a file.
const stdin = args.includes('--secrets-file') ? readFileSync(args[args.indexOf('--secrets-file') + 1], 'utf8') : '';
appendFileSync(STATE + '/calls.jsonl', JSON.stringify({ args, stdin, account: process.env.CLOUDFLARE_ACCOUNT_ID ?? null }) + '\\n');
if (args[0] === 'auth') {
  if (!existsSync(STATE + '/token')) { console.error('You are not authenticated. Please run \`wrangler login\`.'); process.exit(1); }
  console.log(JSON.stringify({ type: 'oauth', token: readFileSync(STATE + '/token', 'utf8') }));
} else if (args[0] === 'login') {
  const state = 'st' + Math.random().toString(36).slice(2);
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (url.pathname !== '/oauth/callback' || url.searchParams.get('state') !== state || !url.searchParams.get('code')) return response.writeHead(400).end();
    writeFileSync(STATE + '/token', ${JSON.stringify(token)});
    response.end('You have granted authorization.');
    server.close();
    console.log('Successfully logged in.');
  });
  const announce = (port) => {
    publish(STATE + '/login', JSON.stringify({ port, state }));
    console.log('Attempting to login via OAuth...');
    console.log('Visit this link to authenticate: https://dash.cloudflare.com/oauth2/auth?response_type=code&client_id=54d11594&redirect_uri=' + encodeURIComponent('http://127.0.0.1:' + port + '/oauth/callback') + '&scope=account%3Aread&state=' + state);
  };
  if (existsSync(STATE + '/listen-late')) {
    // Not answering yet, as a port nobody listens on: every connection dropped until the delay is over. The port
    // stays this process's all along, so that no other process, here, can take it in between.
    const until = Date.now() + (Number(readFileSync(STATE + '/listen-late', 'utf8')) || 700);
    server.on('connection', (socket) => {
      if (Date.now() < until) socket.destroy();
    });
  }
  // 127.0.0.1, not localhost: ::1 and 127.0.0.1 each have their own ports, and another process here may hold this one on the other.
  server.listen(0, '127.0.0.1', () => announce(server.address().port));
} else if (args[0] === 'deploy') {
  if (existsSync(STATE + '/slow')) await new Promise((resolve) => setTimeout(resolve, 60_000));
  const config = jsonc.parse(readFileSync(args[args.indexOf('-c') + 1], 'utf8'));
  const name = config.name;
  if (existsSync(STATE + '/fail-' + name)) { console.error('✘ [ERROR] A request to the Cloudflare API failed.'); process.exit(1); }
  if (REAL !== null) {
    // Its stdin a pipe, as setup gives it: see deploymentWrangler.
    const dry = spawnSync('/bin/sh', ['-c', 'cat | "$0" "$@"', process.execPath, REAL, 'deploy', STATE + '/stub.js', '--assets', STATE + '/assets', '--dry-run', ...args.slice(1)], {
      input: stdin,
      encoding: 'utf8',
      env: { ...process.env, FORCE_COLOR: '0', WRANGLER_SEND_METRICS: 'false' },
    });
    writeFileSync(STATE + '/dry-' + name, dry.stdout + dry.stderr);
    if (dry.status !== 0) { console.error(dry.stdout + dry.stderr); process.exit(1); }
  }
  const account = process.env.CLOUDFLARE_ACCOUNT_ID ?? config.account_id;
  const secrets = stdin === '' ? [] : Object.keys(JSON.parse(stdin));
  const bindings = [
    ...(config.hyperdrive ?? []).map(({ binding, id }) => ({ type: 'hyperdrive', name: binding, id })),
    ...Object.entries(config.vars ?? {}).map(([key, text]) => ({ type: 'plain_text', name: key, text })),
    ...(config.services ?? []).map(({ binding, service }) => ({ type: 'service', name: binding, service })),
  ];
  const token = readFileSync(STATE + '/token', 'utf8');
  await fetch(process.env.CLOUDFLARE_API_BASE_URL + '/accounts/' + account + '/workers/scripts/' + name, { method: 'PUT', headers: { authorization: 'Bearer ' + token }, body: JSON.stringify({ secrets, bindings }) });
  console.log('Deployed ' + name);
} else {
  console.error('fake wrangler: ' + args.join(' '));
  process.exit(1);
}
`;
  writeFileSync(join(dir, 'node_modules', '.bin', 'wrangler'), script);
  chmodSync(join(dir, 'node_modules', '.bin', 'wrangler'), 0o755);
}

/**
 * The deployment's Vite, as `vite build app` leaves a Workers app: its
 * wrangler.jsonc as Vite's plugin writes it for the build, JSON, with the
 * Worker it built as its entry and nothing to bundle. Says it ran in
 * `<dir>/vite-builds`.
 */
export function fakeVite(dir: string): void {
  mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
  const jsonc = createRequire(import.meta.url).resolve('jsonc-parser');
  writeFileSync(
    join(dir, 'node_modules', '.bin', 'vite'),
    `#!${process.execPath}
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import jsonc from ${JSON.stringify(jsonc)};
const [command, root] = process.argv.slice(2);
if (command !== 'build' || root !== 'app') { console.error('fake vite: build app only'); process.exit(1); }
appendFileSync('vite-builds', 'app\\n');
const config = jsonc.parse(readFileSync('app/wrangler.jsonc', 'utf8'));
mkdirSync('app/dist/server', { recursive: true });
writeFileSync('app/dist/server/index.js', 'export default { fetch: () => new Response("ok") };\\n');
writeFileSync('app/dist/server/wrangler.json', JSON.stringify({ ...config, main: 'index.js', no_bundle: true }, null, 2));
`,
  );
  chmodSync(join(dir, 'node_modules', '.bin', 'vite'), 0o755);
}

/**
 * A browser opener that only notes what it was asked to open, a line each, in
 * `<dir>/opened`: put `dir` first on PATH. Tests poll that file while it runs,
 * so it never appends in place, which shows them an empty file or half a
 * line: the list so far and the new address go beside it, then are renamed.
 */
export function fakeOpener(dir: string): void {
  mkdirSync(dir, { recursive: true });
  const opened = `'${dir}/opened'`;
  for (const name of ['xdg-open', 'open']) {
    writeFileSync(join(dir, name), `#!/bin/sh\n{ cat ${opened} 2>/dev/null; printf '%s\\n' "$1"; } > ${opened}.$$ && mv ${opened}.$$ ${opened}\n`);
    chmodSync(join(dir, name), 0o755);
  }
}

/**
 * A test's end, failed or not, in the order that leaves nothing behind: a
 * Ctrl-C at its prompt, which cancels what waits there; its wranglers
 * stopped, which ends what waits on one; its task awaited, a while at most;
 * its steps ended. Only then may its directory go.
 */
export async function settle(keys: PassThrough, task: Promise<unknown>, steps?: { end(): void }): Promise<void> {
  keys.write('\x03');
  stopWranglers();
  await Promise.race([task.catch(() => {}), new Promise((resolve) => setTimeout(resolve, 5_000).unref())]);
  steps?.end();
}

const terminals: PassThrough[] = [];

/** Ctrl-C at every terminal in memory: whatever still waits at a prompt is cancelled, and lets go of what it holds. */
export function cancelTerminals(): void {
  for (const keys of terminals.splice(0)) keys.write('\x03');
}

/** A terminal in memory: keys in, what is drawn out. */
export function fakeTerminal(columns = 120) {
  const keys = Object.assign(new PassThrough(), { isTTY: true, setRawMode: () => {} });
  terminals.push(keys);
  let drawn = '';
  const out = Object.assign(
    new Writable({
      write(chunk, _encoding, done) {
        drawn += String(chunk);
        done();
      },
    }),
    { isTTY: true, columns, rows: 40 },
  );
  return { keys, out, drawn: () => drawn };
}

/**
 * A home whose CLI is signed in to `origin`, as `coffre login <origin>
 * --token` leaves it: a service token, saved as the session there.
 */
export function signedInWithToken(home: string, origin: string, token: string): void {
  mkdirSync(join(home, '.coffre'), { recursive: true, mode: 0o700 });
  const session = { mode: 'signin', kind: 'token', token, expiresAt: null, obtainedAt: new Date().toISOString() };
  writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: origin, instances: { [origin]: session } }), { mode: 0o600 });
}
