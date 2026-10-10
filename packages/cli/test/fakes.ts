// Stand-ins for what `coffre setup` reaches on Workers: Cloudflare's API,
// GitHub, wrangler, a browser, and a terminal in memory. No test reaches
// the real ones.
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';

import sodium from 'libsodium-wrappers';

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
/** A Hyperdrive config; its connection limit Cloudflare's default on Paid when it is made without one. */
export type FakeConfig = { id: string; name: string; origin: Origin; caching: { disabled: boolean }; origin_connection_limit: number };
export type FakeZone = { id: string; name: string; status?: string; name_servers?: string[] };
export type FakeHostname = {
  id: string;
  hostname: string;
  status: string;
  ownership_verification: { type: string; name: string; value: string };
  ssl: { status: string; method: string; type: string; validation_records?: { txt_name: string; txt_value: string }[] };
};

/** Cloudflare's API, as setup and wrangler call it, under one token. */
export async function fakeCloudflare(token: string) {
  const state = {
    accounts: [
      { id: 'acc-acme', name: 'Acme' },
      { id: 'acc-home', name: 'Home' },
    ],
    zones: { 'acc-acme': [{ id: 'zone-1', name: 'acme.test', status: 'active' }], 'acc-home': [] } as Record<string, FakeZone[]>,
    configs: new Map<string, FakeConfig[]>(),
    /** The names of configs deleted on the dashboard once listed, while setup runs. */
    vanishing: new Set<string>(),
    /** Each Worker deployed, `<account>/<name>`: the names of its secrets, and its bindings. */
    scripts: new Map<string, { secrets: Set<string>; bindings: unknown[] }>(),
    requests: [] as { method: string; path: string; body: string }[],
    email: 'ops@acme.test' as string | null,
    /** Each account's workers.dev subdomain, when it has one. */
    subdomains: { 'acc-acme': 'acme' } as Record<string, string>,
    /** The zones Cloudflare for SaaS is enabled on. */
    saas: new Set<string>(),
    /** What the token may not do: custom hostnames (`ssl`), DNS records (`dns`), adding a domain (`zone`), as wrangler's login may not. */
    denied: new Set<'ssl' | 'dns' | 'zone'>(),
    /** API tokens made on the dashboard, which may do all of it. */
    apiTokens: new Set<string>(),
    /** What a zone with Cloudflare for SaaS on and no fallback origin answers: Cloudflare does not document it. */
    noFallback: '404' as '404' | 'empty' | '1551',
    fallback: new Map<string, { origin: string; status: string }>(),
    dns: new Map<string, { type: string; name: string; content: string; proxied: boolean }[]>(),
    hostnames: new Map<string, FakeHostname[]>(),
    /** The records the custom hostnames' DNS provider has, by name: Cloudflare sees each a moment after it is there. */
    published: new Set<string>(),
    /** Tokens that may make API tokens, as one with API Tokens Edit may; wrangler's login may not. */
    tokenMakers: new Set<string>(),
    /** Tokens that may do only what they were given: `workers_scripts`, say, or `workers_routes:<zone>`. */
    scoped: new Map<string, Set<string>>(),
    /** The API tokens made through the API, their values included, as only their maker sees them. */
    tokens: [] as { id: string; name: string; policies: { resources: Record<string, string>; permission_groups: { id: string }[] }[]; value: string }[],
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
    const bearer = request.headers.authorization?.replace(/^Bearer /, '') ?? '';
    const scoped = state.scoped.get(bearer);
    if (bearer !== token && !state.apiTokens.has(bearer) && scoped === undefined) return send(401, null, [{ code: 10000, message: 'Authentication error' }]);
    const refused = (what: 'ssl' | 'dns' | 'zone') => bearer === token && state.denied.has(what);
    const path = url.pathname.replace(/^\/client\/v4/, '');
    let match: RegExpExecArray | null;
    const forbidden = () => send(403, null, [{ code: 9109, message: 'Unauthorized to access requested resource' }]);
    if (path === '/user/tokens/verify') return send(200, { id: state.tokens.find(({ value }) => value === bearer)?.id ?? 'tok-given', status: 'active' });
    if (path.startsWith('/user/tokens')) {
      if (!state.tokenMakers.has(bearer)) return forbidden();
      if (path === '/user/tokens/permission_groups') return send(200, PERMISSION_GROUPS);
      if (path === '/user/tokens' && request.method === 'POST') {
        const { name, policies } = JSON.parse(text) as (typeof state.tokens)[number];
        const made = { id: `tok-${randomBytes(4).toString('hex')}`, name, policies, value: `cf-made-${randomBytes(20).toString('hex')}` };
        state.tokens.push(made);
        // What it may do: its groups, on the account, and on the zone they name.
        const may = new Set<string>();
        for (const policy of policies) {
          const zone = Object.keys(policy.resources).map((resource) => /^com\.cloudflare\.api\.account\.zone\.(.+)$/.exec(resource)?.[1]).find((id) => id !== undefined);
          for (const { id } of policy.permission_groups) {
            const permission = PERMISSION_GROUPS.find((group) => group.id === id)!.permission;
            may.add(zone === undefined ? permission : `${permission}:${zone}`);
          }
        }
        state.scoped.set(made.value, may);
        return send(200, made);
      }
      if (path === '/user/tokens') return page(state.tokens.map(({ id, name }) => ({ id, name, status: 'active' })));
      if ((match = /^\/user\/tokens\/([^/]+)$/.exec(path)) !== null && request.method === 'DELETE') {
        const id = match[1]!;
        const gone = state.tokens.find((each) => each.id === id);
        state.tokens = state.tokens.filter((each) => each.id !== id);
        if (gone !== undefined) state.scoped.delete(gone.value);
        return send(200, { id });
      }
    }
    // What a token for the deploys reads, to show it has each permission it needs; a scoped token reads nothing else.
    const reads: [RegExp, string][] = [
      [/^\/accounts\/[^/]+$/, 'account_settings'],
      [/^\/accounts\/[^/]+\/workers\/scripts$/, 'workers_scripts'],
      [/^\/accounts\/[^/]+\/storage\/kv\/namespaces$/, 'workers_kv_storage'],
      [/^\/accounts\/[^/]+\/hyperdrive\/configs$/, 'hyperdrive'],
      [/^\/zones\/([^/]+)\/workers\/routes$/, 'workers_routes'],
    ];
    const read = reads.find(([pattern]) => pattern.test(path));
    if (scoped !== undefined) {
      const zone = read === undefined ? undefined : read[0].exec(path)![1];
      if (request.method !== 'GET' || read === undefined || !scoped.has(zone === undefined ? read[1] : `${read[1]}:${zone}`)) return forbidden();
      if (read[1] !== 'hyperdrive') return send(200, read[1] === 'account_settings' ? { id: path.split('/')[2] } : []);
    } else if (read !== undefined && read[1] !== 'hyperdrive') {
      return send(200, read[1] === 'account_settings' ? { id: path.split('/')[2] } : []);
    }
    if (path === '/accounts') return page(state.accounts);
    if (path === '/user') return state.email === null ? send(403, null, [{ code: 9109, message: 'Unauthorized' }]) : send(200, { email: state.email });
    if (path === '/zones' && request.method === 'POST') {
      if (refused('zone')) return send(403, null, [{ code: 10000, message: 'Authentication error' }]);
      const { account, name } = JSON.parse(text) as { account: { id: string }; name: string };
      const zone = { id: `zone-${randomBytes(4).toString('hex')}`, name, status: 'pending', name_servers: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'] };
      (state.zones[account.id] ??= []).push(zone);
      return send(200, zone);
    }
    if (path === '/zones') return page(state.zones[url.searchParams.get('account.id') ?? ''] ?? []);
    if ((match = /^\/accounts\/([^/]+)\/workers\/subdomain$/.exec(path)) !== null) {
      const subdomain = state.subdomains[match[1]!];
      return subdomain === undefined ? send(404, null, [{ code: 10007, message: 'This account has no workers.dev subdomain' }]) : send(200, { subdomain });
    }
    if ((match = /^\/zones\/([^/]+)\/dns_records$/.exec(path)) !== null) {
      if (refused('dns')) return send(403, null, [{ code: 10000, message: 'Authentication error' }]);
      const records = state.dns.get(match[1]!) ?? [];
      state.dns.set(match[1]!, records);
      if (request.method === 'POST') {
        const record = JSON.parse(text) as { type: string; name: string; content: string; proxied: boolean };
        records.push(record);
        return send(200, record);
      }
      return send(200, records.filter(({ name }) => name === url.searchParams.get('name')));
    }
    if ((match = /^\/zones\/([^/]+)\/custom_hostnames(?:\/([^/]+))?$/.exec(path)) !== null) {
      const [, zone, part] = match;
      if (refused('ssl')) return send(403, null, [{ code: 10000, message: 'Authentication error' }]);
      if (!state.saas.has(zone!)) return send(403, null, [{ code: 1404, message: 'No quota has been allocated for this zone.' }]);
      const hostnames = state.hostnames.get(zone!) ?? [];
      state.hostnames.set(zone!, hostnames);
      if (part === 'fallback_origin') {
        if (request.method === 'PUT') {
          const { origin } = JSON.parse(text) as { origin: string };
          // As Cloudflare checks it: a proxied record of the zone's.
          if (!(state.dns.get(zone!) ?? []).some(({ name, proxied }) => name === origin && proxied)) {
            return send(400, null, [{ code: 1551, message: 'Origin should be a proxied A/AAAA/CNAME dns record' }]);
          }
          state.fallback.set(zone!, { origin, status: 'pending_deployment' });
        }
        const fallback = state.fallback.get(zone!);
        if (fallback !== undefined) return send(200, fallback);
        if (state.noFallback === 'empty') return send(200, null);
        return send(state.noFallback === '1551' ? 400 : 404, null, [{ code: 1551, message: 'No fallback origin' }]);
      }
      // Cloudflare's view of a hostname: active once it sees its CNAME or its TXT record; its certificate, once it sees both of its TXT records.
      const seen = (hostname: FakeHostname): FakeHostname => {
        const has = (name: string) => state.published.has(name);
        if (hostname.status !== 'active' && (has(hostname.hostname) || has(hostname.ownership_verification.name))) hostname.status = 'active';
        // Its certificate's records come a moment after the hostname: never in the answer to the POST.
        hostname.ssl.validation_records ??= ['a', 'b'].map((half) => ({ txt_name: `_acme-challenge.${hostname.hostname}`, txt_value: `${half}-${randomBytes(8).toString('hex')}` }));
        if (hostname.ssl.status === 'pending_validation' && has(`_acme-challenge.${hostname.hostname}`)) hostname.ssl.status = 'active';
        return hostname;
      };
      if (part === undefined && request.method === 'POST') {
        const { hostname, ssl } = JSON.parse(text) as { hostname: string; ssl: { method: string; type: string } };
        if (hostnames.some((each) => each.hostname === hostname)) return send(409, null, [{ code: 1406, message: 'Duplicate custom hostname found.' }]);
        const made: FakeHostname = {
          id: `ch-${randomBytes(4).toString('hex')}`,
          hostname,
          status: 'pending',
          ownership_verification: { type: 'txt', name: `_cf-custom-hostname.${hostname}`, value: randomBytes(16).toString('hex') },
          ssl: { status: 'pending_validation', ...ssl },
        };
        hostnames.push(made);
        return send(201, { ...made, ssl: { ...made.ssl } });
      }
      if (part === undefined) return send(200, hostnames.filter(({ hostname }) => hostname === url.searchParams.get('hostname')).map(seen));
      const hostname = hostnames.find(({ id }) => id === part);
      if (hostname === undefined) return send(404, null, [{ code: 1436, message: 'The custom hostname was not found.' }]);
      // Validation starts over: a moved hostname is pending again, its certificate too.
      if (request.method === 'PATCH') Object.assign(hostname, { status: hostname.status === 'moved' ? 'pending' : hostname.status, ssl: { ...hostname.ssl, status: 'pending_validation' } });
      return send(200, seen(hostname));
    }
    if ((match = /^\/accounts\/([^/]+)\/hyperdrive\/configs(?:\/([^/]+))?$/.exec(path)) !== null) {
      const [, account, id] = match;
      const configs = state.configs.get(account!) ?? [];
      state.configs.set(account!, configs);
      const visible = ({ origin: { password: _password, ...origin }, ...config }: FakeConfig) => ({ ...config, origin });
      if (id === undefined && request.method === 'GET') {
        const listed = configs.map(visible);
        state.configs.set(account!, configs.filter(({ name }) => !state.vanishing.has(name)));
        state.vanishing.clear();
        return send(200, listed);
      }
      if (id === undefined && request.method === 'POST') {
        const made = { id: `hd-${randomBytes(4).toString('hex')}`, caching: { disabled: false }, origin_connection_limit: 60, ...JSON.parse(text) } as FakeConfig;
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

/** Cloudflare's permission groups, as it lists them to a token that may make tokens: those the deploy needs, and some it does not. */
const PERMISSION_GROUPS = [
  { id: 'pg-scripts-read', name: 'Workers Scripts Read', permission: 'workers_scripts_read' },
  { id: 'pg-scripts', name: 'Workers Scripts Write', permission: 'workers_scripts' },
  { id: 'pg-settings', name: 'Account Settings Read', permission: 'account_settings' },
  { id: 'pg-kv', name: 'Workers KV Storage Write', permission: 'workers_kv_storage' },
  { id: 'pg-hyperdrive-write', name: 'Hyperdrive Write', permission: 'hyperdrive_write' },
  { id: 'pg-hyperdrive', name: 'Hyperdrive Read', permission: 'hyperdrive' },
  { id: 'pg-routes', name: 'Workers Routes Write', permission: 'workers_routes' },
  { id: 'pg-dns', name: 'DNS Write', permission: 'dns' },
];

/**
 * GitHub, as its App manifest flow goes: the form posted, Create clicked at
 * once, the code converted, once. And a repository's Actions secrets, as
 * its API takes them: each sealed to the repository's public key, which the
 * stand-in opens with libsodium, as GitHub does.
 */
export async function fakeGitHub() {
  await sodium.ready;
  const keys = sodium.crypto_box_keypair();
  const state = {
    manifests: [] as Record<string, unknown>[],
    codes: new Map<string, { client_id: string; client_secret: string; slug: string }>(),
    /** The tokens that may set each repository's secrets, by token. */
    tokens: new Map<string, Set<string>>(),
    /** Each repository's secrets, opened: what GitHub Actions would see. */
    secrets: new Map<string, Map<string, string>>(),
    /** Every call to the secrets API: its method, path and token. */
    calls: [] as { method: string; path: string; token: string }[],
  };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');
    const secrets = /^\/api\/v3\/repos\/([^/]+\/[^/]+)\/actions\/secrets\/([^/]+)$/.exec(url.pathname);
    if (secrets !== null) {
      const [, repository, name] = secrets;
      const json = (status: number, body?: unknown) =>
        response.writeHead(status, { 'content-type': 'application/json' }).end(body === undefined ? undefined : JSON.stringify(body));
      const token = request.headers.authorization?.replace(/^Bearer /, '') ?? '';
      state.calls.push({ method: request.method ?? '', path: url.pathname, token });
      const repos = state.tokens.get(token);
      if (repos === undefined) return json(401, { message: 'Bad credentials' });
      if (!repos.has(repository!)) return json(403, { message: 'Resource not accessible by personal access token' });
      const stored = state.secrets.get(repository!) ?? new Map<string, string>();
      state.secrets.set(repository!, stored);
      if (name === 'public-key') return json(200, { key_id: 'key-1', key: Buffer.from(keys.publicKey).toString('base64') });
      if (request.method === 'GET') return stored.has(name!) ? json(200, { name, created_at: '2026-10-06T00:00:00Z' }) : json(404, { message: 'Not Found' });
      if (request.method === 'PUT') {
        const { encrypted_value: sealed, key_id: id } = JSON.parse(await body(request)) as { encrypted_value: string; key_id: string };
        if (id !== 'key-1') return json(422, { message: 'Bad key_id' });
        const existed = stored.has(name!);
        stored.set(name!, Buffer.from(sodium.crypto_box_seal_open(Buffer.from(sealed, 'base64'), keys.publicKey, keys.privateKey)).toString('utf8'));
        return json(existed ? 204 : 201);
      }
    }
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
        JSON.stringify({ ...app, id: 1, owner: { login: 'ops', type: 'User' }, pem: '-----BEGIN RSA PRIVATE KEY-----', webhook_secret: 'whsec', html_url: `https://github.com/apps/${app.slug}` }),
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
// The token a deploy runs under: one in its environment, as wrangler reads it, or its login's.
const apiToken = process.env.CLOUDFLARE_API_TOKEN ?? null;
appendFileSync(STATE + '/calls.jsonl', JSON.stringify({ args, stdin, account: process.env.CLOUDFLARE_ACCOUNT_ID ?? null, apiToken }) + '\\n');
if (args[0] === 'auth' && apiToken !== null) {
  console.log(JSON.stringify({ type: 'api_token', token: apiToken }));
} else if (args[0] === 'auth') {
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
  const token = apiToken ?? readFileSync(STATE + '/token', 'utf8');
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

/** gh, signed in to one GitHub host with `token`: `gh auth token --hostname <host>` prints it; any other host has none. */
export function fakeGh(dir: string, host: string, token: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'gh'), `#!/bin/sh\n[ "$1 $2 $3 $4" = "auth token --hostname ${host}" ] && echo '${token}' && exit 0\necho 'not logged in' >&2\nexit 1\n`);
  chmodSync(join(dir, 'gh'), 0o755);
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
