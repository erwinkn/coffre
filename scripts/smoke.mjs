#!/usr/bin/env node
// Run a deployment made like examples/workers or examples/node, and take it
// through a first day: health, a sign-in through the dev IdP standing in for
// GitHub, a project with a secret, the page that lists it, a reveal through
// the vault, the scheduled heartbeat and the vault's signed checkpoint, and
// the security headers on the way.
//
//   node scripts/smoke.mjs workers [<dir>]   two Workers under `wrangler dev`, on Postgres
//   node scripts/smoke.mjs node [<dir>]      the server and its vault process, on SQLite
//
// <dir> is the example itself unless given, or any copy of it, such as the
// one scripts/consumer-test.sh installs from packed tarballs. It needs its
// packages installed, and built when they are the workspace's.
//
// The deployment runs its own code, unedited: the smoke hands it settings as
// the environment its wrangler.jsonc or server.env would, with GitHub's URLs
// pointed at the dev IdP. Ports: SMOKE_PORT (3082) for coffre, the next for
// the dev IdP, the one after for wrangler's inspector. Workers use a
// Postgres database of their own, coffre_smoke, dropped when done.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import pg from 'pg';

const root = new URL('..', import.meta.url).pathname;
const kind = process.argv[2];
if (kind !== 'workers' && kind !== 'node') {
    console.error('usage: node scripts/smoke.mjs workers|node [<dir>]');
    process.exit(2);
}
const dir = resolve(process.argv[3] ?? join(root, 'examples', kind));
const port = Number(process.env.SMOKE_PORT ?? 3082);
const origin = `http://127.0.0.1:${port}`;
const idp = `http://127.0.0.1:${port + 1}`;
const scratch = mkdtempSync(join(tmpdir(), `coffre-smoke-${kind}-`));

// Local fixtures, as in .env.dev: none of them is a secret anywhere else.
const ADMIN = 'admin@acme.example';
const KEYS = {
    KEK: 'Y29mZnJlLWxvY2FsLWRldi1rZWstMzItYnl0ZXMhISE=',
    SIGNING_KEY: 'Y29mZnJlLWxvY2FsLXZhdWx0LXNpZ25pbmctc2VlZCE=',
    AUDIT_CHAIN_KEY: 'Y29mZnJlLWxvY2FsLWF1ZGl0LWNoYWluLWtleS0zMmI=',
};
const GITHUB = {
    GITHUB_CLIENT_ID: 'coffre-local',
    GITHUB_CLIENT_SECRET: 'coffre-local-secret',
    GITHUB_URL: `${idp}/github`,
    GITHUB_API_URL: `${idp}/github/api`,
};
const DATABASE = 'coffre_smoke';
const OWNER = 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432';

// The shell's own COFFRE_* (a sourced .env.dev, say) must not reach the
// deployment: it gets what the smoke hands it, and nothing else.
const shell = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));

const children = [];
function start(name, command, args, env, { daemon = true } = {}) {
    const log = join(scratch, `${name}.log`);
    const child = spawn(command, args, {
        cwd: dir,
        env: { ...shell, ...env },
        // Its own process group, so stopping it stops what it started (workerd).
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks = [];
    child.stdout.on('data', (chunk) => chunks.push(chunk));
    child.stderr.on('data', (chunk) => chunks.push(chunk));
    const entry = { name, child, daemon, log: () => Buffer.concat(chunks).toString('utf8'), exited: false };
    child.once('exit', () => (entry.exited = true));
    children.push(entry);
    return entry;
}

function logs() {
    return children.map((entry) => `--- ${entry.name}\n${entry.log().slice(-4000)}`).join('\n');
}

let failed = false;
async function stop() {
    for (const { child, exited } of children) {
        if (!exited) {
            try {
                process.kill(-child.pid, 'SIGTERM');
            } catch {}
        }
    }
    await sleep(500);
    for (const { child, exited } of children) {
        if (!exited) {
            try {
                process.kill(-child.pid, 'SIGKILL');
            } catch {}
        }
    }
    if (kind === 'workers') await dropDatabase().catch(() => {});
    rmSync(scratch, { recursive: true, force: true });
}

function check(condition, what, detail) {
    if (condition) return;
    failed = true;
    throw new Error(`${what}${detail === undefined ? '' : `\n${typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)}`}`);
}

async function run(command, args, env = {}) {
    const entry = start(args[0] ?? command, command, args, env, { daemon: false });
    const code = await new Promise((done) => entry.child.once('exit', done));
    check(code === 0, `${command} ${args.join(' ')} failed`, entry.log());
}

async function until(what, probe, seconds = 60) {
    for (let i = 0; i < seconds * 10; i++) {
        if (children.some((entry) => entry.daemon && entry.exited)) check(false, `a process exited while waiting for ${what}`, logs());
        if (await probe().catch(() => false)) return;
        await sleep(100);
    }
    check(false, `timed out waiting for ${what}`, logs());
}

async function sql(database, statement) {
    const client = new pg.Client(`${OWNER}/${database}`);
    await client.connect();
    try {
        await client.query(statement);
    } finally {
        await client.end();
    }
}

const dropDatabase = () => sql('postgres', `DROP DATABASE IF EXISTS ${DATABASE} WITH (FORCE)`);

const bin = (name) => {
    const path = join(dir, 'node_modules/.bin', name);
    check(existsSync(path), `${path} is missing: install ${dir} first`);
    return path;
};

// --- A browser, reduced to a cookie jar ---------------------------------

const jar = new Map();
async function request(path, init = {}) {
    const url = path.startsWith('http') ? path : `${origin}${path}`;
    const headers = new Headers(init.headers);
    if (url.startsWith(origin) && jar.size > 0) {
        headers.set('cookie', [...jar].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    const response = await fetch(url, { ...init, headers, redirect: 'manual' });
    if (url.startsWith(origin)) {
        for (const cookie of response.headers.getSetCookie()) {
            const [pair] = cookie.split(';');
            const at = pair.indexOf('=');
            const value = pair.slice(at + 1);
            if (value === '' || /max-age=0/i.test(cookie)) jar.delete(pair.slice(0, at));
            else jar.set(pair.slice(0, at), value);
        }
    }
    return response;
}

/** A call a page makes: JSON, from coffre's own origin. */
async function api(method, path, body) {
    const response = await request(`/api${path}`, {
        method,
        headers: { origin, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    check(response.ok, `${method} /api${path} answered ${response.status}`, text);
    return JSON.parse(text);
}

function securityHeaders(response, what) {
    const csp = response.headers.get('content-security-policy') ?? '';
    check(/script-src 'self' 'nonce-[^']+'/.test(csp), `${what}: no nonce-based script-src`, csp);
    check(csp.includes("frame-ancestors 'none'"), `${what}: frames not refused`, csp);
    check(response.headers.get('x-content-type-options') === 'nosniff', `${what}: no nosniff`);
    check(response.headers.get('x-frame-options') === 'DENY', `${what}: no x-frame-options`);
    return csp;
}

// --- The deployment ------------------------------------------------------

async function startWorkers() {
    await run(join(root, 'scripts/ensure-postgres.sh'), []);
    await dropDatabase();
    await run(process.execPath, [join(root, 'scripts/ensure-database.mjs'), DATABASE]);
    await run(bin('coffre-server'), ['migrate', `${OWNER}/${DATABASE}`]);
    // The migration stamps the heartbeat as it runs; make it an hour old, so
    // only the scheduled job can make /readyz pass.
    await sql(DATABASE, "UPDATE audit_heartbeat SET last_beat_at = now() - interval '1 hour' WHERE only_row");
    start(
        'wrangler',
        bin('wrangler'),
        [
            'dev',
            ...['-c', 'app/wrangler.jsonc', '-c', 'vault/wrangler.jsonc'],
            ...['--ip', '127.0.0.1', '--port', String(port), '--inspector-port', String(port + 2)],
            ...['--persist-to', join(scratch, 'state'), '--show-interactive-dev-session=false'],
            // Not in wrangler.jsonc's vars, so not taken from the environment.
            ...['--var', `GITHUB_URL:${GITHUB.GITHUB_URL}`, '--var', `GITHUB_API_URL:${GITHUB.GITHUB_API_URL}`],
        ],
        {
            // Wrangler hands each Worker the vars and secrets its own
            // wrangler.jsonc declares, from here: the app never sees a KEK.
            PUBLIC_URL: origin,
            GITHUB_CLIENT_ID: GITHUB.GITHUB_CLIENT_ID,
            GITHUB_CLIENT_SECRET: GITHUB.GITHUB_CLIENT_SECRET,
            AUDIT_CHAIN_KEY: KEYS.AUDIT_CHAIN_KEY,
            KEK_ID: 'smoke-1',
            KEK: KEYS.KEK,
            SIGNING_KEY: KEYS.SIGNING_KEY,
            ROOT_ADMINS: ADMIN,
            CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE: `postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/${DATABASE}`,
            WRANGLER_SEND_METRICS: 'false',
        },
    );
}

async function startNode() {
    const database = `file:${join(scratch, 'coffre.db')}`;
    const socket = join(scratch, 'vault.sock');
    await run(bin('coffre-server'), ['migrate', database]);
    start('vault', process.execPath, ['src/vault.ts'], {
        VAULT_SOCKET: socket,
        VAULT_STORE: join(scratch, 'vault.db'),
        KEK_ID: 'smoke-1',
        KEK: KEYS.KEK,
        SIGNING_KEY: KEYS.SIGNING_KEY,
        ROOT_ADMINS: ADMIN,
    });
    await until('the vault socket', async () => existsSync(socket));
    startServer = () =>
        start('server', process.execPath, ['src/server.ts'], {
            PORT: String(port),
            PUBLIC_URL: origin,
            DATABASE_URL: database,
            VAULT_SOCKET: socket,
            AUDIT_CHAIN_KEY: KEYS.AUDIT_CHAIN_KEY,
            ...GITHUB,
        });
    startServer();
}

let startServer;

/**
 * What the Cron trigger does every five minutes. `serve` runs it as it
 * starts, and every five minutes after: so on Node, restart the server.
 */
async function scheduled() {
    if (kind === 'node') {
        const server = children.find((entry) => entry.name === 'server' && !entry.exited);
        const exited = new Promise((done) => server.child.once('exit', done));
        server.daemon = false;
        process.kill(-server.child.pid, 'SIGTERM');
        await exited;
        startServer();
        await until('the restarted server', async () => (await fetch(`${origin}/readyz`)).ok);
        return;
    }
    const response = await request('/cdn-cgi/local/scheduled?cron=*/5+*+*+*+*');
    check(response.ok, `the scheduled handler answered ${response.status}`, `${await response.text()}\n${logs()}`);
}

// --- The day -------------------------------------------------------------

async function smoke() {
    for (const p of [port, port + 1, port + 2]) {
        const busy = await fetch(`http://127.0.0.1:${p}/`).then(
            () => true,
            () => false,
        );
        check(!busy, `port ${p} is taken; set SMOKE_PORT to a free run of three`);
    }

    start('dev-idp', process.execPath, [join(root, 'dev/idp/src/server.ts')], {
        COFFRE_AUTH_MODE: 'dev',
        COFFRE_DEV_IDP_PORT: String(port + 1),
    });
    await until('the dev IdP', async () => (await fetch(`${idp}/.well-known/openid-configuration`)).ok);

    if (kind === 'workers') await startWorkers();
    else await startNode();
    await until(`${origin}/livez`, async () => (await fetch(`${origin}/livez`)).ok, 120);
    console.log(`  up        ${kind} from ${dir}`);

    // Readiness follows the audit heartbeat, which only the scheduled job
    // writes: not ready until it has run.
    if (kind === 'workers') {
        const stale = await request('/readyz');
        check(stale.status === 503, `/readyz answered ${stale.status} before any heartbeat`, await stale.text());
        await scheduled();
    }
    await until('/readyz', async () => (await request('/readyz')).ok, 20);
    console.log('  healthy   /livez, and /readyz once the heartbeat ran');

    const anonymous = await request('/api/me');
    check(anonymous.status === 401, `/api/me answered ${anonymous.status} without a session`);
    securityHeaders(anonymous, 'a refusal');

    const login = await request('/login');
    check(login.status === 200, `/login answered ${login.status}`);
    const csp = securityHeaders(login, '/login');
    const html = await login.text();
    const nonce = /'nonce-([^']+)'/.exec(csp)[1];
    check(html.includes(`nonce="${nonce}"`), "/login's scripts do not carry the policy's nonce");
    const asset = /\/_coffre\/assets\/[\w.-]+\.js/.exec(html)?.[0];
    check(asset !== undefined, "/login loads no script from /_coffre/assets/", html.slice(0, 2000));
    const script = await request(asset);
    check(script.ok && /javascript/.test(script.headers.get('content-type') ?? ''), `${asset} answered ${script.status}`);
    console.log(`  headers   CSP with a nonce, nosniff, DENY; ${asset} served`);

    // Sign in as a root admin, the way a browser does: to the provider, which
    // is the dev IdP, and back.
    const leave = await request('/auth/signin/github');
    const authorize = new URL(leave.headers.get('location') ?? '');
    check(leave.status === 302 && authorize.origin === idp, 'sign-in did not go to the dev IdP', leave.headers.get('location'));
    const form = new URLSearchParams(authorize.searchParams);
    form.set('email', ADMIN);
    const approve = await fetch(authorize.origin + authorize.pathname, { method: 'POST', body: form, redirect: 'manual' });
    const callback = approve.headers.get('location') ?? '';
    check(approve.status === 302 && callback.startsWith(`${origin}/auth/callback/github?`), 'the dev IdP did not send us back', callback);
    const back = await request(callback);
    check(back.status === 302 || back.status === 303, `the callback answered ${back.status}`, await back.text());
    const me = await api('GET', '/me');
    check(me.principal.id === ADMIN && me.instanceRole === 'root-admin', 'signed in as someone else', me);
    console.log(`  sign-in   ${ADMIN}, through the dev IdP's GitHub`);

    await api('PUT', '/projects/smoke', { name: 'Smoke' });
    await api('PUT', '/projects/smoke/dev', { name: 'Development' });
    await api('PATCH', '/secrets/smoke/dev', { GREETING: 'hello from the smoke' });
    const page = await request('/projects/smoke/dev');
    const pageHtml = await page.text();
    check(page.status === 200 && pageHtml.includes('GREETING'), `the environment page answered ${page.status} without the key`);
    check(!pageHtml.includes('hello from the smoke'), 'the environment page shows a value nobody revealed');
    console.log('  page      /projects/smoke/dev lists GREETING, and no value');

    const revealed = await api('POST', '/reveals', { path: 'smoke/dev' });
    check(revealed.values.GREETING === 'hello from the smoke', 'the reveal came back wrong', revealed);
    console.log('  reveal    smoke/dev, through the vault');

    // Each heartbeat has the vault sign the audit log's head, which must
    // extend the last head it signed; a refusal fails the job. Two, so the
    // second extends the first.
    const before = await api('GET', '/audit/verification');
    await scheduled();
    await scheduled();
    const verification = await api('GET', '/audit/verification');
    check(verification.ok && verification.checkpoint !== null, 'the audit log is not verified and checkpointed', verification);
    check(verification.checkpoint.seq >= before.rows, 'the checkpoint does not cover the reveal', { before, verification });
    console.log(`  audit     ${verification.rows} rows verified, the vault's checkpoint at #${verification.checkpoint.seq}`);
}

try {
    await smoke();
    console.log(`${kind} smoke passed: ${origin}`);
} catch (error) {
    failed = true;
    console.error(`${kind} smoke FAILED: ${error.message}\n\nThe processes' output:\n${logs()}`);
} finally {
    await stop();
}
process.exit(failed ? 1 : 0);
