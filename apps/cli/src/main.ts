#!/usr/bin/env node
/**
 * coffre CLI.
 *
 * Deliberately dependency-free: node:util's parseArgs and node:child_process
 * are enough. A tool that handles every credential we own is a poor place to
 * add a transitive dependency tree for argument parsing.
 */
import { parseArgs } from 'node:util';
import { execFile, spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join, dirname } from 'node:path';
import { promisify } from 'node:util';
import { isJsonContentType } from './auth-mode.ts';
import {
  credentialHeaders,
  emptyStore,
  instanceOrigin,
  parseMode,
  parseStore,
  resolveTarget,
  withSession,
  withoutSession,
  type Store,
  type Target,
} from './instance.ts';
import { formatDotenv, formatShellExports } from '../../../packages/core/src/dotenv.ts';
import {
  DESTINATIONS,
  configFromArguments,
  type DestinationField,
} from '../../../packages/sync/src/destinations.ts';

const CREDENTIALS_PATH = join(homedir(), '.coffre', 'credentials.json');

// `coffre export … | head` closes the pipe early; that is the reader being
// done, not an error worth a stack trace.
process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EPIPE') process.exit(0);
  throw error;
});
const DEV_IDP_URL = process.env.COFFRE_DEV_IDP_URL ?? '';

function readStore(): Store {
  return existsSync(CREDENTIALS_PATH) ? parseStore(readFileSync(CREDENTIALS_PATH, 'utf8')) : emptyStore();
}

function writeStore(store: Store): void {
  mkdirSync(dirname(CREDENTIALS_PATH), { recursive: true, mode: 0o700 });
  // 0600: a token that grants access to production secrets should not be
  // world-readable on a shared machine.
  writeFileSync(CREDENTIALS_PATH, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });
}

function fail(message: string): never {
  process.stderr.write(`coffre: ${message}\n`);
  process.exit(1);
}

function attempt<T>(step: () => T): T {
  try {
    return step();
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

function target(): Target {
  return attempt(() => resolveTarget(process.env, readStore()));
}

/** cloudflared keeps and refreshes the Access token; ask it each time. */
async function cloudflaredToken(origin: string): Promise<string> {
  try {
    const { stdout } = await promisify(execFile)('cloudflared', ['access', 'token', `-app=${origin}`]);
    const token = stdout.trim();
    if (token === '' || token.includes(' ')) throw new Error(stdout);
    return token;
  } catch {
    fail(`could not get a Cloudflare Access token for ${origin}: run \`coffre login ${origin}\``);
  }
}

async function headersFor(to: Target): Promise<Record<string, string>> {
  const access = to.credential.kind === 'cloudflared' ? await cloudflaredToken(to.origin) : undefined;
  return credentialHeaders(to.mode, to.credential, access);
}

async function api(path: string, init: RequestInit = {}, to: Target = target()): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(`${to.origin}${path}`, {
      ...init,
      // Cloudflare Access redirects rejected non-browser clients to its login
      // page. Following that redirect would turn an auth failure into HTML that
      // later explodes in JSON parsing.
      redirect: 'manual',
      headers: {
        ...(await headersFor(to)),
        'content-type': 'application/json',
        ...(init.headers ?? {}),
      },
    });
  } catch (error) {
    fail(`could not reach ${to.origin}: ${error instanceof Error ? error.message : String(error)}`);
  }

  const relogin = `run \`coffre login ${to.origin}\``;
  if (response.status >= 300 && response.status < 400) {
    if (to.mode === 'cloudflare') fail(`Cloudflare Access did not accept your token: ${relogin}`);
    fail(`${to.origin} redirected to ${response.headers.get('location') ?? 'elsewhere'}; is that the right address?`);
  }
  if (response.status === 401) fail(`your session on ${to.origin} is missing, expired or revoked: ${relogin}`);
  if (response.status === 403) fail('forbidden: you do not have a grant for that environment');
  if (response.status === 404) fail('not found');
  if (!response.ok) {
    let detail = `request failed with status ${response.status}`;
    if (isJsonContentType(response.headers.get('content-type'))) {
      const body = (await response.json()) as { error?: unknown; message?: unknown };
      if (typeof body.message === 'string' && body.message.length > 0) {
        fail(`${detail}: ${body.message}`);
      }
      if (typeof body.error === 'string' && body.error.length > 0) {
        fail(`${detail}: ${body.error}`);
      }
    }
    fail(detail);
  }
  if (!isJsonContentType(response.headers.get('content-type'))) {
    fail('request returned a non-JSON response');
  }

  return response.json();
}

/** Parse `project/environment/KEY` or `project/environment`. */
function parsePath(raw: string): { project: string; environment: string; key?: string } {
  const parts = raw.split('/');
  if (parts.length < 2 || parts.length > 3 || parts.some((part) => part.length === 0)) {
    fail(`expected project/environment[/KEY], got: ${raw}`);
  }
  return { project: parts[0], environment: parts[1], key: parts[2] };
}

// --- commands ---------------------------------------------------------------

type Me = {
  principal: { type: string; id: string };
  environments: { project: string; environment: string; permissions: string[] }[];
};

function printMe(me: Me): void {
  if (me.environments.length === 0) {
    process.stdout.write('  no environments granted yet\n');
  }
  for (const entry of me.environments) {
    process.stdout.write(
      `  ${`${entry.project}/${entry.environment}`.padEnd(24)} ${entry.permissions.join(', ')}\n`,
    );
  }
}

/**
 * Sign in to an instance and make it the current one. How depends on who
 * vouches for people there, which the CLI finds out by asking:
 *
 * - coffre's own sign-in answers the device-flow request: the CLI shows a
 *   code, you approve it in a browser where you are signed in, and the CLI
 *   receives a session token of its own.
 * - Cloudflare Access answers with a redirect to its login page: the CLI hands
 *   over to `cloudflared`, which keeps the Access token from then on.
 * - The local dev IdP mints a persona token directly (COFFRE_AUTH_MODE=dev).
 */
async function login(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      email: { type: 'string' },
      'service-token': { type: 'string' },
      'no-browser': { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });

  const mode = attempt(() => parseMode(process.env.COFFRE_AUTH_MODE));
  const requested = positionals[0] ?? process.env.COFFRE_API_URL ?? readStore().current;
  if (!requested) fail('usage: coffre login <url>, for example `coffre login https://coffre.example.com`');
  const origin = attempt(() => instanceOrigin(requested, mode ?? 'signin'));

  if (mode === 'dev') return devLogin(origin, values.email, values['service-token']);
  if (values.email || values['service-token']) {
    fail('--email and --service-token pick a persona on the local dev IdP; they need COFFRE_AUTH_MODE=dev');
  }
  if (mode === 'cloudflare') return accessLogin(origin);

  let started: Response;
  try {
    started = await fetch(`${origin}/api/auth/device`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_label: `coffre CLI on ${hostname()}` }),
    });
  } catch (error) {
    fail(`could not reach ${origin}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (started.status >= 300 && started.status < 400) return accessLogin(origin);
  if (started.status === 404) {
    fail(`${origin} does not offer coffre sign-in; if it is a local dev server, set COFFRE_AUTH_MODE=dev`);
  }
  if (started.status === 429) fail('too many sign-in attempts from this address; wait a minute and retry');
  if (!started.ok || !isJsonContentType(started.headers.get('content-type'))) {
    // Access normally redirects, but an application can be set to answer
    // non-browser clients with a bare 401 or 403 instead.
    fail(
      `${origin} did not start a sign-in (status ${started.status}). If it is behind Cloudflare Access,\n` +
        `  run \`COFFRE_AUTH_MODE=cloudflare coffre login ${origin}\``,
    );
  }
  const device = (await started.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
  };

  process.stderr.write(
    `\nTo sign in, open\n\n    ${device.verification_uri_complete}\n\n` +
      `and check that it shows the code  ${device.user_code}\n\n`,
  );
  if (!values['no-browser'] && process.stderr.isTTY) openBrowser(device.verification_uri_complete);
  process.stderr.write('Waiting for you to approve it…\n');

  const session = await pollDevice(origin, device.device_code, device.interval, device.expires_in);
  const me = (await api('/api/me', {}, {
    origin,
    mode: 'signin',
    credential: { kind: 'token', token: session.access_token },
  })) as Me;

  writeStore(
    withSession(readStore(), origin, {
      mode: 'signin',
      token: session.access_token,
      principal: me.principal,
      expiresAt: session.expires_at,
      obtainedAt: new Date().toISOString(),
    }),
  );
  process.stdout.write(`Signed in to ${origin} as ${me.principal.id}\n`);
  printMe(me);
}

type DeviceToken = {
  access_token: string;
  expires_at: string | null;
  principal: { type: string; id: string };
};

async function pollDevice(
  origin: string,
  deviceCode: string,
  interval: number,
  expiresIn: number,
): Promise<DeviceToken> {
  const deadline = Date.now() + expiresIn * 1000;
  let wait = Math.max(interval, 1) * 1000;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, wait));
    let response: Response;
    try {
      response = await fetch(`${origin}/api/auth/device/token`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ device_code: deviceCode }),
      });
    } catch {
      // A dropped connection mid-wait is not a reason to make someone start over.
      continue;
    }
    if (response.ok) return (await response.json()) as DeviceToken;
    const { error } = (await response.json().catch(() => ({}))) as { error?: string };
    if (response.status === 429 || error === 'slow_down') {
      wait += 5000;
      continue;
    }
    if (error === 'authorization_pending') continue;
    if (error === 'access_denied') fail('the sign-in was declined in the browser');
    if (error === 'expired_token') fail('the code expired before it was approved; run `coffre login` again');
    fail(`sign-in failed: ${error ?? `status ${response.status}`}`);
  }
  fail('the code expired before it was approved; run `coffre login` again');
}

/** Best effort: on a machine without a desktop the printed link is enough. */
function openBrowser(url: string): void {
  const [command, ...args] =
    process.platform === 'darwin'
      ? ['open', url]
      : process.platform === 'win32'
        ? ['cmd', '/c', 'start', '""', url]
        : ['xdg-open', url];
  const child = spawn(command, args, { stdio: 'ignore', detached: true });
  child.on('error', () => {});
  child.unref();
}

async function accessLogin(origin: string): Promise<void> {
  process.stderr.write(`${origin} is behind Cloudflare Access; signing in with cloudflared.\n`);
  const code = await new Promise<number | null>((resolve) => {
    const child = spawn('cloudflared', ['access', 'login', origin], { stdio: 'inherit' });
    child.on('error', () => resolve(null));
    child.on('exit', (status) => resolve(status));
  });
  if (code === null) {
    fail(
      'this instance uses Cloudflare Access, which needs cloudflared: ' +
        'https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/\n' +
        '  In CI, set COFFRE_ACCESS_CLIENT_ID and COFFRE_ACCESS_CLIENT_SECRET to an Access service token instead.',
    );
  }
  if (code !== 0) fail('cloudflared could not sign you in');

  const to: Target = { origin, mode: 'cloudflare', credential: { kind: 'cloudflared' } };
  const me = (await api('/api/me', {}, to)) as Me;
  writeStore(
    withSession(readStore(), origin, {
      mode: 'cloudflare',
      principal: me.principal,
      obtainedAt: new Date().toISOString(),
    }),
  );
  process.stdout.write(`Signed in to ${origin} as ${me.principal.id}\n`);
  printMe(me);
}

/** Local development only: the dev IdP mints an Access-shaped token for a persona. */
async function devLogin(origin: string, email?: string, serviceToken?: string): Promise<void> {
  if (DEV_IDP_URL === '') fail('COFFRE_DEV_IDP_URL is required when COFFRE_AUTH_MODE=dev');

  const url = new URL('/dev/mint', DEV_IDP_URL);
  if (serviceToken) {
    url.searchParams.set('common_name', serviceToken);
  } else {
    url.searchParams.set('email', email ?? 'admin@acme.example');
  }
  if (process.env.COFFRE_ACCESS_AUD) {
    url.searchParams.set('aud', process.env.COFFRE_ACCESS_AUD);
  }

  const response = await fetch(url);
  if (!response.ok) fail(`dev IdP returned ${response.status}`);
  const { token } = (await response.json()) as { token: string };

  const me = (await api('/api/me', {}, {
    origin,
    mode: 'dev',
    credential: { kind: 'token', token },
  })) as Me;
  writeStore(
    withSession(readStore(), origin, {
      mode: 'dev',
      token,
      principal: me.principal,
      obtainedAt: new Date().toISOString(),
    }),
  );
  process.stdout.write(`logged in as ${me.principal.id} (${me.principal.type})\n`);
  printMe(me);
}

/** End the session on the server, then forget it here. */
async function logout(args: string[]): Promise<void> {
  const store = readStore();
  const requested = args[0] ?? process.env.COFFRE_API_URL ?? store.current;
  if (!requested) fail('not signed in anywhere');
  const origin = attempt(() => instanceOrigin(requested, 'dev'));
  const session = store.instances[origin];
  if (session === undefined) fail(`not signed in to ${origin}`);

  if (session.mode === 'signin' && session.token) {
    // Revoking is the point; if the server is unreachable, say so rather than
    // pretend the token is dead.
    const response = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      redirect: 'manual',
      headers: { authorization: `Bearer ${session.token}`, 'content-type': 'application/json' },
    }).catch(() => null);
    if (response === null) fail(`could not reach ${origin} to end the session; nothing was changed`);
    // 401: the session had already ended, which is what we wanted anyway.
    if (!response.ok && response.status !== 401) {
      fail(`${origin} refused to end the session (status ${response.status}); nothing was changed`);
    }
  }

  writeStore(withoutSession(store, origin));
  process.stdout.write(`Signed out of ${origin}\n`);
  if (session.mode === 'cloudflare') {
    process.stdout.write('  cloudflared still holds its Access token until it expires.\n');
  }
}

async function whoami(): Promise<void> {
  const to = target();
  const me = (await api('/api/me', {}, to)) as Me;
  const session = readStore().instances[to.origin];
  const via =
    to.credential.kind === 'access-service-token'
      ? 'an Access service token'
      : process.env.COFFRE_TOKEN
        ? 'COFFRE_TOKEN'
        : { signin: 'coffre sign-in', cloudflare: 'Cloudflare Access', dev: 'the dev IdP' }[to.mode];
  process.stdout.write(`${me.principal.id} (${me.principal.type}) on ${to.origin}, via ${via}\n`);
  if (!process.env.COFFRE_TOKEN && session?.expiresAt) {
    const days = Math.round((Date.parse(session.expiresAt) - Date.now()) / 86_400_000);
    process.stdout.write(`  session ends ${session.expiresAt.slice(0, 10)} (in ${days} day${days === 1 ? '' : 's'})\n`);
  }
  printMe(me);
}

/** Switch the current instance, or list them. */
function use(args: string[]): void {
  const store = readStore();
  if (args[0] === undefined) {
    const origins = Object.keys(store.instances);
    if (origins.length === 0) fail('not signed in anywhere yet: run `coffre login <url>`');
    for (const origin of origins) {
      const session = store.instances[origin];
      const marker = origin === store.current ? '*' : ' ';
      process.stdout.write(`${marker} ${origin.padEnd(36)} ${session.principal?.id ?? ''}\n`);
    }
    return;
  }
  const origin = attempt(() => instanceOrigin(args[0], 'dev'));
  if (!(origin in store.instances)) fail(`not signed in to ${origin}: run \`coffre login ${origin}\``);
  writeStore({ ...store, current: origin });
  process.stdout.write(`Now using ${origin}\n`);
}

async function get(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) fail('usage: coffre get <project>/<environment>/<KEY>');

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre get <project>/<environment>/<KEY>');

  const result = (await api(
    `/api/projects/${project}/environments/${environment}/secrets/${key}`,
  )) as { value: string };

  // Bare value on stdout so it composes: coffre get x/y/Z | pbcopy
  process.stdout.write(`${result.value}\n`);
}

async function list(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) fail('usage: coffre list <project>/<environment>');

  const { project, environment } = parsePath(target);
  const result = (await api(
    `/api/projects/${project}/environments/${environment}/keys`,
  )) as {
    permissions: string[];
    keys: { key: string; archived: boolean; version: number; updatedBy: string }[];
  };

  // Listing keys is not a read of any value, and is not logged as one.
  for (const entry of result.keys) {
    const archived = entry.archived ? '  (archived)' : '';
    process.stdout.write(`${entry.key}\tv${entry.version}\t${entry.updatedBy}${archived}\n`);
  }
}

async function set(args: string[]): Promise<void> {
  const [target, value] = args;
  if (!target) fail('usage: coffre set <project>/<environment>/<KEY> [value]');

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre set <project>/<environment>/<KEY> [value]');

  // Prefer stdin so the value never lands in shell history.
  const resolved = value ?? readFileSync(0, 'utf8').replace(/\n$/, '');

  const result = (await api(
    `/api/projects/${project}/environments/${environment}/secrets/${key}`,
    { method: 'PUT', body: JSON.stringify({ value: resolved }) },
  )) as { version: number };

  process.stdout.write(`${key} written as version ${result.version}\n`);
}

/**
 * Fetch every secret for an environment and exec a command with them in the
 * environment. One round trip, and one audit row per secret injected.
 */
async function run(args: string[]): Promise<void> {
  const separator = args.indexOf('--');
  if (separator === -1 || separator === args.length - 1) {
    fail('usage: coffre run <project>/<environment> -- <command> [args...]');
  }

  const target = args.slice(0, separator)[0];
  if (!target) fail('usage: coffre run <project>/<environment> -- <command> [args...]');

  const { project, environment } = parsePath(target);
  const command = args.slice(separator + 1);

  const result = (await api(
    `/api/projects/${project}/environments/${environment}/secrets`,
  )) as { secrets: Record<string, string> };

  const child = spawn(command[0], command.slice(1), {
    // Secrets are passed through the environment of the child only. They are
    // never written to disk and never appear in argv, which is world-readable
    // via ps.
    env: { ...process.env, ...result.secrets },
    stdio: 'inherit',
  });

  child.on('error', (error) => fail(`failed to run ${command[0]}: ${error.message}`));
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 0);
  });
}

/**
 * Print every secret in an environment, for tools that want a file or a
 * shell rather than a child process. Each value read is one audit row in
 * your name, exactly as with `run`.
 */
async function exportEnv(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: { format: { type: 'string', default: 'dotenv' } },
    allowPositionals: true,
  });
  const usage = 'usage: coffre export <project>/<environment> [--format dotenv|json|shell]';
  if (!positionals[0]) fail(usage);
  const format = values.format;
  if (format !== 'dotenv' && format !== 'json' && format !== 'shell') fail(usage);

  const { project, environment } = parsePath(positionals[0]);
  const result = (await api(
    `/api/projects/${project}/environments/${environment}/secrets`,
  )) as { secrets: Record<string, string> };

  const entries = Object.entries(result.secrets).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  process.stdout.write(
    format === 'json'
      ? `${JSON.stringify(Object.fromEntries(entries), null, 2)}\n`
      : attempt(() => (format === 'shell' ? formatShellExports(entries) : formatDotenv(entries))),
  );
  if (process.stderr.isTTY) {
    const count = entries.length;
    process.stderr.write(
      `coffre: read ${count} secret${count === 1 ? '' : 's'} from ${project}/${environment}; each read is in the audit log under your name\n`,
    );
  }
}

async function history(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) fail('usage: coffre history <project>/<environment>/<KEY>');

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre history <project>/<environment>/<KEY>');

  const result = (await api(
    `/api/projects/${project}/environments/${environment}/secrets/${key}/versions`,
  )) as {
    versions: { version: number; createdAt: string; createdBy: string; current: boolean }[];
  };

  for (const version of result.versions) {
    process.stdout.write(
      `v${String(version.version).padEnd(4)} ${version.createdAt.slice(0, 19).replace('T', ' ')}  ${version.createdBy.padEnd(24)}${version.current ? ' (current)' : ''}\n`,
    );
  }
}

async function rollback(args: string[]): Promise<void> {
  const [target, version] = args;
  if (!target || !version) {
    fail('usage: coffre rollback <project>/<environment>/<KEY> <version>');
  }

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre rollback <project>/<environment>/<KEY> <version>');

  await api(
    `/api/projects/${project}/environments/${environment}/secrets/${key}/rollback`,
    { method: 'POST', body: JSON.stringify({ version: Number(version) }) },
  );

  process.stdout.write(`${key} rolled back to version ${version}\n`);
}

/**
 * Import a .env file. Previews by default; --apply writes.
 *
 * The file is sent verbatim and parsed by the API, so the CLI and the UI
 * cannot disagree about what a .env file means.
 */
async function importEnv(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: { file: { type: 'string' }, apply: { type: 'boolean', default: false } },
    allowPositionals: true,
  });

  const target = positionals[0];
  if (!target) fail('usage: coffre import <project>/<environment> [--file .env] [--apply]');

  const { project, environment } = parsePath(target);
  const content = values.file ? readFileSync(values.file, 'utf8') : readFileSync(0, 'utf8');

  const result = (await api(
    `/api/projects/${project}/environments/${environment}/import`,
    { method: 'POST', body: JSON.stringify({ content, dryRun: !values.apply }) },
  )) as {
    plan: { key: string; action: string; version: number | null }[];
    problems: { line: number; reason: string; text: string }[];
  };

  for (const problem of result.problems ?? []) {
    process.stderr.write(`  line ${problem.line}: ${problem.reason} (${problem.text})\n`);
  }
  for (const entry of result.plan) {
    process.stdout.write(`${entry.action.padEnd(10)} ${entry.key}\n`);
  }

  if (!values.apply) {
    const changes = result.plan.filter((entry) => entry.action !== 'unchanged').length;
    process.stdout.write(
      `\n${changes} change${changes === 1 ? '' : 's'} pending. Re-run with --apply to write.\n`,
    );
  }
}

async function projects(): Promise<void> {
  const result = (await api('/api/admin/projects')) as {
    projects: {
      slug: string;
      name: string;
      archivedAt: string | null;
      permissions: string[];
      environments: { slug: string; archivedAt: string | null; secretCount: number }[];
    }[];
  };

  for (const project of result.projects) {
    const archived = project.archivedAt === null ? '' : ' (archived)';
    process.stdout.write(`${project.slug}${archived}  ${project.name}\n`);
    for (const environment of project.environments.filter((e) => e.archivedAt === null)) {
      process.stdout.write(
        `  ${environment.slug.padEnd(16)} ${environment.secretCount} secrets\n`,
      );
    }
  }
}

async function whoHasAccess(): Promise<void> {
  const result = (await api('/api/admin/principals')) as {
    principals: {
      principalId: string;
      principalType: string;
      isRootAdmin: boolean;
      grants: { project: string; scope: string; role: string; expiresAt: string | null }[];
    }[];
  };

  for (const principal of result.principals) {
    const root = principal.isRootAdmin ? '  [root admin]' : '';
    process.stdout.write(`${principal.principalId} (${principal.principalType})${root}\n`);
    for (const g of principal.grants) {
      const until = g.expiresAt === null ? '' : ` until ${g.expiresAt.slice(0, 10)}`;
      process.stdout.write(`  ${g.project}/${g.scope.padEnd(16)} ${g.role}${until}\n`);
    }
  }
}

async function grantAccess(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      role: { type: 'string' },
      env: { type: 'string' },
      service: { type: 'boolean', default: false },
      expires: { type: 'string' },
    },
    allowPositionals: true,
  });

  const [project, principalId] = positionals;
  if (!project || !principalId || !values.role) {
    fail('usage: coffre grant <project> <principal> --role <role> [--env <env>] [--service] [--expires YYYY-MM-DD]');
  }

  await api(`/api/admin/projects/${project}/grants`, {
    method: 'POST',
    body: JSON.stringify({
      principalType: values.service ? 'service' : 'user',
      principalId,
      role: values.role,
      environmentSlug: values.env ?? null,
      expiresAt: values.expires ? new Date(`${values.expires}T23:59:59Z`).toISOString() : null,
    }),
  });

  const scope = values.env ? `${project}/${values.env}` : project;
  process.stdout.write(`granted ${values.role} on ${scope} to ${principalId}\n`);
}

type PrincipalReport = {
  principalType: 'user' | 'service';
  status: 'active' | 'removed';
  removedAt: string | null;
  removedBy: string | null;
  live: { grants: number; sessions: number; tokens: number; identities: number };
  exposed: {
    project: string;
    environment: string;
    key: string;
    version: number;
    how: 'read' | 'wrote';
    at: string;
  }[];
  rotated: number;
  issuedTokens: { service: string; label: string | null; hint: string; expiresAt: string }[];
  syncs: (SyncView & { project: string; environment: string })[];
};

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

/** "2 grants, 1 session, 0 linked accounts": what a removal ends. */
function waysIn(
  principalType: 'user' | 'service',
  counts: { grants: number; sessions: number; tokens: number; identities: number },
): string {
  return principalType === 'user'
    ? [plural(counts.grants, 'grant'), plural(counts.sessions, 'session'), plural(counts.identities, 'linked account')].join(', ')
    : [plural(counts.grants, 'grant'), plural(counts.tokens, 'token')].join(', ');
}

/**
 * Offboard someone. Previews by default, like import: what removing them
 * would revoke, and what they leave behind. --apply removes them.
 *
 * Removal takes every way in away at once. What it cannot take back is what
 * they saw, so the report after it is the list of values to rotate.
 */
async function offboard(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      service: { type: 'boolean', default: false },
      apply: { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });

  const principalId = positionals[0];
  if (!principalId) fail('usage: coffre offboard <principal> [--service] [--apply]');
  const path = `/api/admin/directory/${values.service ? 'service' : 'user'}/${encodeURIComponent(principalId)}`;

  let report = (await api(path)) as PrincipalReport;
  const they = report.principalType === 'user' ? 'they' : 'it';

  if (report.status === 'active' && values.apply) {
    const removed = (await api(path, { method: 'DELETE' })) as {
      revoked: number;
      sessions: number;
      tokens: number;
      identities: number;
    };
    process.stdout.write(
      `removed ${principalId}: revoked ${waysIn(report.principalType, { ...removed, grants: removed.revoked })}\n`,
    );
    report = (await api(path)) as PrincipalReport;
  } else if (report.status === 'active') {
    process.stdout.write(
      `${principalId} is active; removing would revoke ${waysIn(report.principalType, report.live)}\n`,
    );
  } else {
    const by = report.removedBy === null ? '' : ` by ${report.removedBy}`;
    const at = report.removedAt === null ? '' : ` on ${report.removedAt.slice(0, 16).replace('T', ' ')}`;
    process.stdout.write(`${principalId} was removed${by}${at}\n`);
  }

  const rotated = report.rotated > 0 ? `, ${report.rotated} already rotated` : '';
  const when = report.status === 'active' ? ` once ${they} ${they === 'they' ? 'leave' : 'is retired'}` : '';
  process.stdout.write(
    `\nValues ${they} saw that nobody has changed since, to rotate${when} (${report.exposed.length}${rotated})\n`,
  );
  if (report.exposed.length === 0) process.stdout.write('  none\n');
  const names = report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`);
  const width = Math.max(0, ...names.map((name) => name.length));
  report.exposed.forEach((entry, index) => {
    process.stdout.write(
      `  ${names[index]!.padEnd(width)}  v${String(entry.version).padEnd(4)} ${entry.how} ${entry.at.slice(0, 10)}\n`,
    );
  });

  if (report.syncs.length > 0) {
    process.stdout.write(`\nSyncs ${they} set up, which keep pushing\n`);
    for (const entry of report.syncs) {
      const paused = entry.paused ? ' (paused)' : '';
      process.stdout.write(
        `  ${entry.project}/${entry.environment} -> ${entry.providerLabel} ${entry.destination}${paused}\n`,
      );
    }
  }
  if (report.issuedTokens.length > 0) {
    process.stdout.write(`\nService tokens ${they} issued, which still work\n`);
    for (const token of report.issuedTokens) {
      const label = token.label === null ? '' : ` "${token.label}"`;
      process.stdout.write(
        `  ${token.service}${label} ${token.hint}, expires ${token.expiresAt.slice(0, 10)}\n`,
      );
    }
  }

  if (report.status === 'active' && !values.apply) {
    process.stdout.write(`\nNothing changed. Re-run with --apply to remove ${principalId}.\n`);
  }
}

async function roles(): Promise<void> {
  const result = (await api('/api/admin/roles')) as {
    roles: {
      slug: string;
      description: string;
      permissions: string[];
      assignableToEnvironment: boolean;
    }[];
  };

  for (const role of result.roles) {
    const scope = role.assignableToEnvironment ? 'project or env' : 'project only';
    process.stdout.write(`${role.slug.padEnd(16)} [${scope}]  ${role.permissions.join(', ')}\n`);
  }
}

async function audit(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      limit: { type: 'string', default: '20' },
      actor: { type: 'string' },
      denied: { type: 'boolean', default: false },
    },
    allowPositionals: false,
  });

  const query = new URLSearchParams({ limit: values.limit ?? '20' });
  if (values.actor) query.set('actorId', values.actor);
  if (values.denied) query.set('decision', 'deny');

  const result = (await api(`/api/audit?${query}`)) as {
    entries: {
      occurredAt: string;
      actorId: string;
      action: string;
      decision: string;
      metadata: { key?: string };
    }[];
  };

  for (const entry of result.entries.reverse()) {
    const key = entry.metadata.key ?? '-';
    process.stdout.write(
      `${entry.occurredAt}  ${entry.decision.padEnd(5)}  ${entry.actorId.padEnd(28)}  ${entry.action.padEnd(13)}  ${key}\n`,
    );
  }
}

async function verify(): Promise<void> {
  const result = (await api('/api/audit/verify')) as
    | { ok: true; rows: number; head: string }
    | { ok: false; failedAtSeq: number; reason: string };

  if (result.ok) {
    process.stdout.write(`audit chain OK: ${result.rows} rows, head ${result.head}\n`);
    return;
  }
  process.stderr.write(
    `audit chain BROKEN at seq ${result.failedAtSeq}: ${result.reason}\n`,
  );
  process.exit(2);
}

type SyncView = {
  id: string;
  provider: string;
  providerLabel: string;
  destination: string;
  credential: string;
  paused: boolean;
  running: boolean;
  lastRunAt: string | null;
  lastStatus: 'succeeded' | 'partial' | 'failed' | null;
  lastError: string | null;
  synced: number;
  pending: number;
  skipped: { key: string; reason: string }[];
};

type RunOutcome =
  | { status: 'busy' }
  | {
      status: 'succeeded' | 'partial' | 'failed';
      upserted: string[];
      deleted: string[];
      failed: { key: string; operation: 'upsert' | 'delete'; message: string }[];
      error: string | null;
    };

const SYNC_USAGE = `usage:
  coffre sync list   <project>/<environment>
  coffre sync add    <project>/<environment> <destination> name=value… --credential <project>/<environment>/<KEY>
  coffre sync run    <project>/<environment> <sync>
  coffre sync pause  <project>/<environment> <sync>
  coffre sync resume <project>/<environment> <sync>
  coffre sync remove <project>/<environment> <sync>

<sync> is the start of an id from \`coffre sync list\`, or the destination's name
when the environment syncs to only one of that kind.

Destinations, and what they take. What is in brackets can be left out, and a
choice left out is its first option. Several targets go comma-separated.
${DESTINATIONS.map((entry) => `  ${entry.kind.padEnd(19)} ${entry.fields.map(fieldUsage).join(' ')}`).join('\n')}
`;

function fieldUsage(field: DestinationField): string {
  if (field.type === 'text') return field.optional ? `[${field.name}=…]` : `${field.name}=…`;
  const options = field.options.map((option) => option.value).join('|');
  return `[${field.name}=${options}]`;
}

/**
 * Push an environment somewhere else and keep it current. The server does
 * the work and checks every field; this names things and reports back.
 */
async function sync(args: string[]): Promise<void> {
  const [verb, path, ...rest] = args;
  if (verb === undefined || verb === '--help' || path === undefined) {
    process.stdout.write(SYNC_USAGE);
    process.exit(verb === undefined || verb === '--help' ? 0 : 1);
  }
  const { project, environment, key } = parsePath(path);
  if (key !== undefined) fail(`syncs belong to an environment: use ${project}/${environment}`);
  const base = `/api/projects/${project}/environments/${environment}/syncs`;

  if (verb === 'list') {
    const { syncs } = (await api(base)) as { syncs: SyncView[] };
    if (syncs.length === 0) process.stdout.write(`${project}/${environment} is not synced anywhere\n`);
    for (const entry of syncs) printSync(entry);
    return;
  }

  if (verb === 'add') {
    const { values, positionals } = parseArgs({
      args: rest,
      options: { credential: { type: 'string' } },
      allowPositionals: true,
    });
    const [kind, ...assignments] = positionals;
    const entry = DESTINATIONS.find((candidate) => candidate.kind === kind);
    if (entry === undefined) fail(`name a destination: ${DESTINATIONS.map((candidate) => candidate.kind).join(', ')}`);
    if (values.credential === undefined) {
      fail(`--credential names the secret holding the ${entry.label} token, such as ${entry.credentialExample}`);
    }
    const config = attempt(() => configFromArguments(entry, assignments));
    const created = (await api(base, {
      method: 'POST',
      body: JSON.stringify({ provider: entry.kind, config, credential: values.credential }),
    })) as SyncView;
    process.stdout.write(
      `Syncing ${project}/${environment} to ${created.destination} (${created.providerLabel}), id ${created.id.slice(0, 8)}.\n` +
        `The first push has started; \`coffre sync list ${project}/${environment}\` shows how it went.\n`,
    );
    return;
  }

  if (!['run', 'pause', 'resume', 'remove'].includes(verb)) fail(`unknown sync command "${verb}"; see \`coffre sync --help\``);
  const reference = rest[0];
  if (reference === undefined) fail(`usage: coffre sync ${verb} ${project}/${environment} <sync>`);
  const { syncs } = (await api(base)) as { syncs: SyncView[] };
  const chosen = attempt(() => pickSync(syncs, reference));

  if (verb === 'run') {
    // The server would only answer that it is busy.
    if (chosen.paused) fail(`syncing to ${chosen.destination} is paused; resume it first`);
    const { sync: after, outcome } = (await api(`/api/syncs/${chosen.id}/run`, { method: 'POST' })) as {
      sync: SyncView;
      outcome: RunOutcome;
    };
    if (outcome.status === 'busy') fail(`a run to ${chosen.destination} is already under way`);
    for (const failure of outcome.failed) {
      process.stderr.write(`  could not ${failure.operation === 'upsert' ? 'push' : 'remove'} ${failure.key}: ${failure.message}\n`);
    }
    if (outcome.status === 'failed') fail(`could not sync to ${after.destination}: ${outcome.error ?? 'the run failed'}`);
    const changed = outcome.upserted.length + outcome.deleted.length;
    process.stdout.write(
      changed === 0 && outcome.failed.length === 0
        ? `${after.destination} was already current\n`
        : `Pushed ${outcome.upserted.length}, removed ${outcome.deleted.length} at ${after.destination}\n`,
    );
    if (outcome.status === 'partial') process.exit(1);
    return;
  }

  if (verb === 'remove') {
    await api(`/api/syncs/${chosen.id}`, { method: 'DELETE' });
    process.stdout.write(
      `No longer syncing to ${chosen.destination}. Keys coffre pushed there stay; remove them at ${chosen.providerLabel} if they should go too.\n`,
    );
    return;
  }

  const paused = verb === 'pause';
  await api(`/api/syncs/${chosen.id}`, { method: 'PATCH', body: JSON.stringify({ paused }) });
  process.stdout.write(
    paused
      ? `Paused syncing to ${chosen.destination}\n`
      : `Resumed syncing to ${chosen.destination}; changes since the pause go out on the next run\n`,
  );
}

/** By id prefix, or by destination when only one sync goes to that kind. */
function pickSync(syncs: SyncView[], reference: string): SyncView {
  const byKind = syncs.filter((entry) => entry.provider === reference);
  if (byKind.length === 1) return byKind[0];
  if (byKind.length > 1) throw new Error(`more than one ${reference} sync here; name it by id (coffre sync list)`);
  if (reference.length < 4) throw new Error('give at least 4 characters of a sync id, or a destination name');
  const byId = syncs.filter((entry) => entry.id.startsWith(reference.toLowerCase()));
  if (byId.length === 1) return byId[0];
  if (byId.length > 1) throw new Error(`"${reference}" starts more than one sync id; give more of it`);
  throw new Error(`no sync "${reference}" here; \`coffre sync list\` shows them`);
}

function printSync(entry: SyncView): void {
  const state = entry.running
    ? 'pushing'
    : entry.paused
      ? 'paused'
      : entry.lastStatus === 'failed'
        ? 'failed'
        : entry.lastStatus === 'partial'
          ? 'partial'
          : entry.lastRunAt === null
            ? 'not run yet'
            : entry.pending > 0
              ? 'behind'
              : 'in sync';
  const counts = [`${entry.synced} synced`, ...(entry.pending > 0 ? [`${entry.pending} pending`] : [])];
  if (entry.lastRunAt !== null) counts.push(`last run ${entry.lastRunAt.slice(0, 16).replace('T', ' ')}`);
  process.stdout.write(`${entry.id.slice(0, 8)}  ${entry.providerLabel.padEnd(18)} ${entry.destination}\n`);
  process.stdout.write(`          ${state}: ${counts.join(', ')}; token from ${entry.credential}\n`);
  if (entry.lastError !== null && !entry.running) process.stdout.write(`          ${entry.lastError}\n`);
  for (const skipped of entry.skipped) {
    process.stdout.write(`          skips ${skipped.key}: ${skipped.reason}\n`);
  }
}

const USAGE = `coffre - secrets, with an audit log

  Session
    coffre login [<url>] [--no-browser]     sign in, and make <url> the current instance
    coffre logout [<url>]
    coffre whoami
    coffre use [<url>]                      list instances, or switch the current one

  Secrets
    coffre list     <project>/<environment>
    coffre get      <project>/<environment>/<KEY>
    coffre set      <project>/<environment>/<KEY> [value]   (reads stdin if omitted)
    coffre run      <project>/<environment> -- <command>
    coffre export   <project>/<environment> [--format dotenv|json|shell]
    coffre history  <project>/<environment>/<KEY>
    coffre rollback <project>/<environment>/<KEY> <version>
    coffre import   <project>/<environment> [--file .env] [--apply]

  Access
    coffre projects
    coffre roles
    coffre access
    coffre grant <project> <principal> --role <role> [--env <env>] [--service]
                 [--expires YYYY-MM-DD]
    coffre offboard <principal> [--service] [--apply]
                                            what removing them revokes, and what to rotate

  Syncs (coffre sync --help for destinations)
    coffre sync list   <project>/<environment>
    coffre sync add    <project>/<environment> <destination> name=value…
                       --credential <project>/<environment>/<KEY>
    coffre sync run|pause|resume|remove <project>/<environment> <sync>

  Audit
    coffre audit [--limit N] [--actor <id>] [--denied]
    coffre verify

  Environment (each overrides the saved session for one command)
    COFFRE_API_URL          which instance to talk to
    COFFRE_TOKEN            a service token (coffre_svc_…), for CI
    COFFRE_ACCESS_CLIENT_ID, COFFRE_ACCESS_CLIENT_SECRET
                            a Cloudflare Access service token, for CI
    COFFRE_AUTH_MODE        signin, cloudflare or dev; normally detected at login
`;

const [command, ...rest] = process.argv.slice(2);

switch (command) {
  case 'login':
    await login(rest);
    break;
  case 'logout':
    await logout(rest);
    break;
  case 'whoami':
    await whoami();
    break;
  case 'use':
    use(rest);
    break;
  case 'export':
    await exportEnv(rest);
    break;
  case 'list':
    await list(rest);
    break;
  case 'get':
    await get(rest);
    break;
  case 'set':
    await set(rest);
    break;
  case 'run':
    await run(rest);
    break;
  case 'history':
    await history(rest);
    break;
  case 'rollback':
    await rollback(rest);
    break;
  case 'import':
    await importEnv(rest);
    break;
  case 'projects':
    await projects();
    break;
  case 'roles':
    await roles();
    break;
  case 'access':
    await whoHasAccess();
    break;
  case 'grant':
    await grantAccess(rest);
    break;
  case 'offboard':
    await offboard(rest);
    break;
  case 'sync':
    await sync(rest);
    break;
  case 'audit':
    await audit(rest);
    break;
  case 'verify':
    await verify();
    break;
  default:
    process.stdout.write(USAGE);
    process.exit(command === undefined || command === '--help' ? 0 : 1);
}
