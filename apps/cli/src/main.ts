#!/usr/bin/env node
/**
 * coffre CLI.
 *
 * Deliberately dependency-free: node:util's parseArgs and node:child_process
 * are enough. A tool that handles every credential we own is a poor place to
 * add a transitive dependency tree for argument parsing.
 */
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

const CREDENTIALS_PATH = join(homedir(), '.coffre', 'credentials.json');
const API_URL = process.env.COFFRE_API_URL ?? 'http://127.0.0.1:8080';
const DEV_IDP_URL = process.env.COFFRE_DEV_IDP_URL ?? '';

type Credentials = { token: string; obtainedAt: string };

function saveToken(token: string): void {
  mkdirSync(dirname(CREDENTIALS_PATH), { recursive: true, mode: 0o700 });
  const payload: Credentials = { token, obtainedAt: new Date().toISOString() };
  // 0600: a token that grants access to production secrets should not be
  // world-readable on a shared machine.
  writeFileSync(CREDENTIALS_PATH, JSON.stringify(payload, null, 2), { mode: 0o600 });
}

function loadToken(): string {
  if (process.env.COFFRE_TOKEN) return process.env.COFFRE_TOKEN;

  if (!existsSync(CREDENTIALS_PATH)) {
    fail('not logged in: run `coffre login` first');
  }
  const credentials = JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf8')) as Credentials;
  return credentials.token;
}

function fail(message: string): never {
  process.stderr.write(`coffre: ${message}\n`);
  process.exit(1);
}

async function api(path: string, token: string, init: RequestInit = {}): Promise<unknown> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      // The same header Cloudflare Access sets on requests it forwards to the
      // origin. Locally the dev IdP mints the token; in production Access does.
      'cf-access-jwt-assertion': token,
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
  });

  if (response.status === 401) fail('unauthenticated: your token is missing, expired or invalid');
  if (response.status === 403) fail('forbidden: you do not have a grant for that environment');
  if (response.status === 404) fail('not found');
  if (!response.ok) fail(`request failed with status ${response.status}`);

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

async function login(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      email: { type: 'string' },
      'service-token': { type: 'string' },
    },
    allowPositionals: false,
  });

  if (DEV_IDP_URL === '') {
    // In production Cloudflare Access issues the token through its browser SSO
    // flow; the CLI does not implement an auth protocol of its own.
    fail(
      'COFFRE_DEV_IDP_URL is not set.\n' +
        '  In production: run `cloudflared access login <coffre-url>` and export\n' +
        '  COFFRE_TOKEN=$(cloudflared access token -app=<coffre-url>)',
    );
  }

  const url = new URL('/dev/mint', DEV_IDP_URL);
  if (values['service-token']) {
    url.searchParams.set('common_name', values['service-token']);
  } else {
    url.searchParams.set('email', values.email ?? 'erwin@equisafe.io');
  }
  if (process.env.COFFRE_ACCESS_AUD) {
    url.searchParams.set('aud', process.env.COFFRE_ACCESS_AUD);
  }

  const response = await fetch(url);
  if (!response.ok) fail(`dev IdP returned ${response.status}`);
  const { token } = (await response.json()) as { token: string };

  saveToken(token);

  const me = (await api('/v1/me', token)) as {
    principal: { type: string; id: string };
    environments: { project: string; environment: string; capability: string }[];
  };

  process.stdout.write(`logged in as ${me.principal.id} (${me.principal.type})\n`);
  if (me.environments.length === 0) {
    process.stdout.write('  no environments granted\n');
  }
  for (const entry of me.environments) {
    process.stdout.write(`  ${entry.project}/${entry.environment}  ${entry.capability}\n`);
  }
}

async function get(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) fail('usage: coffre get <project>/<environment>/<KEY>');

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre get <project>/<environment>/<KEY>');

  const result = (await api(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}`,
    loadToken(),
  )) as { value: string };

  // Bare value on stdout so it composes: coffre get x/y/Z | pbcopy
  process.stdout.write(`${result.value}\n`);
}

async function list(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) fail('usage: coffre list <project>/<environment>');

  const { project, environment } = parsePath(target);
  const result = (await api(
    `/v1/projects/${project}/environments/${environment}/keys`,
    loadToken(),
  )) as { capability: string; keys: { key: string; version: number; updatedBy: string }[] };

  // Listing keys is not a read of any value, and is not logged as one.
  for (const entry of result.keys) {
    process.stdout.write(`${entry.key}\tv${entry.version}\t${entry.updatedBy}\n`);
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
    `/v1/projects/${project}/environments/${environment}/secrets/${key}`,
    loadToken(),
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
    `/v1/projects/${project}/environments/${environment}/secrets`,
    loadToken(),
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

  const result = (await api(`/v1/audit?${query}`, loadToken())) as {
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
  const result = (await api('/v1/audit/verify', loadToken())) as
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

const USAGE = `coffre - secrets, with an audit log

  coffre login [--email <addr>] [--service-token <name>]
  coffre list  <project>/<environment>
  coffre get   <project>/<environment>/<KEY>
  coffre set   <project>/<environment>/<KEY> [value]     (reads stdin if omitted)
  coffre run   <project>/<environment> -- <command>
  coffre audit [--limit N] [--actor <id>] [--denied]
  coffre verify
`;

const [command, ...rest] = process.argv.slice(2);

switch (command) {
  case 'login':
    await login(rest);
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
