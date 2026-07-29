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
import {
  cliAuthHeader,
  cloudflareApiUrl,
  isCloudflareAccessRedirect,
  isJsonContentType,
} from './auth-mode.ts';

const CREDENTIALS_PATH = join(homedir(), '.coffre', 'credentials.json');
const API_URL = process.env.COFFRE_API_URL ?? 'http://127.0.0.1:8080';
const AUTH_MODE = process.env.COFFRE_AUTH_MODE ?? '';
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
  if (AUTH_MODE !== 'dev' && AUTH_MODE !== 'cloudflare') {
    fail('COFFRE_AUTH_MODE must be exactly "dev" or "cloudflare"');
  }

  let apiUrl = API_URL;
  if (AUTH_MODE === 'cloudflare') {
    try {
      apiUrl = cloudflareApiUrl(process.env.COFFRE_API_URL);
    } catch (error) {
      fail(error instanceof Error ? error.message : 'invalid COFFRE_API_URL');
    }
  }

  const response = await fetch(`${apiUrl}${path}`, {
    ...init,
    // Cloudflare Access redirects rejected non-browser clients to its login
    // page. Following that redirect would turn an auth failure into HTML that
    // later explodes in JSON parsing.
    redirect: 'manual',
    headers: {
      ...cliAuthHeader(AUTH_MODE, token),
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
  });

  if (isCloudflareAccessRedirect(AUTH_MODE, response.status)) {
    fail('unauthenticated: your token is missing, expired or invalid');
  }
  if (response.status === 401) fail('unauthenticated: your token is missing, expired or invalid');
  if (response.status === 403) fail('forbidden: you do not have a grant for that environment');
  if (response.status === 404) fail('not found');
  if (!response.ok) fail(`request failed with status ${response.status}`);
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

async function login(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      email: { type: 'string' },
      'service-token': { type: 'string' },
    },
    allowPositionals: false,
  });

  if (AUTH_MODE !== 'dev') {
    // In production Cloudflare Access issues the token through its browser SSO
    // flow; the CLI does not implement an auth protocol of its own.
    fail(
      'persona login is available only when COFFRE_AUTH_MODE=dev.\n' +
        '  In production: run `cloudflared access login <coffre-url>` and export\n' +
        '  COFFRE_TOKEN=$(cloudflared access token -app=<coffre-url>)',
    );
  }
  if (DEV_IDP_URL === '') fail('COFFRE_DEV_IDP_URL is required when COFFRE_AUTH_MODE=dev');

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
    environments: { project: string; environment: string; permissions: string[] }[];
  };

  process.stdout.write(`logged in as ${me.principal.id} (${me.principal.type})\n`);
  if (me.environments.length === 0) {
    process.stdout.write('  no environments granted\n');
  }
  for (const entry of me.environments) {
    process.stdout.write(
      `  ${`${entry.project}/${entry.environment}`.padEnd(24)} ${entry.permissions.join(', ')}\n`,
    );
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

async function history(args: string[]): Promise<void> {
  const target = args[0];
  if (!target) fail('usage: coffre history <project>/<environment>/<KEY>');

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre history <project>/<environment>/<KEY>');

  const result = (await api(
    `/v1/projects/${project}/environments/${environment}/secrets/${key}/versions`,
    loadToken(),
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
    `/v1/projects/${project}/environments/${environment}/secrets/${key}/rollback`,
    loadToken(),
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
    `/v1/projects/${project}/environments/${environment}/import`,
    loadToken(),
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
  const result = (await api('/v1/admin/projects', loadToken())) as {
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
  const result = (await api('/v1/admin/principals', loadToken())) as {
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

  await api(`/v1/admin/projects/${project}/grants`, loadToken(), {
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

async function roles(): Promise<void> {
  const result = (await api('/v1/admin/roles', loadToken())) as {
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

  Secrets
    coffre list     <project>/<environment>
    coffre get      <project>/<environment>/<KEY>
    coffre set      <project>/<environment>/<KEY> [value]   (reads stdin if omitted)
    coffre run      <project>/<environment> -- <command>
    coffre history  <project>/<environment>/<KEY>
    coffre rollback <project>/<environment>/<KEY> <version>
    coffre import   <project>/<environment> [--file .env] [--apply]

  Access
    coffre projects
    coffre roles
    coffre access
    coffre grant <project> <principal> --role <role> [--env <env>] [--service]
                 [--expires YYYY-MM-DD]

  Audit
    coffre audit [--limit N] [--actor <id>] [--denied]
    coffre verify

  Session
    coffre login [--email <addr>] [--service-token <name>]
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
