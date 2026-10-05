// `coffre verify`, as an operator runs it against this deployment: the
// CLI's own entry, as @coffre/cli ships it, in a child process with a home
// of its own and none of this process's COFFRE_ variables. `verify
// instance` with a token from CI, signed in with `coffre login --token`; with `coffre login`, as a user,
// who is turned away, and as the admin, twice, then interrupted, its
// session left signed in each time; and `verify keys` with this
// deployment's keys, a wrong one and a malformed one.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import { CoffreError, type CoffreClient } from '@coffre/client';

import { bearer } from '../browser.ts';
import { KEYS } from '../fixtures.ts';
import { expect, Failure } from '../report.ts';
import type { Person } from './people.ts';

/** What `coffre verify instance` makes and finds on an instance, as an owner: its own place, service and key. */
export const PROBE = { project: 'conformance', environment: 'live', service: 'token:conformance-probe', key: 'SIGN_IN_CANARY' } as const;

/** A canary the token reads, as `--canary` names it. */
export type Canary = { project: string; environment: string; key: string; value: string };

/** What a credential coffre issues, or a canary, looks like in a run's output. */
const SHOWN = /coffre_(svc|cli|web)_[A-Za-z0-9_-]{8,}|coffre-canary-[0-9a-f]{8,}/;

/** The CLI's entry, as its package ships it: built, as a deployment installs it. */
function entry(): string {
  const main = join(dirname(createRequire(import.meta.url).resolve('@coffre/cli/package.json')), 'dist', 'main.js');
  if (!existsSync(main)) throw new Failure('@coffre/cli is not built: run `pnpm build` at the root of the coffre repository');
  return main;
}

type Run = { code: number | null; output: string };

/** A running command: what it has printed so far, stdout and stderr as one, and its exit. */
type Running = { output: () => string; exited: Promise<number | null>; kill: (signal: NodeJS.Signals) => void; waitFor: (pattern: RegExp, what: string) => Promise<RegExpExecArray> };

/** The CLI with a home of its own, where `coffre login` keeps its session: one person's terminal. */
export class Cli {
  readonly origin: string;
  readonly home: string;

  constructor(origin: string) {
    this.origin = origin;
    this.home = mkdtempSync(join(tmpdir(), 'coffre-conformance-cli-'));
  }

  start(args: string[], env: Record<string, string> = {}, input?: string): Running {
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_') && name !== 'NODE_OPTIONS'));
    const child = spawn(process.execPath, [entry(), ...args], {
      env: { ...inherited, HOME: this.home, NO_COLOR: '1', ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
    child.stdin.end(input ?? '');
    const exited = new Promise<number | null>((resolve) => child.on('exit', (code) => resolve(code)));
    return {
      output: () => output,
      exited,
      kill: (signal) => child.kill(signal),
      waitFor: async (pattern, what) => {
        for (let tries = 0; !pattern.test(output); tries += 1) {
          if (tries >= 1200 || child.exitCode !== null) {
            child.kill('SIGKILL');
            throw new Failure(`coffre never got to ${what}`, output);
          }
          await sleep(50);
        }
        return pattern.exec(output)!;
      },
    };
  }

  async run(args: string[], env: Record<string, string> = {}, input?: string): Promise<Run> {
    const running = this.start(args, env, input);
    const code = await running.exited;
    return { code, output: running.output() };
  }

  /** The session `coffre login` keeps here, for this run to check it is still signed in. */
  session(): string {
    const store = JSON.parse(readFileSync(join(this.home, '.coffre', 'credentials.json'), 'utf8')) as { instances: Record<string, { token?: string }> };
    const token = store.instances[this.origin]?.token;
    expect(token !== undefined, `no session for ${this.origin} in the CLI's credentials`, Object.keys(store.instances));
    return token;
  }

  remove(): void {
    rmSync(this.home, { recursive: true, force: true });
  }
}

/** `coffre login`, approved by `person` in their browser, as they would: the CLI's own session. */
export async function cliLogin(cli: Cli, person: Person): Promise<{ detail: string; value: Cli }> {
  const login = cli.start(['login', cli.origin, '--no-browser']);
  const [, code] = await login.waitFor(/shows the code\s+(\S+)/, 'its device login');
  await person.api.deviceLogins.decide(code!, true);
  const status = await login.exited;
  expect(status === 0, `coffre login exited ${status}`, login.output());
  await bearer(cli.origin, cli.session()).me();
  return { detail: `${person.email}, through \`coffre login\` approved in the browser`, value: cli };
}

/** The marks a run printed, by check: `✓`, `✗` or `–`. */
function marks(output: string): Record<string, string> {
  const lines = [...output.matchAll(/^ {2}([✓✗–]) (\S.{18}) /gm)];
  return Object.fromEntries(lines.map(([, mark, name]) => [name!.trim(), mark!]));
}

/** The token's run, from CI: as no one, then as the token, which is no owner and skips verification. */
export async function verifyWithToken(cli: Cli, live: { token: string; canary: Canary }): Promise<string> {
  const { canary } = live;
  // As a CI step does: the token piped to `coffre login --token`, then the canary's value to the check.
  const login = await cli.run(['login', cli.origin, '--token'], {}, `${live.token}\n`);
  expect(login.code === 0, `coffre login --token exited ${login.code}`, login.output);
  const run = await cli.run(['verify', 'instance', cli.origin, '--canary', `${canary.project}/${canary.environment}/${canary.key}`], {}, `${canary.value}\n`);
  const seen = marks(run.output);
  expect(run.code === 0, `coffre verify instance with a token exited ${run.code}`, run.output);
  expect(seen['token verification'] === '–', 'a token that is no owner did not skip verification', run.output);
  expect(!run.output.includes(live.token) && !run.output.includes(canary.value), 'the run printed its token or its canary', run.output);
  const ok = Object.values(seen).filter((mark) => mark === '✓').length;
  return `${ok} checks ok as no one and as the token, its verification skipped; neither the token nor the canary shown`;
}

/** What a run as an owner must leave as it was: every member and their grants, but its service; every project and environment. */
async function everythingElse(api: CoffreClient): Promise<string> {
  const { members } = await api.members.list();
  const { projects } = await api.projects.list();
  return JSON.stringify({
    members: members.filter(({ member }) => member !== PROBE.service),
    projects: projects.map(({ slug, archivedAt, environments }) => ({ slug, archivedAt, environments: environments.map(({ slug: env }) => env) })),
  });
}

/** Signed in as a user, the run says so, and makes nothing; their session stays. Returns what it must leave as it was. */
export async function verifyAsUser(cli: Cli, user: Person, admin: Person): Promise<{ detail: string; value: string }> {
  const before = await everythingElse(admin.api);
  const run = await cli.run(['verify', 'instance']);
  expect(run.code === 1, `coffre verify instance as a user exited ${run.code}, not 1`, run.output);
  expect(marks(run.output).owner === '✗', 'the run went on past a user', run.output);
  expect(/is neither an owner nor a root admin of \S+: nothing was made/.test(run.output), 'the run did not say plainly why it stopped', run.output);
  const service = await admin.api.members.get(PROBE.service).then(
    () => 'there',
    (error: unknown) => (error instanceof CoffreError && error.status === 404 ? 'absent' : Promise.reject(error)),
  );
  expect(service === 'absent', `${PROBE.service} was made for a user`);
  await bearer(cli.origin, cli.session()).me();
  expect((await everythingElse(admin.api)) === before, 'the run changed a member, a grant, a project or an environment for a user');
  return { detail: `${user.email}, a user, is told plainly; nothing made, the session still signed in`, value: before };
}

/** One run as the admin, with their `coffre login` session: every check passes, none skipped, and the session stays. Returns its setup's line. */
export async function verifyAsOwner(cli: Cli): Promise<{ detail: string; value: string }> {
  const session = cli.session();
  const run = await cli.run(['verify', 'instance']);
  const seen = marks(run.output);
  expect(run.code === 0, `coffre verify instance as the admin exited ${run.code}`, run.output);
  // Signed in, nothing is out of reach: a check skipped, such as the token's verification, would only be noise.
  const skipped = Object.entries(seen).filter(([, mark]) => mark !== '✓').map(([name]) => name);
  expect(skipped.length === 0, `the run skipped ${skipped.join(', ')}`, run.output);
  expect(!SHOWN.test(run.output) && !run.output.includes(session), 'the run printed a credential, the session or its canary', SHOWN.exec(run.output)?.[0]);
  expect(/your session stays/.test(run.output), 'the run did not say the session stays', run.output);
  await bearer(cli.origin, session).me();
  const setup = /^ {2}✓ setup +(.*)$/m.exec(run.output)?.[1] ?? '';
  return { detail: `${Object.keys(seen).length} checks ok, the session still signed in; ${setup.split(';')[0]}`, value: setup };
}

/**
 * `coffre verify instance` interrupted mid-run by a Ctrl-C: it exits 130
 * with its credential revoked, the session still signed in, and nothing it
 * printed shows either, or its canary.
 */
export async function verifyInterrupted(cli: Cli, admin: Person): Promise<string> {
  const session = cli.session();
  const running = cli.start(['verify', 'instance']);
  try {
    await running.waitFor(/✓ token reveal/, 'its token checks');
    running.kill('SIGINT');
    const status = await running.exited;
    expect(status === 130, `the interrupted run exited ${status}, not 130`, running.output());
  } finally {
    running.kill('SIGKILL');
  }
  const { tokens } = await admin.api.tokens.list(PROBE.service);
  expect(tokens.length === 0, `the interrupted run left ${PROBE.service} ${tokens.length} credential(s)`, tokens);
  await bearer(cli.origin, session).me();
  expect(!SHOWN.test(running.output()), 'the run printed a credential or a canary', SHOWN.exec(running.output())?.[0]);
  return 'Ctrl-C mid-run: exit 130, its credential revoked, the session still signed in; nothing it printed shows either, or its canary';
}

/**
 * After the runs: the second found everything the first made; the service
 * holds no credential; the session is the one `coffre login` made, still
 * signed in; the canary an operator keeps beside is as it was; nothing
 * else changed; the runs' reads are in the audit log.
 */
export async function verifyLeftovers(cli: Cli, admin: Person, setups: string[], before: string, kept: Canary): Promise<string> {
  // Shown as people read it, service:<name>, though the API keeps token:<name>.
  expect(setups[0]!.includes(`the service account ${PROBE.service.replace(/^token:/, 'service:')}`), 'the first run did not make its service account', setups[0]);
  expect(setups.slice(1).every((line) => line.startsWith('all found')), 'a later run made something again', setups);
  const { tokens } = await admin.api.tokens.list(PROBE.service);
  expect(tokens.length === 0, `${PROBE.service} still holds ${tokens.length} credential(s)`, tokens);
  const { sessions } = await bearer(cli.origin, cli.session()).sessions.list();
  const current = sessions.filter(({ current }) => current);
  expect(current.length === 1 && current[0]!.kind === 'cli', "the CLI's session is not the one it was", sessions);
  const place = `${kept.project}/${kept.environment}`;
  const { values } = await admin.api.secrets.reveal(`${place}/${kept.key}`);
  expect(values[kept.key] === kept.value, `${place}/${kept.key}, kept beside the run's own, was changed`);
  expect((await everythingElse(admin.api)) === before, 'the runs changed a member, a grant, a project or an environment besides their own');
  const { entries } = await admin.api.audit.list({ actor: PROBE.service, limit: 50 });
  expect(entries.length > 0, `the audit log holds no entry by ${PROBE.service}`);
  return `the second run found all; ${PROBE.service} holds no credential; the CLI's session signed in; ${place}/${kept.key} untouched; nothing else changed; ${entries.length} entries by ${PROBE.service} stay`;
}

/**
 * `coffre verify keys`, with the admin's session, the keys piped in: this
 * deployment's pass; a wrong vault key fails and the right app key passes;
 * a malformed app key fails. No key is ever printed.
 */
export async function verifyKeys(cli: Cli): Promise<string> {
  const wrong = Buffer.alloc(32, 7).toString('base64');
  // Piped in, as a script does: the vault key's line, then the app key's.
  const runs: { args: string[]; input: string; code: number; vault: string; app: string; said?: RegExp }[] = [
    { args: ['--vault-id', KEYS.VAULT_KEY_ID], input: `${KEYS.VAULT_KEY}\n${KEYS.APP_KEY}\n`, code: 0, vault: '✓', app: '✓' },
    { args: [], input: `${wrong}\n${KEYS.APP_KEY}\n`, code: 1, vault: '✗', app: '✓', said: /✗ vault key +not this instance's vault key/ },
    { args: [], input: `${KEYS.VAULT_KEY}\nnot-a-key\n`, code: 1, vault: '✓', app: '✗', said: /✗ app key +not an app key/ },
  ];
  for (const { args, input, code, vault, app, said } of runs) {
    const run = await cli.run(['verify', 'keys', ...args], {}, input);
    const seen = marks(run.output);
    expect(run.code === code && seen['vault key'] === vault && seen['app key'] === app, `coffre verify keys exited ${run.code}`, run.output);
    if (said !== undefined) expect(said.test(run.output), 'it did not say which key is not right', run.output);
    for (const key of [KEYS.VAULT_KEY, KEYS.APP_KEY, wrong, 'not-a-key']) expect(!run.output.includes(key), 'a key was printed', run.output);
  }
  return "this deployment's keys pass, vault ID included; a wrong vault key and a malformed app key are each named; no key shown";
}

/**
 * Everything the API does, the CLI does: with the admin's `coffre login`
 * session, a project and its environment, a secret set and renamed, a
 * service admitted and granted, a token issued into a 0600 file, then
 * piped to `coffre login --token` in a CLI of the service's own, read
 * with, revoked after its preview, and refused from then on; the grant
 * revoked, the secret and the project archived. No token shows in what
 * either prints.
 */
export async function manageByCli(cli: Cli): Promise<string> {
  const steps: string[] = [];
  const ci = new Cli(cli.origin);
  const as = (who: Cli, label: string) => async (args: string[], input?: string, code = 0): Promise<string> => {
    const run = await who.run(args, {}, input);
    expect(run.code === code, `coffre ${args.join(' ')}${label} exited ${run.code}, not ${code}`, run.output);
    steps.push(`${args.slice(0, 2).join(' ')}${label}`);
    return run.output;
  };
  const [coffre, service] = [as(cli, ''), as(ci, ', as the service')];
  try {
    const value = `cli-value-${randomBytes(8).toString('hex')}`;
    await coffre(['projects', 'create', 'conformance-cli', '--name', 'CLI']);
    await coffre(['environments', 'create', 'conformance-cli/ci']);
    await coffre(['set', 'conformance-cli/ci/API_KEY'], value);
    await coffre(['rename', 'conformance-cli/ci/API_KEY', 'API_TOKEN']);
    const refused = await coffre(['grant', 'conformance-cli', 'conformance-deploy', '--role', 'viewer', '--env', 'ci', '--service'], undefined, 1);
    expect(refused.includes('admit them first, `coffre admit service:conformance-deploy`'), 'grant to a service not yet admitted did not say to admit it', refused);
    const admitted = await coffre(['admit', 'conformance-deploy', '--service']);
    expect(admitted.includes('admitted service:conformance-deploy') && !admitted.includes('token:'), 'admit --service did not name the service account as service:<name>', admitted);
    expect(admitted.includes('next: coffre grant <project> conformance-deploy'), 'admit --service did not say what comes next', admitted);
    await coffre(['grant', 'conformance-cli', 'conformance-deploy', '--role', 'viewer', '--env', 'ci', '--service']);

    const file = join(cli.home, 'ci-token');
    const wrote = await coffre(['tokens', 'issue', 'conformance-deploy', '--label', 'conformance', '--expires-in', '1', '--output-file', file]);
    const token = readFileSync(file, 'utf8').trim();
    expect(/^coffre_svc_/.test(token) && (statSync(file).mode & 0o777) === 0o600, 'the token file is not a 0600 file holding a service token', statSync(file).mode);
    expect(!wrote.includes(token), 'tokens issue --output-file printed the token');
    // The token as CI uses it: piped to `coffre login --token`.
    const signedIn = await service(['login', cli.origin, '--token'], `${token}\n`);
    expect(!signedIn.includes(token), 'coffre login --token printed the token');
    const read = await service(['get', 'conformance-cli/ci/API_TOKEN']);
    expect(read.trim() === value, 'the issued token did not read the renamed secret', read);

    const [listed] = JSON.parse(await coffre(['tokens', 'conformance-deploy', '--json'])) as { id: string; label: string }[];
    expect(listed?.label === 'conformance', 'tokens --json does not list the issued token', listed);
    const preview = await coffre(['tokens', 'revoke', 'conformance-deploy', listed!.id]);
    expect(/Nothing changed\. Re-run with --apply/.test(preview), 'tokens revoke without --apply did not preview', preview);
    await service(['get', 'conformance-cli/ci/API_TOKEN']);
    await coffre(['tokens', 'revoke', 'conformance-deploy', listed!.id, '--apply']);
    const gone = await service(['get', 'conformance-cli/ci/API_TOKEN'], undefined, 1);
    expect(/does not know this bearer token/.test(gone), 'a revoked token was not refused plainly', gone);

    await coffre(['revoke', 'conformance-cli', 'conformance-deploy', '--env', 'ci', '--service']);
    await coffre(['archive', 'conformance-cli/ci/API_TOKEN']);
    const keys = JSON.parse(await coffre(['list', 'conformance-cli/ci', '--json'])) as { key: string; archived: boolean }[];
    expect(keys.length === 1 && keys[0]!.key === 'API_TOKEN' && keys[0]!.archived, 'the renamed secret is not listed, archived', keys);
    await coffre(['projects', 'archive', 'conformance-cli']);
    const projects = JSON.parse(await coffre(['projects', '--json'])) as { slug: string; archivedAt: string | null }[];
    expect(projects.find(({ slug }) => slug === 'conformance-cli')?.archivedAt !== null, 'the project is not archived', projects);
    const sessions = JSON.parse(await coffre(['sessions', '--json'])) as { kind: string; current: boolean }[];
    expect(sessions.some(({ kind, current }) => kind === 'cli' && current), "sessions --json does not mark this CLI's session", sessions);
    return `${steps.length} commands: ${[...new Set(steps)].join(', ')}; the token only in its 0600 file and piped to login, refused once revoked`;
  } finally {
    ci.remove();
  }
}
