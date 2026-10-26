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
import { appendFileSync, chmodSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { promisify } from 'node:util';
import { init, KINDS, type Kind } from './init.ts';
import { keys } from './keys.ts';
import { hiddenLine, style } from './tty.ts';
import { githubEnvironment, githubMasks, runsCode } from './github-env.ts';
import { bindingFrom, describeBindings, describeEvents, describeKeys, describePlan, keySetFrom, reaches, scopeFrom, serviceMember, TRUST_OPTIONS, TRUST_USAGE } from './trust.ts';
import { exchange, ExchangeFailed, idToken, keyBound, proofOf } from './workload.ts';
import { commandLine, readSession } from './flags.ts';
import { requestLine, stderr, timed, took } from './timings.ts';
import { readSecret } from './secret.ts';
import { generatedLines, generatedPatch, recipeFlag, regeneratedPatch } from './generate.ts';
import { help, lookup, usage, type Command } from './commands.ts';
import { clash, environmentPaths, keyNamed, keyPatterns, listOf } from './environments.ts';
import { listen, type Tunnel } from './tunnels.ts';
import { approve, enroll } from './enroll.ts';
import { freeze, unfreeze } from './freeze.ts';
import * as manage from './manage.ts';
import { serve } from './serve.ts';
import { CheckFailed, memberOf, parse, UsageError } from './manage.ts';
import { cliVersion } from './version.ts';
import { interval, replaceFile, watch } from './watch.ts';
import { KEYS_USAGE, INSTANCE_USAGE, pickCheck, verifyInstance, verifyKeys, VERIFY_USAGE } from './verify/index.ts';
import {
  choose,
  credentialHeaders,
  emptyPins,
  emptyStore,
  instanceOrigin,
  isJsonContentType,
  localFor,
  loginMode,
  parseMode,
  parsePins,
  parseStore,
  REPO_FILE,
  resolveTarget,
  within,
  withPin,
  withoutPins,
  withSession,
  withoutSession,
  type AuthMode,
  type Credential,
  type Local,
  type Pins,
  type Session,
  type Store,
  type Target,
} from './instance.ts';
import {
  ageInDays,
  byFolder,
  CoffreError,
  createClient,
  olderThan,
  planImport,
  apiMember,
  serviceName,
  shownMember,
  unreachable,
  Unreachable,
  type CoffreClient,
} from '@coffre/client';
import { credentialScopeInWords, ROLE_ID } from '@coffre/core/access';
import { formatDotenv, formatShellExports, parseDotenv } from '@coffre/core/dotenv';
import { regenerateWrite, type GeneratedWrite } from '@coffre/core/recipe';

const CREDENTIALS_PATH = join(homedir(), '.coffre', 'credentials.json');
const PINS_PATH = join(homedir(), '.coffre', 'directories.json');

// `coffre export … | head` closes the pipe early; that is the reader being
// done, not an error worth a stack trace.
process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EPIPE') process.exit(0);
  throw error;
});

function readStore(): Store {
  return existsSync(CREDENTIALS_PATH) ? parseStore(readFileSync(CREDENTIALS_PATH, 'utf8')) : emptyStore();
}

function writeStore(store: Store): void {
  writePrivate(CREDENTIALS_PATH, 'credentials', store);
}

/**
 * Read the pins: none only if there is no file. One this CLI cannot read,
 * or reached through a symbolic link, which `writePrivate` refuses too, is
 * an error: a link, dangling or not, would let another file say where
 * credentials go.
 */
function readPins(): Pins {
  try {
    for (const path of [dirname(PINS_PATH), PINS_PATH]) {
      const found = lstatSync(path, { throwIfNoEntry: false });
      if (found === undefined) return emptyPins();
      if (found.isSymbolicLink()) throw new Error('it is reached through a symbolic link');
    }
    return parsePins(readFileSync(PINS_PATH, 'utf8'));
  } catch (error) {
    fail(`cannot read the pinned directories in ${PINS_PATH}: ${(error as Error).message}. Name the instance with --url, or move the file away`);
  }
}

function writePins(pins: Pins): void {
  writePrivate(PINS_PATH, 'pinned directories', pins);
}

/** Write one of the CLI's files, readable by you alone, in a directory only you can enter. */
function writePrivate(path: string, what: string, value: unknown): void {
  const directory = dirname(path);
  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (lstatSync(directory).isSymbolicLink() || (existsSync(path) && lstatSync(path).isSymbolicLink())) {
      throw new Error(`a symbolic link is not a ${what} path`);
    }
    chmodSync(directory, 0o700);
    if ((statSync(directory).mode & 0o777) !== 0o700) throw new Error('directory permissions must be 0700');
    // Creation modes do not tighten an existing file. Replace it privately,
    // so a shared inode or a failed write never receives a new session.
    const temporary = join(directory, `.write-${crypto.randomUUID()}`);
    try {
      writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      chmodSync(temporary, 0o600);
      if ((statSync(temporary).mode & 0o777) !== 0o600) throw new Error('file permissions must be 0600');
      renameSync(temporary, path);
    } finally {
      rmSync(temporary, { force: true });
    }
  } catch (error) {
    fail(`cannot secure ${what} at ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Where the command runs, as pins name it: its real path. A directory gone
 * since is an error, not one without a pin: that would be the default
 * instance's, whatever its pin said.
 */
function here(then: string): string {
  try {
    return realpathSync(process.cwd());
  } catch (error) {
    fail(`cannot tell which directory this is: ${(error as Error).message}. ${then}`);
  }
}

/** Your home, as pins name it. */
function realHome(): string {
  return attempt(() => realpathSync(homedir()));
}

/**
 * The pin or `coffre.json` that applies where the command runs, unless
 * --url names the instance, and so without reading either.
 */
function localHere(): Local | null {
  if (sessionFlags.url !== undefined) return null;
  return attempt(() => localFor(readPins(), here('Name the instance with --url'), realHome(), readRepoFile));
}

/** A `coffre.json`'s text, or null if there is none: one that is a link or no file is refused, not passed over. */
function readRepoFile(path: string): string | null {
  try {
    const entry = lstatSync(path);
    if (!entry.isFile()) throw new Error(`it is ${entry.isSymbolicLink() ? 'a symbolic link' : 'not a file'}, and a ${REPO_FILE} is a file of the repository's own`);
    return readFileSync(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return null;
    throw new Error(`cannot use ${path}: ${(error as Error).message}`);
  }
}

/** Why a command uses the instance it does, as `whoami` and `use` say: `pinned at ~/Code/acme`. */
function because(local: Local): string {
  return local.by === 'pin' ? `pinned at ${shown(local.directory)}` : `named by ${shown(join(local.directory, REPO_FILE))}`;
}

/** A directory as you would type it: `~/Code/acme`. */
function shown(directory: string): string {
  const home = realHome();
  return home !== '/' && within(directory, home) ? `~${directory.slice(home.length)}` : directory;
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
  return attempt(() => resolveTarget(sessionFlags, readStore(), localHere()));
}

/** cloudflared keeps and refreshes the Access token; ask it each time. */
async function cloudflaredToken(origin: string): Promise<string> {
  try {
    const { stdout } = await promisify(execFile)('cloudflared', ['access', 'token', `-app=${origin}`]);
    const token = stdout.trim();
    if (token === '' || token.includes(' ')) throw new Error(stdout);
    return token;
  } catch {
    throw new Error(`could not get a Cloudflare Access token for ${origin}: run \`coffre login ${origin}\``);
  }
}

/**
 * `fetch`, under `--verbose` each request said on stderr with its answer
 * and its time (`timings.ts`): by its path when it is `instance`'s, by its
 * host when it is a platform's or GitHub's. Without `instance`, for the
 * requests only the instance is sent.
 */
function fetching(instance?: string): typeof fetch {
  return sessionFlags.verbose ? timed(fetch, stderr, instance) : fetch;
}

/** A request to the instance. */
function http(input: string | Request, init?: RequestInit): Promise<Response> {
  return fetching()(input, init);
}

/**
 * A CI run's credential, and the ID token it was traded for: asked for once
 * in this process, before its first request, and kept in memory only.
 */
let exchanged: Promise<{ credential: string; idToken: string }> | null = null;

function workloadCredential(origin: string, workload: Extract<Credential, { kind: 'workload' }>): Promise<{ credential: string; idToken: string }> {
  exchanged ??= signIn(origin, workload.service)
    .then(({ issued, idToken: token }) => ({ credential: issued.token, idToken: token }))
    .catch((error: unknown) => fail(error instanceof Error ? error.message : String(error)));
  return exchanged;
}

/**
 * How long a request waits before each time it asks again, while the
 * instance cannot answer it yet (`momentary`): twice, each wait between
 * half and one and a half of these, so that the jobs of one run that
 * failed together do not all ask again together. Then its answer stands.
 */
const UNAVAILABLE_RETRY_MS = [2000, 5000];

function unavailableWait(attempt: number): number | undefined {
  const wait = UNAVAILABLE_RETRY_MS[attempt];
  return wait === undefined ? undefined : Math.round(wait * (0.5 + Math.random()));
}

/**
 * Whether the instance answered 503 for a while it says passes: it could
 * not reach its database or its vault (`unavailable`, no reason), count
 * exchanges (`busy`), or reach the issuer's keys (`issuer_unavailable`),
 * or it is moving to its new app key (`rotating`). Not one that waits on
 * an operator or a deploy (`wrong_kek`, `vault_outdated`, `app_key`,
 * `migrating`), nor the proxy's own answers, nor Cloudflare's page.
 */
function momentary(status: number, body: { error?: unknown; reason?: unknown } | null): boolean {
  if (status !== 503) return false;
  // An instance moving to its new app key, which it says takes a second.
  if (body?.error === 'rotating') return true;
  return body?.error === 'unavailable' && (body.reason === undefined || body.reason === 'busy' || body.reason === 'issuer_unavailable');
}

/**
 * A CI run signed in as `service`: its ID token, the one given or a fresh
 * one from GitHub's runner, traded for a credential. Asked again while the
 * instance cannot answer it yet (`momentary`), each time with a fresh
 * ID token from GitHub: an exchange that committed and lost its answer has
 * spent the one before (docs/design/oidc.md, section 3).
 */
async function signIn(origin: string, service: string, given?: string): Promise<{ issued: { token: string; expiresAt: string }; idToken: string }> {
  for (let attempt = 0; ; attempt++) {
    const token = await idToken(given, process.env, origin, fetching(origin));
    try {
      return { issued: await exchange(origin, service, token, http), idToken: token };
    } catch (error) {
      const wait = unavailableWait(attempt);
      if (wait === undefined || !(error instanceof ExchangeFailed && momentary(error.status, error.body))) throw error;
      if (sessionFlags.verbose) stderr(`the instance could not answer POST /api/auth/oidc: asking again in ${took(wait)}`);
      await new Promise((resolve) => setTimeout(resolve, wait));
    }
  }
}

/** What GitHub must hide from the job's log, beside the values: the run's ID token and credential, if it used them. */
async function workloadSecrets(): Promise<[string, string][]> {
  if (exchanged === null) return [];
  const { credential, idToken: token } = await exchanged;
  return [['', token], ['', credential]];
}

async function headersFor(to: Target): Promise<Record<string, string>> {
  if (to.credential.kind === 'workload') {
    return credentialHeaders(to.mode, to.credential, (await workloadCredential(to.origin, to.credential)).credential);
  }
  const access = to.credential.kind === 'cloudflared' ? await cloudflaredToken(to.origin) : undefined;
  return credentialHeaders(to.mode, to.credential, access);
}

/** What to do next, for a refusal a command expects: its status and message, to a line, or null. */
/** What to suggest after a refusal, by its status and the server's reason for it (`principal_not_registered`), never its words. */
type Hint = (status: number, reason: string | null) => string | null;

/**
 * The API, for one instance. A refusal of a status in `handled` comes back
 * to the command, as a CoffreError, for it to say what to do; any other
 * ends the CLI, said in `send`'s words. `ask` sends each request.
 */
function client(to: Target = target(), hint?: Hint, handled: readonly number[] = [], ask: Ask = once): CoffreClient {
  return createClient({
    url: to.origin,
    headers: () => headersFor(to).catch((error: unknown) => fail(error instanceof Error ? error.message : String(error))),
    transport: (request) => send(request, to, hint, handled, ask),
  });
}

/** How `send` puts a request to the instance: `once`, `retryingPolicyChange` or `reading`. */
type Ask = (request: Request) => Promise<Response>;

/**
 * A request, sent once. Cloudflare Access redirects rejected non-browser
 * clients to its login page. Following that redirect would turn an auth
 * failure into HTML that later explodes in JSON parsing.
 */
function once(request: Request): Promise<Response> {
  return http(request, { redirect: 'manual' });
}

/** How long a read waits before it asks again, once the access policy changed under it. */
const POLICY_RETRY_MS = 300;

/**
 * A read of values (`get`, `run`, `export`), or the handle `run` makes,
 * asked again once, a moment later, when the instance answered 409
 * `policy_changed` (which rolled any write back): the access policy
 * changed while it was answered, and asked again, it is weighed as
 * the policy is now. A second change is answered as any refusal is.
 */
async function retryingPolicyChange(request: Request): Promise<Response> {
  const again = request.clone();
  const response = await once(request);
  if (response.status !== 409) return response;
  const body = (await response.clone().json().catch(() => null)) as { reason?: unknown } | null;
  if (body?.reason !== 'policy_changed') return response;
  if (sessionFlags.verbose) stderr(`the access policy changed while ${requestLine(request.method, new URL(request.url))} was answered: asking again in ${took(POLICY_RETRY_MS)}`);
  await new Promise((resolve) => setTimeout(resolve, POLICY_RETRY_MS));
  return once(again);
}

/**
 * A read of values, `retryingPolicyChange`, asked again too while the
 * instance cannot answer it yet (`momentary`). Each read the vault
 * answered is in the audit log, the one whose answer was lost included.
 */
async function reading(request: Request): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    const again = request.clone();
    const response = await retryingPolicyChange(request);
    const wait = unavailableWait(attempt);
    // The status first: a body is parsed only when it may say the instance cannot answer yet.
    if (wait === undefined || response.status !== 503 || !momentary(response.status, await response.clone().json().catch(() => null))) return response;
    if (sessionFlags.verbose) stderr(`the instance could not answer ${requestLine(request.method, new URL(request.url))}: asking again in ${took(wait)}`);
    await new Promise((resolve) => setTimeout(resolve, wait));
    request = again;
  }
}

/** `client`, for the values `get`, `run` and `export` read: each request is `reading`. */
function reader(handled: readonly number[] = []): CoffreClient {
  return client(target(), undefined, handled, reading);
}

/**
 * The API, for one instance, where every refusal and failure comes back to
 * the command as an error, said in the server's words, and none ends the
 * CLI: for `export --watch`, which outlives a failed round.
 */
function enduringClient(to: Target): CoffreClient {
  return createClient({
    url: to.origin,
    headers: () => headersFor(to),
    transport: (request) => retryingPolicyChange(request).catch((error: unknown) => {
      throw new Error(unreachable(to.origin, error));
    }),
  });
}

/** One request; every way it can fail is explained in terms of what to do next. */
async function send(request: Request, to: Target, hint?: Hint, handled: readonly number[] = [], ask: Ask = once): Promise<Response> {
  let response: Response;
  try {
    response = await ask(request);
  } catch (error) {
    fail(unreachable(to.origin, error));
  }

  const relogin = `run \`coffre login ${to.origin}\``;
  if (response.status >= 300 && response.status < 400) {
    if (to.mode === 'cloudflare') fail(`Cloudflare Access did not accept your token: ${relogin}`);
    fail(`${to.origin} redirected to ${response.headers.get('location') ?? 'elsewhere'}; is that the right address?`);
  }
  if (response.status === 401) fail(refused(to));
  if (handled.includes(response.status)) return response;
  const json = isJsonContentType(response.headers.get('content-type'));
  if (!response.ok) {
    const body = json ? ((await response.json().catch(() => ({}))) as { error?: unknown; message?: unknown; reason?: unknown }) : {};
    const detail = typeof body.message === 'string' && body.message.length > 0 ? body.message : null;
    const next = detail === null ? null : (hint?.(response.status, typeof body.reason === 'string' ? body.reason : null) ?? null);
    if (next !== null) fail(`${detail}: ${next}`);
    if (response.status === 403) fail(`forbidden: ${detail ?? 'you do not have a grant for that environment'}`);
    if (response.status === 404) fail(detail === null ? 'not found' : `not found: ${detail}`);
    const status = `request failed with status ${response.status}`;
    if (detail !== null) fail(`${status}: ${detail}`);
    if (typeof body.error === 'string' && body.error.length > 0) fail(`${status}: ${body.error}`);
    fail(status);
  }
  if (!json) fail('request returned a non-JSON response');
  return response;
}

/**
 * Why the instance turned the credential away, by whose it is. The server
 * says no more than unknown, expired or revoked, on purpose; but a person's
 * saved session that has not reached its end, which the CLI checks first,
 * is one the instance no longer knows: signed out, or the instance reset.
 */
function refused(to: Target): string {
  const relogin = `\`coffre login ${to.origin}\``;
  switch (to.by) {
    case 'service':
      return `${to.origin} refused the credential this run's ID token bought: is its binding still there?`;
    case 'run':
      return `${to.origin} does not know the credential this run's ID token bought: it lasts five minutes. Sign in again, \`coffre login ${to.origin} --service <name>\``;
    case 'token':
      return `${to.origin} does not know this bearer token: it is unknown, expired or revoked`;
    case 'access':
      return `${to.origin} refused the Access service token's sign-in: is its service still a member?`;
    case 'person':
      return to.mode === 'cloudflare'
        ? `${to.origin} refused your Cloudflare Access sign-in: run ${relogin}`
        : `${to.origin} does not know the session saved here: it was signed out, or the instance was reset since. Sign in again: ${relogin}`;
  }
}

/** The instance a command names, as its argument or as --url: one of the two, or neither. */
function oneUrl(given: string | undefined, command: string): string | undefined {
  if (given !== undefined && sessionFlags.url !== undefined) {
    throw new Error(`name the instance once: coffre ${command} <url>, or coffre --url <url> ${command}`);
  }
  return given ?? sessionFlags.url;
}

/** A member as `coffre access` and `whoami` show one: `service:deploy (service account)`, `ada@acme.example (user)`. */
function named(type: string, id: string): string {
  return type === 'service' ? `service:${id} (service account)` : `${id} (user)`;
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

type Me = Awaited<ReturnType<CoffreClient['me']>>;

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
 * Sign in to an instance, make it the default, and pin the directory the
 * login ran in to it. How depends on who vouches for people there, which
 * the CLI finds out by asking (`loginMode`):
 *
 * - coffre's own sign-in: the CLI shows a code, you approve it in a browser
 *   where you are signed in, and the CLI receives a session token of its own.
 *   A session saved here that the instance still knows is kept: the login
 *   only pins.
 * - Cloudflare Access: the CLI hands over to `cloudflared`, which keeps the
 *   Access token from then on.
 */
async function login(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      'no-browser': { type: 'boolean', default: false },
      token: { type: 'boolean', default: false },
      'access-client-id': { type: 'string' },
      service: { type: 'string' },
      'id-token': { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });
  if (positionals.length > 1) fail(`too many arguments: ${positionals.slice(1).join(' ')}`);
  const machine = (['token', 'access-client-id', 'service'] as const).filter((name) => values[name] !== undefined && values[name] !== false);
  if (machine.length > 1) fail(`${machine.map((name) => `--${name}`).join(' and ')} are two ways to sign in: give one`);
  if (values['id-token'] && values.service === undefined) fail('--id-token goes with --service <name>: the ID token signs a CI run in as that service');
  if (machine.length > 0 && values['no-browser']) fail('--no-browser is for a person\'s sign-in, in a browser');
  // Each machine sign-in implies its mode: a bearer token and an ID token are coffre's own, an Access service token Access's.
  if (machine.length > 0 && sessionFlags.authMode !== undefined) fail(`--auth-mode is for a person's sign-in: --${machine[0]} says which`);
  for (const name of ['access-client-id', 'service'] as const) {
    if (values[name]?.trim() === '') fail(`--${name} is empty: an unset variable, perhaps`);
  }

  const mode = attempt(() => parseMode(sessionFlags.authMode));
  // The directory to pin, known before anything is asked of the instance.
  const directory = here('A login pins the directory it runs in: run it from one that exists');

  const given = attempt(() => oneUrl(positionals[0], 'login'));
  const local = given === undefined ? localHere() : null;
  const requested = given ?? local?.origin ?? readStore().current;
  if (!requested) fail('usage: coffre login <url>, for example `coffre login https://coffre.example.com`');
  const origin = attempt(() => instanceOrigin(requested));
  if (local?.by === 'file') {
    // A clone names any URL it likes: you see where you sign in, and a secret you hand over goes only where you name it.
    const file = shown(join(local.directory, REPO_FILE));
    const handed = values.token ? '--token' : values['access-client-id'] !== undefined ? '--access-client-id <id>' : values['id-token'] ? `--service ${values.service} --id-token` : null;
    if (handed !== null) fail(`${file} names ${origin}, and a secret goes only where you name it: \`coffre login ${origin} ${handed}\``);
    process.stderr.write(`Signing in to ${origin}, which ${file} names\n`);
  }
  // A person's session there is not replaced unseen, and left valid on the server: they sign out first.
  const kept = readStore().instances[origin];
  if (machine.length > 0 && kept !== undefined && kept.kind === undefined) {
    fail(`signed in to ${origin} as ${kept.principal?.id ?? 'a person'}: \`coffre logout ${origin}\` first, or sign the run in from a home of its own`);
  }
  if (values.token) await tokenLogin(origin);
  else if (values['access-client-id'] !== undefined) await accessServiceLogin(origin, values['access-client-id'].trim());
  else if (values.service !== undefined) await runLogin(origin, serviceMember(values.service.trim()), values['id-token']);
  else if (!(await keepSession(origin, kept, mode))) {
    const asked = mode ?? (await askMode(origin));
    await (asked === 'cloudflare' ? accessLogin(origin) : deviceLogin(origin, values['no-browser']));
  }
  pinTo(directory, origin);
}

/**
 * A person's session on coffre's own sign-in, saved here, that the instance
 * still knows: made the default again, rather than a new one asked for.
 * Only the instance saying it does not know it, 401, replaces it: any other
 * failure leaves it as it is, and says so.
 */
async function keepSession(origin: string, kept: Session | undefined, mode: AuthMode | undefined): Promise<boolean> {
  if (kept === undefined || kept.kind !== undefined || kept.mode !== 'signin' || !kept.token || mode === 'cloudflare') return false;
  if (kept.expiresAt && Date.parse(kept.expiresAt) <= Date.now()) return false;
  const token = kept.token;
  let me: Me;
  try {
    me = await createClient({
      url: origin,
      headers: () => ({ authorization: `Bearer ${token}` }),
      transport: (request) =>
        http(request, { redirect: 'manual' }).catch((error: unknown) => {
          throw new Unreachable(origin, error);
        }),
    }).me();
    if (typeof me?.principal?.id !== 'string') throw new Error('GET /api/me did not answer as coffre does');
  } catch (error) {
    if (error instanceof CoffreError && error.status === 401) return false;
    const why = (error as Error).message;
    fail(`could not check the session saved for ${origin}, which is kept: ${why}. Retry, or \`coffre logout ${origin}\` first for a new one`);
  }
  writeStore(withSession(readStore(), origin, kept));
  const ends = kept.expiresAt ? `, until ${kept.expiresAt.slice(0, 10)}` : '';
  process.stdout.write(`Signed in to ${origin} as ${me.principal.id} already${ends}: \`coffre logout\` first for a new session\n`);
  printMe(me);
  return true;
}

/**
 * Pin the directory a login ran in to its instance, for it and every
 * directory below: unless it is your home or above it, where the default
 * the login set is enough, or a pin or `coffre.json` there names it already.
 */
function pinTo(directory: string, origin: string): void {
  if (within(realHome(), directory)) return;
  const pins = readPins();
  // A pin here comes before any coffre.json, one that cannot be used included.
  const local = (() => {
    try {
      return localFor(pins, directory, realHome(), readRepoFile);
    } catch {
      return null;
    }
  })();
  if (local?.origin === origin) {
    process.stdout.write(local.by === 'pin' ? `${shown(local.directory)} is pinned to it already\n` : `${shown(join(local.directory, REPO_FILE))} names it already\n`);
    return;
  }
  writePins(withPin(pins, directory, origin));
  process.stdout.write(`Pinned ${shown(directory)} to it: coffre uses ${origin} there and in every directory below\n`);
}

/** A device login: a code shown here, approved in a browser signed in to coffre. */
async function deviceLogin(origin: string, noBrowser: boolean): Promise<void> {
  let started: Response;
  try {
    started = await http(`${origin}/api/auth/device`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_label: `coffre CLI on ${hostname()}` }),
    });
  } catch (error) {
    fail(unreachable(origin, error));
  }
  if (started.status === 429) fail('too many sign-in attempts from this address; wait a minute and retry');
  if (!started.ok || !isJsonContentType(started.headers.get('content-type'))) {
    fail(`${origin} did not start a sign-in (status ${started.status})`);
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
  if (!noBrowser && process.stderr.isTTY) openBrowser(device.verification_uri_complete);
  process.stderr.write('Waiting for you to approve it…\n');

  const session = await pollDevice(origin, device.device_code, device.interval, device.expires_in);
  const me = await client({
    origin,
    mode: 'signin',
    by: 'person',
    credential: { kind: 'token', token: session.access_token },
  }).me();

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

/** Ask the instance how it signs people in. */
async function askMode(origin: string): Promise<'signin' | 'cloudflare'> {
  let response: Response;
  try {
    response = await http(`${origin}/api/auth`, { redirect: 'manual', headers: { accept: 'application/json' } });
  } catch (error) {
    fail(unreachable(origin, error));
  }
  const body = isJsonContentType(response.headers.get('content-type'))
    ? await response.json().catch(() => undefined)
    : undefined;
  return attempt(() => loginMode(origin, response.status, body));
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
      response = await http(`${origin}/api/auth/device/token`, {
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

/**
 * A CI run's sign-in, saved as the instance's session for the commands
 * after it: whoever `to` is, as the instance says, kept as `session`. It
 * replaces another run's session there, never a person's (`login`).
 */
async function saveRun(to: Target, session: Omit<Session, 'principal' | 'obtainedAt'>): Promise<void> {
  // Who it is, asked again as a read is: a sign-in that went through is not lost to a moment's 503 after it.
  const me = await client(to, undefined, [], reading).me();
  writeStore(withSession(readStore(), to.origin, { ...session, principal: me.principal, obtainedAt: new Date().toISOString() }));
  process.stdout.write(`Signed in to ${to.origin} as ${me.principal.id}\n`);
  printMe(me);
}

/** `coffre login <url> --token`: a bearer token, asked for, and kept as the session. */
async function tokenLogin(origin: string): Promise<void> {
  const token = await readSecret({ label: 'Bearer token', hint: 'coffre_svc_… or coffre_pat_…, from `coffre tokens issue` or the service\'s page. Hidden as you type.' }).catch((error: unknown) =>
    fail((error as Error).message),
  );
  await saveRun({ origin, mode: 'signin', by: 'token', credential: { kind: 'token', token } }, { mode: 'signin', kind: 'token', token, expiresAt: null });
}

/** `coffre login <url> --access-client-id <id>`: an Access service token, its secret asked for. */
async function accessServiceLogin(origin: string, clientId: string): Promise<void> {
  const clientSecret = await readSecret({ label: 'Access client secret', hint: `The secret of the Access service token ${clientId}. Hidden as you type.` }).catch((error: unknown) =>
    fail((error as Error).message),
  );
  await saveRun(
    { origin, mode: 'cloudflare', by: 'access', credential: { kind: 'access-service-token', clientId, clientSecret } },
    { mode: 'cloudflare', kind: 'access', clientId, clientSecret },
  );
}

/**
 * `coffre login <url> --service <name>`: a CI run's ID token, traded for a
 * credential of the service that lasts five minutes, kept as the session.
 * GitHub's runner gives the ID token; elsewhere, `--id-token` asks for it.
 */
async function runLogin(origin: string, service: string, ask: boolean): Promise<void> {
  const given = ask
    ? await readSecret({ label: 'ID token', hint: `The run's ID token, for the audience ${origin}. Hidden as you type.` }).catch((error: unknown) => fail((error as Error).message))
    : undefined;
  const { issued } = await signIn(origin, service, given).catch((error: unknown) => fail(error instanceof Error ? error.message : String(error)));
  await saveRun(
    { origin, mode: 'signin', by: 'run', credential: { kind: 'token', token: issued.token } },
    { mode: 'signin', kind: 'run', token: issued.token, expiresAt: issued.expiresAt },
  );
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
        '  In CI, sign in with an Access service token instead: coffre login <url> --access-client-id <id>, its secret pasted or piped in.',
    );
  }
  if (code !== 0) fail('cloudflared could not sign you in');

  const to: Target = { origin, mode: 'cloudflare', by: 'person', credential: { kind: 'cloudflared' } };
  const me = await client(to).me();
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

/**
 * End a person's session on the server, then forget it here. A CI run's
 * is only forgotten: its bearer token or Access service token is the
 * service's, for other runs too, and its credential ends by itself.
 */
async function logout(args: string[]): Promise<void> {
  parse(args, {}, ['<url>'], 1);
  const store = readStore();
  const requested = attempt(() => oneUrl(args[0], 'logout')) ?? localHere()?.origin ?? store.current;
  if (!requested) fail('not signed in anywhere');
  const origin = attempt(() => instanceOrigin(requested));
  const session = store.instances[origin];
  const { pins, unpinned } = withoutPins(readPins(), origin);
  const unpin = () => {
    if (unpinned.length === 0) return;
    writePins(pins);
    process.stdout.write(`  Unpinned ${unpinned.map(shown).join(', ')}\n`);
  };
  if (session === undefined && unpinned.length > 0) {
    process.stdout.write(`Not signed in to ${origin}\n`);
    return unpin();
  }
  if (session === undefined) fail(`not signed in to ${origin}`);

  if (session.kind === undefined && session.mode === 'signin' && session.token) {
    // Revoking is the point; if the server is unreachable, say so rather than
    // pretend the token is dead.
    let response: Response;
    try {
      response = await http(`${origin}/api/auth/logout`, {
        method: 'POST',
        redirect: 'manual',
        headers: { authorization: `Bearer ${session.token}`, 'content-type': 'application/json' },
      });
    } catch (error) {
      fail(`${unreachable(`${origin} to end the session`, error)}; nothing was changed`);
    }
    // 401: the session had already ended, which is what we wanted anyway.
    if (!response.ok && response.status !== 401) {
      fail(`${origin} refused to end the session (status ${response.status}); nothing was changed`);
    }
  }

  writeStore(withoutSession(store, origin));
  process.stdout.write(`Signed out of ${origin}\n`);
  unpin();
  if (session.kind === 'token' || session.kind === 'access') {
    process.stdout.write(`  The ${session.kind === 'token' ? 'bearer token' : 'Access service token'} is forgotten here, and works elsewhere until it is revoked.\n`);
  } else if (session.mode === 'cloudflare' && session.kind === undefined) {
    process.stdout.write('  cloudflared still holds its Access token until it expires.\n');
  }
}

async function whoami(args: string[]): Promise<void> {
  const { values } = parse(args, { json: { type: 'boolean', default: false } }, []);
  const to = target();
  const me = await client(to).me();
  if (values.json) {
    process.stdout.write(`${JSON.stringify({ origin: to.origin, ...me }, null, 2)}\n`);
    return;
  }
  const store = readStore();
  const session = store.instances[to.origin];
  const choice = attempt(() => choose(sessionFlags, store, localHere()));
  const why = choice.by === 'default' ? ' (the default)' : choice.by === 'url' ? '' : ` (${because(choice)})`;
  const via = {
    person: { signin: 'coffre sign-in', cloudflare: 'Cloudflare Access' }[to.mode],
    token: 'a bearer token, from coffre login --token',
    access: 'an Access service token, from coffre login --access-client-id',
    run: "the run's ID token, from coffre login --service",
    service: "the run's ID token, as --service",
  }[to.by];
  process.stdout.write(`${named(me.principal.type, me.principal.id)} on ${to.origin}${why}, via ${via}\n`);
  // An instance before 0.7 says nothing of one.
  if (me.personalToken) {
    const { label, expiresAt, scope } = me.personalToken;
    process.stdout.write(`  personal token "${label}", ends ${expiresAt.slice(0, 16).replace('T', ' ')} UTC, reaching ${credentialScopeInWords(scope)}\n`);
  }
  if (to.by === 'person' && session?.expiresAt) {
    const days = Math.round((Date.parse(session.expiresAt) - Date.now()) / 86_400_000);
    process.stdout.write(`  session ends ${session.expiresAt.slice(0, 10)} (in ${days} day${days === 1 ? '' : 's'})\n`);
  }
  if (me.registered) {
    const mcp = me.features.mcp === null ? 'off' : `on, at ${me.features.mcp}`;
    process.stdout.write(`  MCP clients: ${mcp}\n  CI sign-in by ID token: ${me.features.workloads ? 'on' : 'off'}\n`);
  }
  printMe(me);
}

/**
 * Switch the default instance, or list them: the one used here starred,
 * each with the directories pinned to it, and the `coffre.json` here.
 */
function use(args: string[]): void {
  parse(args, {}, ['<url>'], 1);
  const store = readStore();
  const local = localHere();
  const file = local?.by === 'file' ? local : null;
  if (args[0] === undefined) {
    const pinned = Object.entries(readPins().directories);
    const origins = [...new Set([...Object.keys(store.instances), ...pinned.map(([, origin]) => origin), ...(file === null ? [] : [file.origin])])];
    if (origins.length === 0) fail('not signed in anywhere yet: run `coffre login <url>`');
    const used = local?.origin ?? store.current;
    for (const origin of origins) {
      const session = store.instances[origin];
      const why = [
        ...(origin === store.current ? ['the default'] : []),
        ...pinned.filter(([, to]) => to === origin).map(([directory]) => `pinned at ${shown(directory)}`),
        ...(file?.origin === origin ? [because(file)] : []),
      ];
      const who = session === undefined ? 'not signed in' : (session.principal?.id ?? '');
      process.stdout.write(`${`${origin === used ? '*' : ' '} ${origin.padEnd(36)} ${who.padEnd(24)} ${why.join(', ')}`.trimEnd()}\n`);
    }
    return;
  }
  const origin = attempt(() => instanceOrigin(args[0]));
  if (!(origin in store.instances)) fail(`not signed in to ${origin}: run \`coffre login ${origin}\``);
  writeStore({ ...store, current: origin });
  process.stdout.write(`Now using ${origin} by default\n`);
  if (local !== null && local.origin !== origin) {
    const named = local.by === 'pin' ? `${shown(local.directory)} is pinned to ${local.origin}` : `${shown(join(local.directory, REPO_FILE))} names ${local.origin}`;
    process.stdout.write(`  but not here: ${named}, and \`coffre login ${origin}\` pins this directory to it\n`);
  }
}

async function get(args: string[]): Promise<void> {
  const [target] = parse(args, {}, ['<project>/<environment>/<KEY>']).positionals as [string];

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre get <project>/<environment>/<KEY>');

  const { values } = await reader().secrets.reveal(`${project}/${environment}/${key}`);

  // The value's own bytes when stdout is no terminal, so it composes: coffre get x/y/Z | pbcopy
  // A terminal gets its newline, to leave the prompt on a line of its own.
  process.stdout.write(process.stdout.isTTY ? `${values[key]}\n` : values[key]!);
}

async function list(args: string[]): Promise<void> {
  const { values, positionals } = parse(args, {
    json: { type: 'boolean', default: false },
    'older-than': { type: 'string' },
    stale: { type: 'boolean', default: false },
  }, ['<project>/<environment>']);
  if (values.stale && values['older-than'] !== undefined) throw new UsageError('--stale or --older-than, not both');
  const olderThanDays = values['older-than'] === undefined ? null : days(values['older-than']);
  const { project, environment } = parsePath(positionals[0]!);
  const result = await client().secrets.list(`${project}/${environment}`);
  // `dev@me` while you have no personal dev: dev's own keys, said on stderr so the list stays as it is.
  if (result.personal?.fallback === true) {
    process.stderr.write(`coffre: you have no personal config of ${project}/${result.personal.of}: these are its own keys; a write to ${project}/${environment} makes one\n`);
  }
  // An instance before 0.6 does not say: it flags nothing, and has nothing for --stale.
  const told: number | null | undefined = result.rotateAfterDays;
  if (values.stale && told === undefined) {
    fail('this instance is older than rotation ages (coffre 0.6), and has no rotateAfterDays: upgrade it, or name an age, --older-than 90d');
  }
  const rotateAfterDays = told ?? null;
  if (values.stale && rotateAfterDays === null) {
    fail('this instance flags no value for rotation (its rotateAfterDays is null): name an age, --older-than 90d');
  }
  // Only the values older than asked: never an archived key, nor one without a value.
  const over = values.stale ? rotateAfterDays : olderThanDays;
  const now = Date.now();
  const keys = over === null ? result.keys : result.keys.filter((entry) => olderThan(entry, over, now));
  if (values.json) {
    process.stdout.write(`${JSON.stringify(keys, null, 2)}\n`);
    return;
  }

  // Listing keys is not a read of any value, and is not logged as one.
  for (const [folder, inFolder] of byFolder(keys)) {
    const indent = folder === null ? '' : '  ';
    if (folder !== null) process.stdout.write(`${folder}/\n`);
    for (const entry of inFolder) {
      // How long ago its value was written, a reference's its source's; flagged past the instance's rotateAfterDays.
      const age = ageInDays(entry, now);
      const written = age === null ? '-' : age === 0 ? 'today' : `${age} day${age === 1 ? '' : 's'} ago`;
      // A generated value says how it was made, and that one command rotates it.
      const recipe = entry.generated == null ? null : entry.generated.recipe;
      const rotate = recipe === null ? 'rotate it' : `\`coffre regenerate ${project}/${environment}/${entry.key}\``;
      const due = rotateAfterDays !== null && olderThan(entry, rotateAfterDays, now) ? `  (unchanged over ${rotateAfterDays} days: ${rotate})` : '';
      const made = recipe === null ? '' : `  (generated, ${recipe})`;
      const archived = entry.archived ? '  (archived)' : '';
      // A plain value is no secret, and lists as it is; a sensitive one nobody sees says so, a reference reading one too. An instance before 0.9 says nothing.
      const plain = entry.value != null ? `  plain: ${entry.value}` : entry.sensitivity === 'sensitive' ? '  sensitive' : '';
      // In a fork, where a key stands to its parent's: an instance before 0.7 says nothing.
      const parent = entry.parent ?? null;
      const standing = parent === null
        ? ''
        : parent.state === 'inherited'
          ? `  (from ${parent.from}${parent.reset ? '; its own reset, and kept' : ''})`
          : parent.state === 'removed'
            ? `  (removed here: ${parent.held === false ? `${parent.from} dropped it too` : `not inherited from ${parent.from}`})`
            : `  (overrides ${parent.from}${parent.changed ? `; ${parent.from} changed since` : ''})`;
      const { reference } = entry;
      if (reference !== null) {
        // A reference reads its source's current version; one that cannot read says why.
        const state = reference.state === 'live' ? `v${reference.version}` : reference.state.replace('_', ' ');
        process.stdout.write(`${indent}${entry.key}\t→ ${reference.source}\t${state}\t${shownMember(reference.createdBy).replace(/^user:/, '')}\t${written}${plain}${due}${archived}${standing}\n`);
        continue;
      }
      process.stdout.write(`${indent}${entry.key}\tv${entry.version ?? '-'}\t${entry.updatedBy ?? '-'}\t${written}${made}${plain}${due}${archived}${standing}\n`);
    }
  }
}

/** `90d`: an age in whole days, as `--older-than` takes it. */
function days(text: string): number {
  const match = /^(\d+)d$/.exec(text);
  if (match === null) throw new UsageError(`--older-than takes days, as 90d, not "${text}"`);
  return Number(match[1]);
}

async function set(args: string[]): Promise<void> {
  const { values, positionals } = parse(args, {
    ref: { type: 'string' },
    generate: { type: 'string' },
    'public-key': { type: 'string' },
    plain: { type: 'boolean' },
    secret: { type: 'boolean' },
    sensitive: { type: 'boolean' },
  }, ['<project>/<environment>/<KEY>', '[value]'], 1);
  const [target, given] = positionals as [string, string | undefined];
  // A secret on the command line is in the shell's history and `ps`: it is asked for. A plain value is no secret.
  if (given !== undefined && values.plain !== true) fail('coffre set asks for the value: paste it, or pipe it in, never as an argument; a value that is no secret may be one, with --plain');

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre set <project>/<environment>/<KEY>');
  // Who sees the value: said, or a secret, and sensitive where the key is now (`Sensitivity`, docs/design/credential-proxy.md).
  const levels = (['plain', 'secret', 'sensitive'] as const).filter((level) => values[level] === true);
  if (levels.length > 1) fail(`--plain, --secret or --sensitive: one says who sees the value, not ${levels.map((level) => `--${level}`).join(' and ')}`);
  const sensitivity = levels[0];
  if (values.ref !== undefined && values.generate !== undefined) fail('--ref or --generate: a key reads another secret, or holds a value made here, not both');
  if (values.ref !== undefined && sensitivity !== undefined) fail(`--${sensitivity} says who sees a value: a reference has its source's`);
  if (values.plain === true && values.generate !== undefined) fail('--plain writes a value given here, as it is: not with --generate');
  if (values['public-key'] !== undefined && values.generate === undefined) fail('--public-key goes with --generate and a key pair\'s recipe, as ecdsa:p-256');
  // Made here, sent with its recipe, and never shown: nobody sees the value, and Regenerate makes the next one alike.
  if (values.generate !== undefined) {
    const made = await generatedPatch(key, recipeFlag(values.generate), values['public-key']);
    const patch = sensitivity === undefined ? made : Object.fromEntries(Object.entries(made).map(([name, write]) => [name, { ...write, sensitivity: sensitivity as 'secret' | 'sensitive' }]));
    const result = await client().secrets.set(`${project}/${environment}`, patch);
    process.stdout.write(`${generatedLines(patch, versionsOf(result.keys), 'generated').join('\n')}\n`);
    return;
  }
  // A reference names a secret, which is no secret: it may be a flag. A value is never one, so the two never mix.
  if (values.ref !== undefined) {
    const source = parsePath(values.ref);
    if (!source.key) fail(`--ref names a secret, <project>/<environment>/<KEY>, not "${values.ref}"`);
    const made = await client().secrets.set(`${project}/${environment}`, { [key]: { ref: values.ref } });
    const outcome = made.keys[key];
    process.stdout.write(`${key} is a reference to ${'reference' in outcome ? outcome.reference : values.ref}: whoever reads ${project}/${environment} reads it\n`);
    return;
  }

  // Plain, no secret: whoever lists the environment sees it, and its apps get it as it is, placeholders or not.
  // Said as 0.9 says it, which an instance of 0.9 takes too.
  const value = given ?? await readValue(key);
  const written = sensitivity === undefined ? value : sensitivity === 'plain' ? { value, plain: true as const } : { value, sensitivity };
  const result = await client().secrets.set(`${project}/${environment}`, { [key]: written });
  const outcome = result.keys[key];
  // Who sees it, as the write answers (an instance before 0.10 says nothing): said, or the key's own, kept, in
  // <env>@me the one it overrides.
  const level = 'sensitivity' in outcome ? outcome.sensitivity : sensitivity;
  const personal = environment.endsWith('@me');
  const kept = sensitivity === undefined ? `, as ${personal ? 'the key it overrides' : 'it was'}; --secret makes it a secret ${personal ? 'your app is given' : 'its readers see'}` : '';
  const said = level === 'plain' ? `, plain: shown to ${personal ? 'you alone' : `whoever lists ${project}/${environment}`}`
    : level === 'sensitive' ? `, sensitive: shown to nobody, Owners included; apps use it through the credential proxy, and services read it${kept}` : '';
  process.stdout.write(`${key} written as version ${'version' in outcome ? outcome.version : '?'}${said}\n`);
}

/**
 * Make keys stricter, their values kept (`Sensitivity`): one key, or every
 * key of an environment that is looser now. A key is made looser only by
 * writing its value again (`coffre set … --plain`), never by flipping one
 * nobody could read, so only stricter levels are asked for here; but an
 * Owner of the project makes a sensitive value secret in place
 * (`loosenable`), `mark market/prod secret` then every sensitive one of
 * its own too. A key of the environment's that is a reference, or that a
 * fork inherits, reads the level of the value where it is held: left as it
 * is, and named, with where to mark it, when it is not at the level asked.
 */
async function mark(args: string[]): Promise<void> {
  const { positionals } = parse(args, {}, ['<project>/<environment>[/<KEY>]', '<plain|secret|sensitive>']);
  const [target, level] = positionals as [string, string];
  if (level !== 'plain' && level !== 'secret' && level !== 'sensitive') fail(`coffre mark makes keys plain, secret or sensitive, not "${level}"`);
  const { project, environment, key } = parsePath(target);
  const path = `${project}/${environment}`;
  const coffre = client();
  const { keys: listed, loosenable } = await coffre.secrets.list(path);
  const order = ['plain', 'secret', 'sensitive'];
  // Looser than asked, or, for an Owner of the project asking for secret, sensitive (an older instance lists no `loosenable`).
  const marks = (sensitivity: string) => order.indexOf(sensitivity) < order.indexOf(level) || (loosenable === true && level === 'secret' && sensitivity === 'sensitive');
  // Each key's own value, to mark: an instance before 0.10 lists no sensitivity, and marks nothing.
  const own = listed.filter((entry) => !entry.archived && entry.reference === null && entry.version !== null && entry.parent?.state !== 'inherited' && entry.parent?.state !== 'removed');
  if (listed.some((entry) => entry.version !== null && entry.sensitivity === undefined)) fail(`${path}'s instance is older than sensitivity (coffre 0.10): upgrade it first`);
  const marking = key === undefined
    ? own.filter((entry) => marks(entry.sensitivity ?? 'secret')).map((entry) => entry.key)
    : [key];
  // What the environment reads from elsewhere, to mark: its level is where the value is held, so it is marked there.
  // A reference that reads nothing, and a key a fork removes, have no level to mark.
  const left = key !== undefined ? [] : listed.flatMap((entry) => {
    if (entry.archived || !marks(entry.sensitivity ?? 'secret')) return [];
    if (entry.reference !== null) return entry.reference.state === 'live' ? [`${entry.key}, a reference to ${entry.reference.source}: mark it there`] : [];
    if (entry.parent?.state !== 'inherited') return [];
    return [`${entry.key}, inherited from ${project}/${entry.parent.from}: mark it there, or write ${environment}'s own`];
  });
  if (marking.length === 0) process.stdout.write(`nothing to mark in ${path}: every value of its own is ${level}${loosenable === true && level === 'secret' ? '' : ' or stricter'}\n`);
  else {
    const before = new Map(listed.map((entry) => [entry.key, entry.sensitivity]));
    const result = await coffre.secrets.set(path, Object.fromEntries(marking.map((name) => [name, { sensitivity: level }])));
    for (const name of marking) {
      const outcome = result.keys[name];
      const was = before.get(name);
      const version = outcome !== undefined && 'version' in outcome ? outcome.version : '?';
      process.stdout.write(was === level ? `${name}: already ${level}\n` : `${name}: ${was ?? 'secret'} → ${level}, as version ${version}, its value kept\n`);
    }
  }
  if (left.length > 0) process.stderr.write(`coffre: left as they are: ${left.join('; ')}\n`);
}

/**
 * Regenerate a key by the recipe its current value was made by: a new value
 * made here and written as a new version, never shown, and for a key pair's
 * either half, both halves at once. Listing the environment reads no value.
 */
async function regenerate(args: string[]): Promise<void> {
  const [target] = parse(args, {}, ['<project>/<environment>/<KEY>']).positionals as [string];
  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre regenerate <project>/<environment>/<KEY>');
  const path = `${project}/${environment}`;
  const coffre = client();
  const listed = (await coffre.secrets.list(path)).keys;
  const patch = await regeneratedPatch(path, key, listed).catch((error: unknown) => fail((error as Error).message));
  const result = await coffre.secrets.set(path, patch);
  process.stdout.write(`${generatedLines(patch, versionsOf(result.keys), 'regenerated').join('\n')}\n`);
}

/** The version each key of a write got. */
function versionsOf(keys: Record<string, { version: number } | { archived: true } | { reference: string }>): Record<string, number | null> {
  return Object.fromEntries(Object.entries(keys).map(([key, outcome]) => [key, 'version' in outcome ? outcome.version : null]));
}

/**
 * A secret's value, as it is: typed at a hidden prompt on a terminal, or
 * stdin, a value of several lines included, less exactly one final line
 * break. Never empty: an unset variable piped in would blank the secret.
 */
async function readValue(key: string): Promise<string> {
  const value = process.stdin.isTTY
    ? await hiddenLine(process.stdin, process.stderr, style(process.stderr), `${key}:`, 'Hidden as you type; for a value of several lines, pipe it in.', true)
    : readFileSync(0, 'utf8').replace(/\r?\n$/, '');
  if (value === '') fail(process.stdin.isTTY ? 'no value given' : 'no value: none came on stdin, and there is no terminal to ask on');
  return value;
}

/**
 * The keys each environment named gives a read of them, by path: listed,
 * which opens no value, those `patterns` names (`export --keys`), or all of
 * them. One the caller may not list, a reference among them that cannot be
 * read, a pattern that names none of them, or a key two of them define
 * stops here, before anything is read, thrown for the command to end on.
 */
async function listKeys(paths: readonly string[], list: CoffreClient, patterns: readonly string[] | null): Promise<Map<string, string[]>> {
  const keys = new Map<string, string[]>();
  for (const path of paths) {
    const listed = await list.secrets.list(path).catch((error: unknown) => {
      throw new Error(`${path}: ${error instanceof CoffreError ? error.message : String(error)}. Nothing was read`);
    });
    const live = listed.keys.filter(({ key, archived }) => !archived && (patterns === null || patterns.some((pattern) => keyNamed(pattern, key))));
    // A parent's key, listed by name only to whoever cannot list that parent: held here, and never readable by them.
    const hidden = live.filter(({ version, reference, parent }) => version === null && reference === null && parent?.state === 'inherited');
    if (hidden.length > 0) {
      const which = [...new Set(hidden.map(({ parent }) => parent!.from))].map((from) => `${hidden.filter(({ parent }) => parent!.from === from).map(({ key }) => key).join(', ')} from ${path.split('/')[0]}/${from}`);
      throw new Error(`${path} inherits ${which.join('; ')}, which you cannot read. Nothing was read`);
    }
    // A key without a value of its own reads through its reference, which reveal refuses for the whole environment when it cannot.
    const stuck = live.find(({ version, reference }) => version === null && reference !== null && reference.state !== 'live');
    if (stuck !== undefined) {
      throw new Error(`${path}/${stuck.key} is a reference that cannot be read (${stuck.reference!.state.replaceAll('_', ' ')}): \`coffre references ${path}\` says more. Nothing was read`);
    }
    keys.set(path, live.filter(({ version, reference }) => version !== null || reference !== null).map(({ key }) => key));
  }
  // A name none of them holds is a typo, or a key not written yet: either way, not one to export without.
  const unmatched = (patterns ?? []).filter((pattern) => ![...keys.values()].some((held) => held.some((key) => keyNamed(pattern, key))));
  if (unmatched.length > 0) throw new Error(`${listOf(paths)} hold${paths.length === 1 ? 's' : ''} no key that --keys names as ${listOf(unmatched)}. Nothing was read`);
  const shared = clash([...keys]);
  if (shared !== null) throw new Error(`${shared}: a key comes from one environment only. Nothing was read`);
  return keys;
}

/**
 * Every value in the environments named, as one environment: all are read,
 * or none is. One is read as it always was. Of several, each is listed
 * first (`listKeys`), unless `only` says already which keys of each to read,
 * those `export --keys` names, and an environment it names none of is not
 * read at all. Then each is read, one audited read apiece, and what came
 * back is checked again, for an environment changed in between. What stops
 * it is thrown, for the command to end on or, watching, to outlive.
 */
async function readEnvironments(
  paths: readonly string[],
  api: { read: CoffreClient; list: CoffreClient },
  only: Map<string, string[]> | null = null,
): Promise<{ entries: [string, string][]; version: string; sensitive: string[]; useOnly: string[] }> {
  if (only === null && paths.length > 1) await listKeys(paths, api.list, null);
  // The keys named that a workload's read left out, as it only uses them: said, as a person's sensitive ones are.
  const useOnly: string[] = [];
  const read: [string, { values: Record<string, string>; version: string | null; sensitive?: string[] }][] = [];
  for (const path of paths) {
    const keys = only?.get(path);
    if (keys === undefined) {
      read.push([path, await api.read.secrets.reveal(path)]);
      continue;
    }
    if (keys.length === 0) continue;
    const answer = await api.read.secrets.reveal(path, keys);
    const wanted = new Set(keys);
    // An instance before 0.12 reads the whole environment, whatever it is asked: only what was named leaves this run.
    if (Object.keys(answer.values).some((key) => !wanted.has(key))) {
      process.stderr.write(`coffre: ${path} was read whole, as an instance before 0.12 reads it: only the keys --keys names are exported, and the audit log has every one\n`);
    }
    const values = Object.fromEntries(Object.entries(answer.values).filter(([key]) => wanted.has(key)));
    const gone = keys.filter((key) => !Object.hasOwn(values, key) && !(answer.sensitive ?? []).includes(key) && !(answer.useOnly ?? []).includes(key));
    if (gone.length > 0) throw new Error(`${path} no longer holds ${listOf(gone)}, as read just now. No value was used, and the read is in the audit log`);
    useOnly.push(...keys.filter((key) => (answer.useOnly ?? []).includes(key)));
    read.push([path, { ...answer, values }]);
  }
  const shared = clash(read.map(([path, { values }]) => [path, Object.keys(values)]));
  if (shared !== null) throw new Error(`${shared}, as read just now. No value was used, and the reads are in the audit log`);
  // The environments' versions, of what was read: as `coffre version` answers them, together.
  // A person's read leaves its sensitive values out, by name; an instance before 0.10 says nothing.
  const sensitive = read.flatMap(([, answer]) => answer.sensitive ?? []).sort();
  return { entries: read.flatMap(([, { values }]) => Object.entries(values)), version: read.map(([, answer]) => answer.version).join(' '), sensitive, useOnly: useOnly.sort() };
}

/** What a read left out, on stderr: a person's sensitive keys, which nobody is handed, and the keys --keys named that a workload only uses. */
function sayLeftOut(sensitive: readonly string[], useOnly: readonly string[] = []): void {
  if (sensitive.length > 0) process.stderr.write(`coffre: left out, sensitive, which nobody is handed: ${sensitive.join(', ')} (the credential proxy uses them, and a service account reads them)\n`);
  if (useOnly.length > 0) process.stderr.write(`coffre: left out, which this workload only uses through coffre: ${useOnly.join(', ')} (its binding's reads do not list them)\n`);
}

/** `readEnvironments` for a command that ends on what stops it, said in `send`'s words for a failed request. */
function readOrEnd(paths: readonly string[], only: Map<string, string[]> | null = null): Promise<[string, string][]> {
  const api = { read: reader(), list: reader([403, 404]) };
  return readEnvironments(paths, api, only).then(
    (read) => {
      sayLeftOut(read.sensitive, read.useOnly);
      return read.entries;
    },
    (error: unknown) => fail(error instanceof Error ? error.message : String(error)),
  );
}

/**
 * What a person's app gets through the credential proxy (`placeholders`): its
 * environment, what the proxy left out, and what this run made of the
 * person's own, by personal config.
 */
type Placeholders = { env: Record<string, string>; left: string[]; credentials: string[]; given: string[]; expiresAt: string; tunnels: Tunnel[]; handle: string; made: [string, string[]][]; revoke: () => Promise<void> };

/** A plan, `GET /use/<project>/<env>`: what the app gets, and what this run is to make of the person's own. */
type Plan = { env: Record<string, string>; credentials: Record<string, string>; tunnels?: Record<string, Tunnel>; left: string[]; generate?: Record<string, { recipe: string; replaces: string; sensitivity?: 'secret' }> };

/**
 * Placeholders for the environments named, where the instance has the
 * credential proxy (docs/design/credential-proxy.md) and the session is a
 * person's: one handle for the run, which the proxy takes in place of each
 * credential's keys, and the values the person may read, as they are. Null where the instance has no
 * proxy, or for a service account, which reads values (R13).
 */
async function placeholders(paths: readonly string[], to: Target = target()): Promise<Placeholders | null> {
  if (!(await proxied(to))) return null;
  // A plan reads values too, and is asked again as `run`'s reads are.
  const at = (path: string, headers: Record<string, string>) =>
    retryingPolicyChange(new Request(`${to.origin}/use${path}`, { headers })).catch((error: unknown) => fail(unreachable(to.origin, error)));
  // A label is 120 characters at most: the paths go in whole, the label names as many as fit.
  const label = `coffre run on ${hostname()}: ${paths.join(' ')}`;
  // Asked again too: a handle weighed from a policy another change overtook is made from none, and refused to be asked again.
  const handle = await client(to, undefined, [], retryingPolicyChange).handles.create({ label: label.length <= 120 ? label : `${label.slice(0, 119)}…`, paths: [...paths] });
  const planOf = async (path: string): Promise<Plan> => {
    const response = await at(`/${path}`, { authorization: `Bearer ${handle.token}` });
    const body = (await response.json().catch(() => ({}))) as { message?: string };
    if (!response.ok) fail(`${path}: ${body.message ?? `the credential proxy answered ${response.status}`}`);
    return body as Plan;
  };
  const plans: [string, Plan][] = [];
  const made: [string, string[]][] = [];
  for (const path of paths) {
    let plan = await planOf(path);
    // Where the deployment generates (its `generate`): each key a recipe made that the app would go without gets
    // a value of the person's own, made here by that recipe, in their personal config, which the plan reads from
    // then on. Each write replaces the version the plan read, so of two runs at once, one writes and the other,
    // refused, reads the plan again and finds it.
    for (let attempt = 1; Object.keys(plan.generate ?? {}).length > 0; attempt++) {
      if (attempt > 3) fail(`${path}: its keys kept changing while coffre made your own; run again`);
      const mine = `${path.replace(/@me$/, '')}@me`;
      const writes = await Promise.all(Object.entries(plan.generate!).map(async ([key, { recipe, replaces, sensitivity }]) => {
        const write = await regenerateWrite(key, { recipe }, () => replaces);
        // At the level the plan says, a secret the app is given: an instance before 0.10 says none.
        if (sensitivity !== undefined) for (const entry of Object.values(write)) entry.sensitivity = sensitivity;
        return write;
      }));
      const patch = Object.assign(Object.create(null) as GeneratedWrite, ...writes);
      const wrote = await client(to, undefined, [409]).secrets.set(mine, { ...patch }).then(() => true, (error: unknown) => {
        // Another run wrote first: its value is the one to read. Any other refusal (`too_deep`) is said as it is.
        if (error instanceof CoffreError && error.status === 409 && error.reason === 'stale') return false;
        if (error instanceof CoffreError) fail(`${mine}: ${error.message}`);
        throw error;
      });
      if (wrote) made.push([mine, Object.keys(patch).sort()]);
      plan = await planOf(path);
    }
    plans.push([path, plan]);
  }
  const tunnelsOf = (plan: (typeof plans)[number][1]) => Object.values(plan.tunnels ?? {});
  const shared = clash(plans.map(([path, plan]) => [path, [...Object.keys(plan.env), ...tunnelsOf(plan).map((tunnel) => tunnel.key), ...plan.left]]));
  if (shared !== null) fail(`${shared}: a key comes from one environment only`);
  // Merged as entries: a variable may be named __proto__, which assigning into an object would drop.
  const credentials = Object.fromEntries(plans.flatMap(([, plan]) => Object.entries(plan.credentials)));
  const env: Record<string, string> = Object.fromEntries(plans.flatMap(([, plan]) => Object.entries(plan.env)));
  return {
    // What `credential(name)` (`@coffre/client/credential`) reads: each credential's URL on the proxy, and the handle.
    env: { ...env, COFFRE_CREDENTIALS: JSON.stringify(credentials), COFFRE_HANDLE: handle.token },
    left: plans.flatMap(([, plan]) => plan.left).sort(),
    credentials: Object.keys(credentials).sort(),
    // A placeholder is the handle, or holds it in the shape its client checks (`sk_test_coffre_use_…`, a JWT's last part).
    given: Object.keys(env).filter((key) => !env[key]!.includes(handle.token)).sort(),
    expiresAt: handle.expiresAt,
    tunnels: plans.flatMap(([, plan]) => tunnelsOf(plan)),
    handle: handle.token,
    made,
    // A run's handle ends with its command (`run`): no app it started holds it after. Asked quietly: a refusal, or an
    // instance out of reach, leaves the handle to end by itself.
    revoke: async () => void (await createClient({ url: to.origin, headers: () => headersFor(to), transport: once }).handles.revoke(handle.id)),
  };
}

/** Whether `to` is a person's session, a personal token's included, on an instance with the credential proxy: what gets placeholders. */
async function proxied(to: Target): Promise<boolean> {
  const person = to.by === 'person' || (to.credential.kind === 'token' && to.credential.token.startsWith('coffre_pat_'));
  if (!person) return false;
  const proxy = await http(`${to.origin}/use`, { headers: await headersFor(to), redirect: 'manual' }).catch((error: unknown) => fail(unreachable(to.origin, error)));
  if (proxy.status === 404 || !isJsonContentType(proxy.headers.get('content-type'))) return false;
  if (!proxy.ok) fail(`${to.origin}'s credential proxy answered ${proxy.status}`);
  return true;
}

/** What `run` and `export` say of a person's placeholders, on stderr: what the app holds, and what it does without. */
function sayPlaceholders(placed: Placeholders, paths: readonly string[], to: Target): void {
  const lines = [
    `coffre: placeholders for ${listOf(paths)}: ${placed.credentials.length === 0 ? 'no credential the proxy covers' : `${placed.credentials.join(', ')} through ${to.origin}/use`}; the handle lasts until ${new Date(placed.expiresAt).toLocaleString()} (\`coffre tokens\` lists it)`,
    ...placed.made.map(([mine, keys]) => `coffre: made your own ${keys.join(', ')} in ${mine}, each by its recipe: your next runs use them`),
    ...(placed.given.length === 0 ? [] : [`coffre: values as they are, which you may read: ${placed.given.join(', ')}`]),
    ...(placed.tunnels.length === 0 ? [] : [`coffre: ${placed.tunnels.map((tunnel) => tunnel.key).join(', ')} through a tunnel to its database, on 127.0.0.1`]),
    ...(placed.left.length === 0 ? [] : [`coffre: left out, neither proxied nor yours to read: ${placed.left.join(', ')}`]),
  ];
  process.stderr.write(`${lines.join('\n')}\n`);
}

/**
 * Fetch every secret of the environments named and exec a command with them
 * in its environment: one audited read per environment, and one audit row
 * per secret injected. A variable the shell already sets is overwritten,
 * unless --keep-existing keeps it. (`export` prints values for a tool to
 * apply, so it has no shell environment to defer to.)
 */
async function run(args: string[]): Promise<void> {
  const separator = args.indexOf('--');
  if (separator === -1 || separator === args.length - 1) {
    fail('usage: coffre run [--keep-existing] <project>/<environment> [<project>/<environment> ...] -- <command> [args...]');
  }

  const { values: flags, positionals } = parseArgs({
    args: args.slice(0, separator),
    options: { 'keep-existing': { type: 'boolean', default: false }, proof: { type: 'string' } },
    allowPositionals: true,
    strict: true,
  });
  const command = args.slice(separator + 1);

  // A service, key-bound where the instance has it: the session's environments unless named, and nothing but its key in memory.
  const to = target();
  if (flags.proof !== undefined && to.credential.kind !== 'workload') fail('--proof is how a service proves itself: coffre --service <name> run --proof …');
  const bound =
    to.credential.kind === 'workload'
      ? await keyBound(to.origin, to.credential.service, await proofOf(flags.proof, process.env), positionals, (line) => process.stderr.write(`${line}\n`), fetching(to.origin)).catch(
          (error: unknown) => fail(error instanceof Error ? error.message : String(error)),
        )
      : null;
  const paths = bound?.places ?? environmentPaths(positionals);
  // A person's app gets placeholders, where the instance has the proxy; a service account, the values.
  const placed = bound === null ? await placeholders(paths) : null;
  if (placed !== null) sayPlaceholders(placed, paths, to);
  const values = bound?.env ?? placed?.env ?? Object.fromEntries(await readOrEnd(paths));
  // Each database the app reaches through a tunnel: a listener of this run's, for as long as its command runs.
  for (const tunnel of placed?.tunnels ?? []) {
    const { url } = await listen(tunnel, placed!.handle).catch((error: unknown) => fail((error as Error).message));
    // As an own property: a variable may be named __proto__, which assigning would drop.
    Object.defineProperty(values, tunnel.key, { value: url, enumerable: true, writable: true, configurable: true });
  }
  // The shell's own variables win, if asked: one that is set, empty or not, is kept, and coffre's value for it dropped (it was read, and the read is audited).
  const kept = flags['keep-existing'] ? Object.keys(values).filter((key) => Object.hasOwn(process.env, key)) : [];
  for (const key of kept) delete values[key];
  if (kept.length > 0) {
    process.stderr.write(`coffre: kept the value already set in your environment for ${kept.sort().join(', ')}, not coffre's\n`);
  }

  const child = spawn(command[0], command.slice(1), {
    // Secrets are passed through the environment of the child only. They are
    // never written to disk and never appear in argv, which is world-readable
    // via ps.
    env: { ...process.env, ...values },
    stdio: 'inherit',
  });

  // The command's to answer: a terminal's Ctrl-C reaches it as it reaches this run, which keeps its tunnels' listeners
  // for it (a psql's cancel request goes through them), and a SIGTERM or SIGHUP sent to this run is passed on to it.
  const passOn = (signal: NodeJS.Signals) => () => void child.kill(signal);
  const handlers = { SIGINT: () => undefined, SIGTERM: passOn('SIGTERM'), SIGHUP: passOn('SIGHUP') } as const;
  for (const [signal, handler] of Object.entries(handlers)) process.on(signal, handler);
  /** Its handle revoked, or its key-bound session logged out, a few seconds at most, and then `then`: offline, either ends by itself, at its expiry. */
  const ended = (then: () => void) => {
    for (const [name, handler] of Object.entries(handlers)) process.off(name, handler);
    const ending = placed?.revoke() ?? bound?.close();
    const revoked = ending === undefined ? Promise.resolve() : Promise.race([ending.catch(() => undefined), new Promise((resolve) => setTimeout(resolve, 3000).unref())]);
    void revoked.then(then);
  };
  child.on('error', (error) => ended(() => fail(`failed to run ${command[0]}: ${error.message}`)));
  child.on('exit', (code, signal) =>
    ended(() => {
      if (signal) process.kill(process.pid, signal);
      process.exit(code ?? 0);
    }),
  );
}

/**
 * Print every secret of the environments named, for tools that want a file
 * or a shell rather than a child process. Each value read is one audit row
 * in your name, exactly as with `run`.
 */
async function exportEnv(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      format: { type: 'string', default: 'dotenv' },
      'output-file': { type: 'string' },
      watch: { type: 'boolean', default: false },
      interval: { type: 'string' },
      'on-change': { type: 'string' },
      keys: { type: 'string', multiple: true },
    },
    allowPositionals: true,
  });
  const usage = 'usage: coffre export <project>/<environment> [<project>/<environment> ...] [--keys <KEY | PREFIX_*>...] [--format dotenv|json|shell|github] [--output-file <file> [--watch [--interval 60s] [--on-change <command>]]]';
  const format = values.format;
  if (format !== 'dotenv' && format !== 'json' && format !== 'shell' && format !== 'github') fail(usage);
  const paths = environmentPaths(positionals);
  const patterns = values.keys === undefined ? null : keyPatterns(values.keys.join(' '));
  const file = values['output-file'];
  const githubEnv = process.env.GITHUB_ENV;
  if (format === 'github' && !githubEnv) fail('--format github requires GITHUB_ENV (run it in a GitHub Actions step)');
  if (format === 'github' && file !== undefined) fail('--format github appends to GITHUB_ENV, and writes no other file');
  // Every later step of the job sees what GITHUB_ENV gets: the workflow, which its reviewers read, names it, never whoever writes the environment.
  if (format === 'github' && patterns === null) {
    fail(`--format github exports to every later step of the job only the keys the workflow names: --keys "DATABASE_URL STRIPE_*". To hand every key to one process, \`coffre run ${paths.join(' ')} -- <command>\``);
  }
  const hijacks = (keys: readonly string[]) => {
    const key = format === 'github' ? keys.find(runsCode) : undefined;
    if (key !== undefined) fail(`${key} cannot be set through GITHUB_ENV: a later step's shell, loader or runtime would take code to run from it. Nothing was read`);
  };
  hijacks(patterns?.filter((pattern) => !pattern.endsWith('*')) ?? []);
  if (values.watch && file === undefined) fail('--watch keeps a file current: name it, --output-file <file>');
  if (values.watch && patterns !== null) fail('--watch keeps every key of its environments current: leave --keys out');
  if (!values.watch && (values.interval !== undefined || values['on-change'] !== undefined)) fail('--interval and --on-change are for --watch');
  const text = (entries: [string, string][]) =>
    format === 'json' ? `${JSON.stringify(Object.fromEntries(entries), null, 2)}\n` : format === 'shell' ? formatShellExports(entries) : formatDotenv(entries);
  const byKey = (entries: [string, string][]) => entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  if (values.watch) {
    const intervalMs = attempt(() => interval(values.interval ?? '60s'));
    const to = target();
    if (to.by === 'run' || to.credential.kind === 'workload') fail("--watch outlives a CI run's credential, which lasts five minutes: watch with a session or a bearer token");
    if (await proxied(to)) fail("--watch keeps a file of values current, and a person's gets placeholders, which change only with the deployment: export again then");
    const api = enduringClient(to);
    process.stderr.write(`coffre: keeping ${file} current with ${listOf(paths)}; each read is in the audit log under your name, and asking whether to read is not\n`);
    // What a person's read leaves out, said when it changes, as the first read's is.
    let said = '';
    await watch({
      version: async () => (await Promise.all(paths.map((path) => api.environments.version(path)))).map((answer) => answer.version).join(' '),
      read: async () => {
        const { entries, version, sensitive } = await readEnvironments(paths, { read: api, list: api });
        if (sensitive.join(' ') !== said) sayLeftOut(sensitive);
        said = sensitive.join(' ');
        return { text: text(byKey(entries)), version };
      },
      file: file!,
      intervalMs,
      onChange: values['on-change'] ?? null,
      say: (line) => process.stderr.write(`coffre: ${line}\n`),
    }).catch((error: unknown) => fail(error instanceof Error ? error.message : String(error)));
  }

  // A person's placeholders are planned for whole environments, the handle's helpers with them: no key of them is picked.
  if (patterns !== null && format !== 'github' && (await proxied(target()))) {
    fail("--keys picks values, and a person's export here gets placeholders, which the credential proxy plans for whole environments: leave --keys out");
  }
  // The keys --keys names, by environment, listed before anything is made or read.
  const only = patterns === null ? null : await listKeys(paths, reader([403, 404]), patterns).catch((error: unknown) => fail(error instanceof Error ? error.message : String(error)));
  // What a prefix found, refused as a name is, and as `githubEnvironment` would refuse it once read.
  hijacks(only === null ? [] : [...only.values()].flat());
  // GitHub's environment is a CI run's, which a service account signs in for.
  const placed = format === 'github' ? null : await placeholders(paths);
  if (placed !== null) sayPlaceholders(placed, paths, target());
  if (placed !== null && placed.tunnels.length > 0) {
    process.stderr.write(`coffre: left out of the export: ${placed.tunnels.map((tunnel) => tunnel.key).join(', ')}, whose tunnel lives only as long as \`coffre run\`\n`);
  }
  const entries = byKey(placed === null ? await readOrEnd(paths, only) : Object.entries(placed.env));
  if (format === 'github') {
    // All masks precede validation, file I/O and the summary. Never print the
    // environment records, even if the file cannot be written.
    process.stdout.write(githubMasks([...(await workloadSecrets()), ...entries]));
    attempt(() => appendFileSync(githubEnv!, githubEnvironment(entries), { encoding: 'utf8', mode: 0o600 }));
  } else if (file !== undefined) attempt(() => replaceFile(file, text(entries)));
  else process.stdout.write(attempt(() => text(entries)));
  if (process.stderr.isTTY && placed === null) {
    const count = entries.length;
    process.stderr.write(
      `coffre: read ${count} secret${count === 1 ? '' : 's'} from ${listOf(paths)}${file === undefined ? '' : ` into ${file}`}; each read is in the audit log under your name\n`,
    );
  }
}

async function history(args: string[]): Promise<void> {
  const { values, positionals } = parse(args, { json: { type: 'boolean', default: false } }, ['<project>/<environment>/<KEY>']);
  const { project, environment, key } = parsePath(positionals[0]!);
  if (!key) throw new UsageError('name a secret: <project>/<environment>/<KEY>');

  const result = await client().secrets.history(`${project}/${environment}/${key}`);
  if (values.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  for (const version of result.versions) {
    process.stdout.write(
      // An instance before 0.7 says nothing of recipes.
      `v${String(version.version).padEnd(4)} ${version.createdAt.slice(0, 19).replace('T', ' ')}  ${version.createdBy.padEnd(24)}${version.current ? ' (current)' : ''}${version.recipe == null ? '' : `  (generated, ${version.recipe})`}\n`,
    );
  }
}

async function rollback(args: string[]): Promise<void> {
  const [target, version] = parse(args, {}, ['<project>/<environment>/<KEY>', '<version>']).positionals as [string, string];

  const { project, environment, key } = parsePath(target);
  if (!key) fail('usage: coffre rollback <project>/<environment>/<KEY> <version>');

  const wanted = Number(version);
  if (!Number.isInteger(wanted) || wanted < 1) fail(`"${version}" is not a version number`);
  await client().secrets.restore(`${project}/${environment}/${key}`, wanted);

  process.stdout.write(`${key} rolled back to version ${version}\n`);
}

/**
 * Import a .env file. Previews by default; --apply writes.
 *
 * The preview is a dry run of the write: the server compares against the
 * current values, logs each one it opens as a read, and sends none back.
 * --apply then writes the keys that differ in one transaction, a new version
 * each.
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
  const parsed = parseDotenv(content);

  for (const problem of parsed.problems) {
    // The key, when the line has one, and never the line: it may be a value.
    process.stderr.write(`  line ${problem.line}: ${problem.reason}${problem.key === undefined ? '' : ` (${problem.key})`}\n`);
  }
  if (parsed.entries.length === 0) return;

  const coffre = client();
  const path = `${project}/${environment}`;
  const { plan, changes } = await planImport(coffre, path, parsed.entries);
  if (values.apply && Object.keys(changes).length > 0) await coffre.secrets.set(path, changes);

  for (const entry of plan) {
    process.stdout.write(`${entry.action.padEnd(10)} ${entry.key}\n`);
  }

  if (!values.apply) {
    const pending = Object.keys(changes).length;
    process.stdout.write(
      `\n${pending} change${pending === 1 ? '' : 's'} pending. Re-run with --apply to write.\n`,
    );
  }
}

async function whoHasAccess(args: string[]): Promise<void> {
  const { values, positionals } = parse(args, { json: { type: 'boolean', default: false }, service: { type: 'boolean', default: false } }, ['<project>[/<environment>] | <member>'], 1);
  // A member's own access: an email, or a service account's name with --service or service:.
  const asked = positionals[0];
  if (asked !== undefined && (values.service || /[@:]/.test(asked))) return memberAccess(memberOf(asked, values.service), values.json);
  const result = await client().members.list(positionals[0]);
  if (values.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  for (const member of result.members) {
    const role = member.instanceRole === 'member' ? '' : `  ${manage.roleInWords(member)}`;
    const tampered = member.tampered ? '  [record failed its integrity check: remove to start over]' : '';
    process.stdout.write(`${named(member.principalType, member.principalId)}${role}${tampered}\n`);
    for (const g of member.grants) {
      const place = g.environment === null ? g.project : `${g.project}/${g.environment}`;
      const until = g.expiresAt === null ? '' : ` until ${g.expiresAt.slice(0, 10)}`;
      process.stdout.write(`  ${place.padEnd(24)} ${g.role}${until}\n`);
    }
  }
  // Who reads a place's secrets through references held elsewhere: a grant there is not the only way in.
  if (positionals[0] === undefined) return;
  const into = (await client().references.list(positionals[0])).references
    .filter((reference) => reference.source.startsWith(`${positionals[0]}/`) && reference.readers !== null);
  if (into.length === 0) return;
  process.stdout.write(`\nAlso readable through references\n`);
  for (const reference of into) {
    process.stdout.write(`  ${reference.source} through ${reference.holder}, made by ${shownMember(reference.createdBy).replace(/^user:/, '')}\n`);
    for (const reader of reference.readers!) process.stdout.write(`    ${shownMember(reader).replace(/^user:/, '')}\n`);
  }
}

/** `coffre access ada@acme.example`: their instance role and the grants you manage, in one read. */
async function memberAccess(member: string, json: boolean): Promise<void> {
  const access = await client().members.access(member);
  if (json) return void process.stdout.write(`${JSON.stringify(access, null, 2)}\n`);
  const tampered = access.status === 'tampered' ? '  [record failed its integrity check: remove to start over]' : access.status === 'removed' ? '  [removed]' : '';
  process.stdout.write(`${named(access.principalType, access.principalId)}  ${manage.roleInWords(access)}${tampered}\n`);
  for (const g of access.grants) {
    const place = g.environment === null ? g.project : `${g.project}/${g.environment}`;
    process.stdout.write(`  ${place.padEnd(24)} ${g.role}${g.expiresAt === null ? '' : ` until ${g.expiresAt.slice(0, 10)}`}\n`);
  }
}

async function grantAccess(args: string[]): Promise<void> {
  const { values, positionals } = parse(
    args,
    {
      role: { type: 'string' },
      env: { type: 'string' },
      service: { type: 'boolean', default: false },
      expires: { type: 'string' },
    },
    ['<project>', '<principal>'],
  );

  const [project, principalId] = positionals as [string, string];
  if (!values.role) throw new UsageError('name the role: --role <role>');
  manage.onAProject(project);

  const role = values.role;
  // Which roles the instance defines, it says: one an Owner made is granted as one that ships.
  if (!ROLE_ID.test(role)) fail(`no role "${role}": \`coffre roles\` lists them`);
  const scope = values.env ? `${project}/${values.env}` : project;
  const who = memberOf(principalId, values.service);
  // A member is admitted before they hold anything: grant does not make one.
  const admit = `coffre admit ${shownMember(who).replace(/^user:/, '')}`;
  const hint: Hint = (status, reason) => (status === 409 && reason === 'principal_not_registered' ? `admit them first, \`${admit}\`` : null);
  // Declarative: this place gets this role, replacing any other role there.
  await client(target(), hint).access.set(who, {
    [scope]: values.expires ? { role, until: values.expires } : role,
  });

  process.stdout.write(`granted ${values.role} on ${scope} to ${shownMember(who).replace(/^user:/, '')}\n`);
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

/** "2 grants, 1 session, 0 linked accounts, 1 connected app": what a removal ends. */
function waysIn(
  principalType: 'user' | 'service',
  counts: { grants: number; sessions: number; tokens: number; identities: number; apps: number },
): string {
  return principalType === 'user'
    ? [
        plural(counts.grants, 'grant'),
        plural(counts.sessions, 'session'),
        ...(counts.tokens > 0 ? [plural(counts.tokens, 'personal token')] : []),
        plural(counts.identities, 'linked account'),
        plural(counts.apps, 'connected app'),
      ].join(', ')
    : [plural(counts.grants, 'grant'), plural(counts.tokens, 'token')].join(', ');
}

/**
 * Offboard someone. Previews by default, like import: what removing them
 * would revoke, and what they leave behind. --apply removes them.
 *
 * Removal takes every way in away at once. What it cannot take back is what
 * they saw, so the report after it is the list of values to rotate.
 */
async function trust(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: TRUST_OPTIONS,
    allowPositionals: true,
  });
  const [service] = positionals;
  // `coffre trust` alone says how, as `coffre help` says it does.
  if (positionals.length === 0 && Object.values(values).every((value) => value === undefined || value === false)) {
    process.stdout.write(`${TRUST_USAGE}\n`);
    return;
  }
  if (!service) throw new UsageError('name the service: coffre trust <service> …');
  if (positionals.length > 1) throw new UsageError(`too many arguments: ${positionals.slice(1).join(' ')}`);
  const member = serviceMember(service);
  const coffre = client();
  const { scope: scopeFlags, label, replace, apply, 'jwks-file': jwksFile, 'replace-keys': replaceKeys, ...flags } = values;
  if (Object.keys(flags).length === 0 && jwksFile === undefined && replaceKeys === undefined) {
    process.stdout.write(describeBindings(member, (await coffre.bindings.list(member)).bindings));
    return;
  }
  const jwks = (() => {
    if (jwksFile === undefined) return undefined;
    try {
      return keySetFrom(readFileSync(jwksFile, 'utf8'), jwksFile);
    } catch (error) {
      return fail((error as NodeJS.ErrnoException).code === undefined ? (error as Error).message : `could not read ${jwksFile}: ${(error as Error).message}`);
    }
  })();
  if (replaceKeys === true) {
    const { issuer, ...others } = flags;
    if (issuer === undefined || jwks === undefined) throw new UsageError('--replace-keys takes --issuer <iss> and --jwks-file <path>: whose bindings get which keys');
    const extra = [...Object.keys(others), ...(scopeFlags === undefined ? [] : ['scope']), ...(label === undefined ? [] : ['label']), ...(replace === undefined ? [] : ['replace'])];
    if (extra.length > 0) throw new UsageError(`--replace-keys changes only the keys of the bindings on --issuer, not --${extra.join(', --')}`);
    const plan = await coffre.bindings.previewKeys(member, { issuer, jwks });
    if (!apply) {
      process.stdout.write(`${describeKeys(member, plan, null)}Run it again with --apply to save it.\n`);
      return;
    }
    const saved = await coffre.bindings.replaceKeys(member, { issuer, jwks });
    process.stdout.write(describeKeys(member, plan, saved));
    return;
  }
  // A repository or project the lookup cannot see comes back here, for bindingFrom to say how to give its IDs.
  const lookup = client(target(), undefined, [400, 404]);
  const binding = await bindingFrom(flags, (input) => lookup.bindings.lookup(input), { service: member }).catch((error: unknown) =>
    fail(error instanceof Error ? error.message : String(error)),
  );
  const scope = (() => {
    try {
      return scopeFrom(scopeFlags);
    } catch (error) {
      throw new UsageError((error as Error).message);
    }
  })();
  // A workload's binding, its profile and policy, is the route's from PR 1a of docs/design/workload-access.md on: until then, the server refuses it with a 400.
  const input = { ...binding, ...(scope === undefined ? {} : { scope }), ...(jwks === undefined ? {} : { jwks }), label: label ?? null, replaces: replace ?? [] } as Parameters<CoffreClient['bindings']['preview']>[1];
  const plan = await coffre.bindings.preview(member, input);
  const events = describeEvents(plan);
  if (!apply) {
    process.stdout.write(describePlan(member, plan, null));
    if (events !== null) process.stdout.write(`${events}\n`);
    process.stdout.write('Run it again with --apply to save it.\n');
    return;
  }
  const saved = await coffre.bindings.create(member, input);
  process.stdout.write(describePlan(member, plan, saved.binding));
  if (events !== null) process.stdout.write(`${events}\n`);
}

/** `coffre offboard` of a service account by its manager: what it holds, and with --apply, removed. */
async function offboardManaged(coffre: CoffreClient, member: string, apply: boolean): Promise<void> {
  const access = await coffre.members.access(member);
  const shown = shownMember(member);
  if (!access.managed) fail(`you do not manage ${shown}: it holds something you do not, or the instance keeps it to admins`);
  if (!apply) {
    process.stdout.write(`${shown} is active; removing it would revoke ${access.grants.length} grant${access.grants.length === 1 ? '' : 's'}, and every token and trust binding\nNothing changed. Re-run with --apply to remove it.\n`);
    return;
  }
  const removed = await coffre.members.remove(member);
  process.stdout.write(`removed ${shown}: revoked ${waysIn('service', removed.revoked)}\n`);
}

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
  const member = memberOf(principalId, values.service);
  const shown = shownMember(member).replace(/^user:/, '');
  const coffre = client();

  // A service account's manager, who does not run the instance, reads what it holds, not what it read anywhere.
  const found = await coffre.members.get(member).catch((error: unknown) => {
    if (error instanceof CoffreError && error.status === 403 && member.startsWith('token:')) return null;
    throw error;
  });
  if (found === null) return offboardManaged(coffre, member, values.apply);
  let report = found;
  const they = report.principalType === 'user' ? 'they' : 'it';

  if (report.status === 'active' && values.apply) {
    const removed = await coffre.members.remove(member);
    process.stdout.write(`removed ${shown}: revoked ${waysIn(report.principalType, removed.revoked)}\n`);
    report = removed.report ?? report;
  } else if (report.status === 'active') {
    process.stdout.write(
      `${shown} is active; removing would revoke ${waysIn(report.principalType, report.live)}\n`,
    );
  } else {
    const by = report.removedBy === null ? '' : ` by ${report.removedBy}`;
    const at = report.removedAt === null ? '' : ` on ${report.removedAt.slice(0, 16).replace('T', ' ')}`;
    process.stdout.write(`${shown} was removed${by}${at}\n`);
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

  if (report.apps.length > 0) {
    process.stdout.write(`\nConnected apps, which removing them disconnects (${report.apps.length})\n`);
    const width = Math.max(...report.apps.map((app) => app.name.length));
    for (const app of report.apps) {
      const used = app.lastUsedAt === null ? 'never used' : `last used ${app.lastUsedAt.slice(0, 10)}`;
      process.stdout.write(`  ${app.name.padEnd(width)}  ${app.host ?? 'no website'}, may ${app.scopes.join(', ')}, ${used}\n`);
    }
  }

  // An instance before 0.7 lists none.
  const personalTokens = report.personalTokens ?? [];
  if (personalTokens.length > 0) {
    process.stdout.write(`\nPersonal tokens, which act as them and removing them revokes (${personalTokens.length})\n`);
    for (const token of personalTokens) {
      const used = token.lastUsedAt === null ? 'never used' : `last used ${token.lastUsedAt.slice(0, 10)}`;
      process.stdout.write(`  "${token.label ?? ''}" ${token.hint}, reaching ${reaches(token.scope)}, ${used}, expires ${token.expiresAt.slice(0, 16).replace('T', ' ')} UTC\n`);
    }
  }

  if (report.issuedTokens.length > 0) {
    process.stdout.write(`\nBearer tokens ${they} issued to service accounts, which still work\n`);
    for (const token of report.issuedTokens) {
      const label = token.label === null ? '' : ` "${token.label}"`;
      process.stdout.write(
        `  service:${serviceName(token.service)}${label} ${token.hint}, reaching ${reaches(token.scope)}, expires ${token.expiresAt.slice(0, 10)}\n`,
      );
    }
  }

  if (report.references.length > 0) {
    process.stdout.write(`\nReferences ${they} made: each belongs to the environment that holds it, so removing ${they === 'they' ? 'them' : 'it'} ends none. Review them; \`coffre references break\` ends one\n`);
    for (const reference of report.references) {
      const state = reference.state === 'live' ? '' : `  (${reference.state.replace('_', ' ')})`;
      process.stdout.write(`  ${reference.holder} → ${reference.source}, ${reference.createdAt.slice(0, 10)}${state}\n`);
    }
  }

  if (report.status === 'active' && !values.apply) {
    process.stdout.write(`\nNothing changed. Re-run with --apply to remove ${shown}.\n`);
  }
}

async function audit(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      limit: { type: 'string', default: '20' },
      actor: { type: 'string' },
      denied: { type: 'boolean', default: false },
      // Sign-ins, tokens and the vault's key operations, which are left out unless asked for.
      detail: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });

  const limit = Number(values.limit);
  if (!Number.isInteger(limit) || limit < 1) fail(`--limit takes a positive number, not "${values.limit}"`);
  if (positionals.length > 1) fail('usage: coffre audit [<project>[/<environment>[/<KEY>]]] [--limit N] [--actor <id>] [--denied] [--detail] [--json]');
  const result = await client().audit.list({
    path: positionals[0],
    limit,
    // `service:deploy` as people write it, `token:deploy` as the log keeps it.
    actor: values.actor === undefined ? undefined : apiMember(values.actor),
    decision: values.denied ? 'deny' : undefined,
    detail: values.detail ? '1' : undefined,
  });
  if (values.json) {
    process.stdout.write(`${JSON.stringify(result.entries, null, 2)}\n`);
    return;
  }

  for (const entry of result.entries.reverse()) {
    // A read of several secrets at one place is one entry: its place and how many it read. A server before 0.7 says nothing of them.
    const read = entry.secrets == null ? '' : ` (${entry.secrets.length} secrets)`;
    const place = ([entry.project, entry.environment, entry.key].filter((part) => part !== null).join('/') || '-') + read;
    // A personal token's entries are its person's, and say which token: `ada@acme.example via "cursor-agent"`.
    // An instance before 0.7 sends no `token`.
    const actor = `${entry.actorType === 'service' ? `service:${entry.actorId}` : entry.actorId}${entry.token == null ? '' : ` via "${entry.token.label}"`}`;
    process.stdout.write(`${entry.occurredAt}  ${entry.decision.padEnd(5)}  ${actor.padEnd(28)}  ${entry.action.padEnd(16)}  ${place}\n`);
  }
}

/**
 * An Owner's acceptance that audit entries `<from>` to `<to>` are lost for
 * good: the audit watch's anchor goes on past them, and its finding, with
 * the acceptance, stays in the log.
 */
async function acceptLoss(args: string[]): Promise<void> {
  const [from, to, ...rest] = args;
  const entry = (value: string | undefined) => (value !== undefined && /^[0-9]{1,15}$/.test(value) ? Number(value) : null);
  if (entry(from) === null || entry(to) === null || rest.length > 0) fail('usage: coffre audit accept-loss <from> <to>');
  const { resumes } = await client().audit.acceptLoss({ from: entry(from)!, to: entry(to)! });
  process.stdout.write(`entries ${from} to ${to} accepted as lost: the audit watch goes on from entry ${resumes ?? 0}\n`);
}

/** One check of the instance, named, or chosen on the terminal (`verify/index.ts`). */
async function verify(args: string[]): Promise<void> {
  const [named, ...more] = args;
  if (named === '--help' || named === '-h') {
    process.stdout.write(`${VERIFY_USAGE}\n`);
    return;
  }
  const check = named ?? (await pickCheck());
  switch (check) {
    case 'instance':
      return verifyInstance(more, readStore(), sessionFlags, localHere());
    case 'keys': {
      const to = target();
      return verifyKeys(more, client(to), to.origin);
    }
    case 'log':
      if (more.length > 0) fail('usage: coffre verify log');
      return verifyLog();
    default:
      process.stderr.write(`coffre: no check named ${check}\n${VERIFY_USAGE}\n`);
      process.exit(2);
  }
}

/**
 * The whole audit log, verified by the app and the vault from its first
 * entry, a stretch a request, for whoever reads it whole: what the audit
 * page's check, which goes on from the newest checkpoint, takes on trust.
 */
async function verifyLog(): Promise<void> {
  const shown = process.stderr.isTTY;
  const result = await client().audit.verifyWhole((stretch) => {
    if (shown && stretch.ok && typeof stretch.next === 'string') process.stderr.write(`\rverified through entry ${stretch.through}…`);
  });
  if (shown) process.stderr.write('\r\x1b[K');

  if (result.ok) {
    const through = result.through === null ? 'empty' : `verified from the first entry through entry ${result.through}`;
    const signed = result.checkpoint === null
      ? 'no checkpoint signed yet'
      : `last checkpoint: entry ${result.checkpoint.seq}, signed ${result.checkpoint.signedAt}`;
    const pending = result.pending === undefined ? '' : `${result.pending} key operations still under way\n`;
    if (result.remaining > 0) {
      // Past the newest checkpoint a stretch goes one walk, and none goes on from there: not the whole log.
      process.stderr.write(
        `audit log not verified to its end: ${through}, and ${result.remaining} newer entries wait for the checkpoints to catch up, ` +
          'a walk every five minutes; run this again after the next beats\n',
      );
      process.exit(3);
    }
    process.stdout.write(`audit log OK: ${through}, ${result.entries} entries; members and grants replayed\n${signed}\n${pending}`);
    return;
  }
  const at = result.failedAtSeq === null ? '' : ` at entry ${result.failedAtSeq}`;
  const through = result.through === null ? 'nothing verified' : `verified through entry ${result.through}`;
  process.stderr.write(`audit log BROKEN${at}, found by the ${result.author}'s check (${through}): ${result.reason}\n`);
  process.exit(2);
}

/** `coffre init --workers|--node [<dir>]`: a new deployment of coffre. */
function initProject(args: string[]): void {
  const { values, positionals } = parseArgs({
    args,
    options: { workers: { type: 'boolean' }, node: { type: 'boolean' } },
    allowPositionals: true,
  });
  const kinds = KINDS.filter((kind) => values[kind]);
  if (kinds.length !== 1 || positionals.length > 1) fail('usage: coffre init --workers|--node [<dir>]');
  const kind: Kind = kinds[0];
  const dir = resolve(positionals[0] ?? '.');
  const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  const files = attempt(() => init(kind, dir, version));
  for (const file of files) process.stdout.write(`  ${file}\n`);
  // Where it went, as the person wrote it.
  const at = dir === process.cwd() ? null : (positionals[0] ?? null);
  process.stdout.write(
    `\nA ${kind === 'workers' ? 'Cloudflare Workers' : 'Node'} deployment of coffre ${version}` +
      `${at === null ? ' here' : ` in ${at}`}. Next:\n\n` +
      `${at === null ? '' : `  cd ${/\s/.test(at) ? `'${at}'` : at}\n`}  pnpm install\n\n` +
      'Then README.md takes it from there.\n',
  );
}

const line = attempt(() => commandLine(process.argv.slice(2)));
const { command, rest } = line;
/** What the session flags say, their files read before any command runs: a file that is not there stops it first. */
const sessionFlags = attempt(() => readSession(line.session));

/** The API of the instance the session names, asked for once a command has read its arguments. */
const connect = () => client();

/** Each command, by the words that name it: those `coffre help` lists, each one (`commands.ts`). */
const COMMANDS: Record<Command, (args: string[]) => unknown> = {
  init: initProject,
  keys,
  // Their own chunks: the database driver and the migrations load only for them.
  setup: async (args) => (await import('./setup.ts')).setup(args),
  update: async (args) => (await import('./update.ts')).update(args),
  migrate: async (args) => (await import('./migrate.ts')).migrate(args),
  login,
  logout,
  whoami,
  use,
  sessions: (args) => manage.sessions(connect, args),
  'sessions revoke': (args) => manage.sessionsRevoke(connect, args),
  apps: (args) => manage.apps(connect, args),
  'apps revoke': (args) => manage.appsRevoke(connect, args),
  identities: (args) => manage.identities(connect, args),
  'identities unlink': (args) => manage.identitiesUnlink(connect, args),
  list,
  get,
  set,
  mark,
  regenerate,
  run,
  export: exportEnv,
  version: (args) => manage.version(connect, args),
  history,
  rollback,
  import: importEnv,
  rename: (args) => manage.renameSecret(connect, args),
  archive: (args) => manage.archiveSecret(connect, args, true),
  unarchive: (args) => manage.archiveSecret(connect, args, false),
  reset: (args) => manage.resetSecret(connect, args),
  remove: (args) => manage.removeSecret(connect, args),
  move: (args) => manage.move(connect, args),
  folders: (args) => manage.folders(connect, args),
  'folders rename': (args) => manage.foldersRename(connect, args),
  'folders remove': (args) => manage.foldersRemove(connect, args),
  // A read of key names, asked again as reads of values are: the Action's `require-complete: true` gate.
  missing: (args) => manage.missing(() => client(target(), undefined, [], reading), args),
  'missing dismiss': (args) => manage.missingDismiss(connect, args, true),
  'missing restore': (args) => manage.missingDismiss(connect, args, false),
  projects: (args) => manage.projects(connect, args),
  'projects create': (args) => manage.projectsCreate(connect, args),
  'projects rename': (args) => manage.projectsRename(connect, args),
  'projects archive': (args) => manage.projectsArchive(connect, args, true),
  'projects unarchive': (args) => manage.projectsArchive(connect, args, false),
  'projects delete': (args) => manage.placeDelete(connect, args, false),
  'environments create': (args) => manage.environmentsCreate(connect, args),
  references: (args) => manage.references(connect, args),
  'references break': (args) => manage.referencesBreak(connect, args),
  fork: (args) => manage.fork(connect, args),
  personal: (args) => manage.personal(connect, args),
  'environments rename': (args) => manage.environmentsRename(connect, args),
  'environments archive': (args) => manage.environmentsArchive(connect, args, true),
  'environments unarchive': (args) => manage.environmentsArchive(connect, args, false),
  'environments delete': (args) => manage.placeDelete(connect, args, true),
  'environments protect': (args) => manage.environmentsProtect(connect, args, true),
  'environments unprotect': (args) => manage.environmentsProtect(connect, args, false),
  roles: (args) => manage.roles(connect, args),
  'roles set': (args) => manage.rolesSet(connect, args),
  'roles reset': (args) => manage.rolesReset(connect, args),
  'roles remove': (args) => manage.rolesRemove(connect, args),
  access: whoHasAccess,
  admit: (args) => manage.admit(connect, args),
  grant: grantAccess,
  revoke: (args) => manage.revoke(connect, args),
  offboard,
  settings: (args) => manage.settings(connect, args),
  tokens: (args) => manage.tokens(connect, args),
  'tokens issue': (args) => manage.tokensIssue(connect, args),
  'tokens revoke': (args) => manage.tokensRevoke(connect, args),
  trust,
  untrust: (args) => manage.untrust(connect, args),
  enroll,
  approve,
  freeze,
  unfreeze,
  serve: (args) => serve(args, sessionFlags.url, fetching),
  audit,
  'audit accept-loss': acceptLoss,
  verify,
  'verify instance': (args) => verify(['instance', ...args]),
  'verify keys': (args) => verify(['keys', ...args]),
  'verify log': (args) => verify(['log', ...args]),
};

/** The commands whose --help says more than their line in `coffre help`. */
const HELP: Partial<Record<Command, string>> = {
  trust: TRUST_USAGE,
  verify: VERIFY_USAGE,
  'verify instance': INSTANCE_USAGE,
  'verify keys': KEYS_USAGE,
};

/** A command's help, or a group's. */
function helpText(words: string): string {
  const own = HELP[words as Command];
  return own === undefined ? help(words) : `${own}\n`;
}

/** A parse error's first sentence, without Node's advice: `unknown option '--bogus'`. */
function parseError(error: unknown): string | null {
  const code = (error as { code?: unknown } | null)?.code;
  if (error instanceof UsageError) return error.message;
  if (typeof code !== 'string' || !code.startsWith('ERR_PARSE_ARGS')) return null;
  const message = (error as Error).message.split(/\.(\s|$)/)[0]!;
  return message.charAt(0).toLowerCase() + message.slice(1);
}

if (command === '--version' || command === '-v') {
  process.stdout.write(`${cliVersion()}\n`);
  process.exit(0);
}
if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
  const about = command === 'help' && rest.length > 0 ? lookup(rest) : null;
  if (command === 'help' && rest.length > 0 && about === null) {
    process.stderr.write(`coffre: no command ${rest.join(' ')}\n${usage()}`);
    process.exit(2);
  }
  process.stdout.write(about === null ? usage() : helpText('group' in about ? about.group : about.command));
  process.exit(0);
}

const found = lookup([command, ...rest]);
if (found === null) {
  process.stderr.write(`coffre: no command ${command}\n\n${usage()}`);
  process.exit(1);
}
const words = 'group' in found ? found.group : found.command;
const args = 'group' in found ? rest : found.args;
const end = args.indexOf('--');
if ((end === -1 ? args : args.slice(0, end)).some((arg) => arg === '--help' || arg === '-h')) {
  process.stdout.write(helpText(words));
  process.exit(0);
}
// `coffre tokens` alone has commands under it, and is none itself.
if ('group' in found) {
  process.stderr.write(`coffre: ${command} needs a command after it\n${helpText(words)}`);
  process.exit(2);
}
try {
  await COMMANDS[found.command](found.args);
} catch (error) {
  if (error instanceof CheckFailed) {
    // Not process.exit: what the command printed to a pipe would be cut short.
    process.stderr.write(`coffre: ${error.message}\n`);
    process.exitCode = 1;
  } else {
    const misuse = parseError(error);
    if (misuse === null) fail(error instanceof Error ? error.message : String(error));
    process.stderr.write(`coffre: ${misuse}\n${helpText(words)}`);
    process.exit(2);
  }
}
