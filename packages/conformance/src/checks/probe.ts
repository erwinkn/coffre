// `probe --sign-in`: the token tier, without setting it up by hand. An owner
// signs the probe in through a device login, as `coffre login` does; the
// probe makes or finds its own place, issues its service a fresh credential
// and writes a fresh canary, runs the token tier as that credential, then,
// as the owner, verifies the whole audit chain. However it ends, the
// credential is revoked and the session ended. Neither the credential nor
// the canary is ever printed or written down.
//
// What stays: the project, the environment and the service, which the next
// run finds, the canary's versions, and the run's entries in the audit log.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

import { CoffreError, type CoffreClient } from '@coffre/client';

import { bearer } from '../browser.ts';
import { expect, Failure, refused, Report } from '../report.ts';
import { tokenChecks, type Canary } from './live.ts';
import { canary, type Person } from './people.ts';

/** The probe's own place on an instance, made the first time, and found after. Nothing else is touched. */
export const PROBE = {
  project: 'conformance',
  environment: 'live',
  service: 'token:conformance-probe',
  // Its own key, beside a CANARY an operator may keep for a probe with a token from CI.
  key: 'SIGN_IN_CANARY',
} as const;

/** A device login to approve: the address to open, and the code it must show. */
export type DeviceLogin = { url: string; code: string };

/** How a device login gets approved: by a person in a browser, or, in the local run, by the admin's own session. */
export type Approve = (login: DeviceLogin) => void | Promise<void>;

/** A session from a device login: its credential, which never leaves this process, and who it is. */
type Session = { token: string; api: CoffreClient; who: string };

/** What the run made, to undo at its end: the credential it issued, if it got that far. */
type Issued = { member: string; id: string };

/** A device login, approved by `approve`, polled until it is, as `coffre login` polls. */
async function deviceSignIn(origin: string, approve: Approve): Promise<string> {
  const json = { 'content-type': 'application/json' };
  const started = await fetch(`${origin}/api/auth/device`, {
    method: 'POST',
    headers: json,
    body: JSON.stringify({ client_label: 'coffre-conformance probe' }),
  });
  expect(started.ok, `${origin} did not start a device login: ${started.status}`);
  const device = (await started.json()) as { device_code: string; user_code: string; verification_uri_complete: string; interval: number; expires_in: number };
  await approve({ url: device.verification_uri_complete, code: device.user_code });
  const deadline = Date.now() + device.expires_in * 1000;
  let wait = Math.max(device.interval, 1) * 1000;
  // The first look comes at once: the local run has approved already.
  for (let first = true; Date.now() < deadline; first = false) {
    if (!first) await new Promise((resolve) => setTimeout(resolve, wait));
    const polled = await fetch(`${origin}/api/auth/device/token`, { method: 'POST', headers: json, body: JSON.stringify({ device_code: device.device_code }) }).catch(() => null);
    if (polled === null) continue;
    const answer = (await polled.json().catch(() => ({}))) as { access_token?: string; error?: string };
    if (polled.ok && answer.access_token !== undefined) return answer.access_token;
    if (polled.status === 429 || answer.error === 'slow_down') wait += 5000;
    else if (answer.error === 'access_denied') throw new Failure('the device login was declined in the browser: nothing was made');
    else if (answer.error === 'expired_token') break;
    else if (answer.error !== 'authorization_pending') throw new Failure(`the device login failed: ${answer.error ?? polled.status}`);
  }
  throw new Failure('the device login expired before it was approved: nothing was made');
}

/** End a session, as `coffre logout` does. One already ended is ended. */
async function endSession(origin: string, token: string): Promise<void> {
  const response = await fetch(`${origin}/api/auth/logout`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' } });
  expect(response.ok || response.status === 401, `${origin} did not end the session: ${response.status}`);
}

/** Signed in, as an owner or a root admin, or stopped, the session ended, before anything is made. */
async function signIn(origin: string, approve: Approve): Promise<{ detail: string; value: Session }> {
  const token = await deviceSignIn(origin, approve);
  const api = bearer(origin, token);
  const me = await api.me();
  const who = me.principal.id;
  if (me.instanceRole === 'user') {
    await endSession(origin, token);
    throw new Failure(`${who} is neither an owner nor a root admin of ${origin}: the probe made nothing, and ended the session`);
  }
  return { detail: `${who}, ${me.instanceRole === 'owner' ? 'an owner' : 'a root admin'}, through a device login`, value: { token, api, who } };
}

/** Make what is missing of the probe's place, and the service's two grants; then a fresh canary, and a fresh credential. */
async function setUp(api: CoffreClient, issued: Issued[]): Promise<{ detail: string; value: { token: string; canary: Canary; made: string[] } }> {
  const place = `${PROBE.project}/${PROBE.environment}`;
  const made: string[] = [];
  const { projects } = await api.projects.list();
  const project = projects.find(({ slug }) => slug === PROBE.project);
  expect(project?.archivedAt == null, `${PROBE.project} is archived: unarchive it, or the probe has nowhere to run`);
  if (project === undefined) {
    await api.projects.create(PROBE.project, { name: 'Conformance' });
    made.push(`the project ${PROBE.project}`);
  }
  const environment = project?.environments.find(({ slug }) => slug === PROBE.environment);
  expect(environment?.details?.archivedAt == null, `${place} is archived: unarchive it, or the probe has nowhere to run`);
  if (environment === undefined) {
    await api.environments.create(place, { name: 'Live' });
    made.push(`the environment ${place}`);
  }
  if ((await api.members.add(PROBE.service)).created) made.push(`the service ${PROBE.service}`);
  const { changes } = await api.access.set(PROBE.service, { [place]: 'viewer', [PROBE.project]: 'auditor' });
  const granted = Object.entries(changes).filter(([, change]) => change !== 'unchanged');
  if (granted.length > 0) made.push(`its grants on ${granted.map(([where]) => where).join(' and ')}`);
  const value = canary();
  await api.secrets.set(place, { [PROBE.key]: value });
  const credential = await api.tokens.issue(PROBE.service, { label: 'coffre-conformance probe, one run', expiresInDays: 1 });
  issued.push({ member: PROBE.service, id: credential.id });
  return {
    detail: `${made.length === 0 ? 'all found' : `made ${made.join(', ')}`}; a fresh ${place}/${PROBE.key} and a fresh credential for ${PROBE.service}`,
    value: { token: credential.token, canary: { project: PROBE.project, environment: PROBE.environment, key: PROBE.key, value }, made },
  };
}

/** What the whole audit chain says, read by the owner, which a token cannot be. */
async function verification(api: CoffreClient): Promise<string> {
  const verified = await api.audit.verify();
  expect(verified.ok, 'the audit log does not verify', verified);
  return `the whole chain verifies, as the signed-in owner: ${verified.entries} entries, through entry ${verified.through}`;
}

/**
 * The signed-in tier: sign in, set up, the token tier, verification as the
 * owner; and, however it ends, a Ctrl-C included, the credential revoked and
 * the session ended. `prefix` names its checks apart from the local run's
 * own. Returns the session's credential, ended, for the local run to check.
 */
export async function signedInChecks(report: Report, origin: string, approve: Approve, prefix = ''): Promise<ProbeRun | undefined> {
  const session = await report.check(`${prefix}sign-in`, {}, () => signIn(origin, approve));
  if (session === undefined) return undefined;
  const issued: Issued[] = [];
  let ended: Promise<string> | null = null;
  const end = () => (ended ??= cleanUp(origin, session, issued));
  // Ctrl-C, or a SIGTERM: the credential and the session go before the process does.
  const interrupted = (code: number) => () => void end().finally(() => process.exit(code));
  const onInt = interrupted(130);
  const onTerm = interrupted(143);
  process.once('SIGINT', onInt);
  process.once('SIGTERM', onTerm);
  let live: { token: string; made: string[] } | undefined;
  try {
    live = await report.check(`${prefix}probe setup`, {}, () => setUp(session.api, issued));
    await tokenChecks(report, origin, live ?? {}, prefix);
    await report.check(`${prefix}owner verification`, {}, () => verification(session.api));
  } finally {
    process.off('SIGINT', onInt);
    process.off('SIGTERM', onTerm);
    await report.check(`${prefix}clean-up`, {}, end);
  }
  return live === undefined ? undefined : { session: session.token, credential: live.token, made: live.made };
}

/** A run's session and credential, both ended by its end, for the local run to try; and what its setup made. */
export type ProbeRun = { session: string; credential: string; made: string[] };

/** Revoke what the run issued, end its session, and say what stays. */
async function cleanUp(origin: string, session: Session, issued: Issued[]): Promise<string> {
  for (const { member, id } of issued) await session.api.tokens.revoke(member, id);
  const { tokens } = await session.api.tokens.list(PROBE.service).catch(() => ({ tokens: [] as unknown[] }));
  await endSession(origin, session.token);
  const others = tokens.length === 0 ? 'no working credential' : `${tokens.length} credential${tokens.length === 1 ? '' : 's'} this run did not issue, left as they are`;
  return (
    `${issued.length === 0 ? 'nothing issued' : 'the credential revoked'}, the session ended. Staying: ${PROBE.project}/${PROBE.environment} and its ` +
    `${PROBE.key}, ${PROBE.service} with ${others}, and this run's entries in the audit log`
  );
}

/** Open `url` in this machine's browser, if it has one: on a server, the printed address serves. */
export function openBrowser(url: string): void {
  const [command, ...args] =
    process.platform === 'darwin' ? ['open', url] : process.platform === 'win32' ? ['cmd', '/c', 'start', '', url] : ['xdg-open', url];
  try {
    const child = spawn(command!, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    // No opener: the printed address serves.
  }
}

// --- the local run's checks of it ----------------------------------------------

/** The local run approves as the person signing in: their own session approves the code, as their browser would. */
function approvedBy(person: Person): Approve {
  return async ({ code }) => {
    await person.api.deviceLogins.decide(code, true);
  };
}

/** What the probe must leave as it was: every member and their grants, but its service; every project and environment. */
async function everythingElse(api: CoffreClient): Promise<string> {
  const { members } = await api.members.list();
  const { projects } = await api.projects.list();
  return JSON.stringify({
    members: members.filter(({ member }) => member !== PROBE.service),
    projects: projects.map(({ slug, archivedAt, environments }) => ({ slug, archivedAt, environments: environments.map(({ slug: env }) => env) })),
  });
}

/** Signed in as a user, the probe says so, and makes nothing: no service, no session left. Returns what it must leave as it was. */
export async function probeAsUser(origin: string, user: Person, admin: Person): Promise<{ detail: string; value: string }> {
  const before = await everythingElse(admin.api);
  const quiet = new Report(19, true);
  await signedInChecks(quiet, origin, approvedBy(user));
  const [signIn] = quiet.results;
  expect(quiet.results.length === 1 && signIn?.status === 'FAIL', 'the probe went on past a user', quiet.results);
  expect(signIn.line.includes('is neither an owner nor a root admin') && signIn.line.includes('made nothing'), 'the probe did not say plainly why it stopped', signIn.line);
  const service = await admin.api.members.get(PROBE.service).then(
    () => 'there',
    (error: unknown) => (error instanceof CoffreError && error.status === 404 ? 'absent' : Promise.reject(error)),
  );
  expect(service === 'absent', `${PROBE.service} was made for a user`);
  const { sessions } = await user.api.sessions.list();
  expect(!sessions.some(({ label }) => label === 'coffre-conformance probe'), "the user's probe session was left open", sessions);
  expect((await everythingElse(admin.api)) === before, 'the probe changed a member, a grant, a project or an environment for a user');
  return { detail: `${user.email}, a user, is told plainly; nothing made, the session ended`, value: before };
}

/** One run of `probe --sign-in`, as the admin: every check of it passes. Its lines, summed up. */
export async function probeRun(origin: string, admin: Person): Promise<{ detail: string; value: ProbeRun }> {
  const quiet = new Report(19, true);
  const run = await signedInChecks(quiet, origin, approvedBy(admin));
  const failed = quiet.results.filter(({ status }) => status === 'FAIL');
  expect(run !== undefined && failed.length === 0, `the probe failed: ${failed.map(({ name }) => name).join(', ')}`, quiet.results);
  const said = JSON.stringify(quiet.results);
  expect(!said.includes(run.credential) && !said.includes(run.session) && !/coffre-canary-/.test(said), "the probe's lines show its credential, its session or its canary");
  const skipped = quiet.results.filter(({ status }) => status === 'skip').map(({ name }) => name);
  return {
    detail: `${quiet.results.length - skipped.length} checks ok${skipped.length === 0 ? '' : `, ${skipped.join(', ')} skipped`}; ${run.made.length === 0 ? 'all found' : `made ${run.made.join(', ')}`}`,
    value: run,
  };
}

/**
 * After two runs: the second found everything the first made; each run's
 * credential and session refuse, and the service holds no credential; the
 * canary an operator keeps beside is as it was; nothing else changed; the
 * runs' reads are in the audit log.
 */
export async function probeLeftovers(origin: string, admin: Person, runs: ProbeRun[], before: string, kept: Canary): Promise<string> {
  expect(runs[0]!.made.includes(`the service ${PROBE.service}`), 'the first run did not make its service', runs[0]!.made);
  expect(runs.slice(1).every(({ made }) => made.length === 0), 'a later run made something again', runs.map(({ made }) => made));
  for (const { session, credential } of runs) {
    for (const [what, token] of [['session', session], ['credential', credential]] as const) {
      await refused(`a run's ${what} still worked after it`, bearer(origin, token).me());
    }
  }
  const { tokens } = await admin.api.tokens.list(PROBE.service);
  expect(tokens.length === 0, `${PROBE.service} still holds ${tokens.length} credential(s)`, tokens);
  const place = `${kept.project}/${kept.environment}`;
  const { values } = await admin.api.secrets.reveal(`${place}/${kept.key}`);
  expect(values[kept.key] === kept.value, `${place}/${kept.key}, kept beside the probe's own, was changed`);
  expect((await everythingElse(admin.api)) === before, 'the runs changed a member, a grant, a project or an environment besides their own');
  const { entries } = await admin.api.audit.list({ actor: PROBE.service, limit: 50 });
  expect(entries.length > 0, `the audit log holds no entry by ${PROBE.service}`);
  return `the second run found all; ${runs.length} sessions and credentials refuse; ${PROBE.service} holds none; ${place}/${kept.key} untouched; nothing else changed; ${entries.length} entries by ${PROBE.service} stay`;
}

/** What a credential coffre issues, or a canary, looks like in a run's output. */
const SHOWN = /coffre_(svc|cli|web)_[A-Za-z0-9_-]{8,}|coffre-canary-[0-9a-f]{8,}/;

/**
 * The command itself, `coffre-conformance probe <url> --sign-in`, as the
 * admin approves it, interrupted mid-run by a Ctrl-C: it exits 130 with its
 * credential revoked and its session ended, and nothing it printed shows
 * either, or its canary.
 */
export async function probeInterrupted(origin: string, admin: Person): Promise<string> {
  // The command this process runs as, from its sources or its build.
  const child = spawn(process.execPath, [...process.execArgv, process.argv[1]!, 'probe', origin, '--sign-in'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
  const exited = new Promise<number | null>((resolve) => child.on('exit', (code) => resolve(code)));
  try {
    const waitFor = async (pattern: RegExp, what: string) => {
      for (let tries = 0; !pattern.test(output); tries += 1) {
        expect(tries < 600 && child.exitCode === null, `the probe never got to ${what}`, output);
        await sleep(50);
      }
      return pattern.exec(output)!;
    };
    const [, code] = await waitFor(/shows the code (\S+)\./, 'its device login');
    await admin.api.deviceLogins.decide(code!, true);
    await waitFor(/ok {4}token reveal/, 'its token checks');
    child.kill('SIGINT');
    const status = await exited;
    expect(status === 130, `the interrupted probe exited ${status}, not 130`, output);
  } finally {
    if (child.exitCode === null) child.kill('SIGKILL');
  }
  const { tokens } = await admin.api.tokens.list(PROBE.service);
  expect(tokens.length === 0, `the interrupted run left ${PROBE.service} ${tokens.length} credential(s)`, tokens);
  const { sessions } = await admin.api.sessions.list();
  expect(!sessions.some(({ label }) => label === 'coffre-conformance probe'), "the interrupted run's session was left open", sessions);
  expect(!SHOWN.test(output), 'the probe printed a credential or a canary', SHOWN.exec(output)?.[0]);
  return 'Ctrl-C mid-run: exit 130, its credential revoked and its session ended; nothing it printed shows either, or its canary';
}
