// `coffre verify instance`: an instance checked from outside. First as
// anyone on the network sees it; then with a bearer token that reads one
// canary. The token is the operator's, from CI, with its canary; or, with
// this CLI signed in as an admin or owner of the whole instance, one the run issues itself:
// it finds or makes its own place, writes a fresh canary, runs the token's
// checks, then verifies the whole audit log as the owner. However it ends,
// the credential it issued is revoked. The session is the one `coffre login`
// made, and it stays signed in. Neither credential, nor the canary, is ever
// printed or written down.
//
// What stays: the project, the environment and the service, which the next
// run finds, the canary's versions, and the run's entries in the audit log.
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { CoffreError, createClient, shownMember, type CoffreClient } from '@coffre/client';

import { readSecret } from '../secret.ts';
import { askedMode, credentialHeaders, instanceOrigin, REPO_FILE, resolveTarget, SIGN_IN_HINT, signInError, type Local, type SessionFlags, type Store } from '../instance.ts';
import { Cancelled, openTerminal, release, style, yes, type Output } from '../tty.ts';
import { anonymousChecks } from './anonymous.ts';
import { Checks, expect, Failure, stop } from './checks.ts';
import { parseCanary, tokenChecks, type Canary } from './token.ts';

/** The run's own place on an instance, made the first time, and found after. Nothing else is touched. */
export const PROBE = {
  project: 'conformance',
  environment: 'live',
  service: 'token:conformance-probe',
  // Its own key, beside a CANARY an operator may keep for a run with a token from CI.
  key: 'SIGN_IN_CANARY',
} as const;

export const INSTANCE_USAGE = `usage:
  coffre verify instance <url> [--yes]
  coffre verify instance <url> --canary <project>/<environment>/<KEY>, signed in with a bearer token

Checks the instance <url> names from outside. It never takes the default
session's instance for the one you mean: without <url> (or --url), it runs only
where a \`coffre.json\` or a pin (\`coffre login <url>\` in the directory makes
one) names the instance, and then only with that instance's own session.

  as no one        health, headers, every route refusing no one, changes from
                   another site refused, /api/auth, nothing like a value shown
  as an owner      with your \`coffre login\` session, as an owner or a root
                   admin: finds or makes conformance/live and
                   service:conformance-probe, issues it a credential, writes a
                   fresh canary, runs the token's checks below, then verifies
                   the whole audit log as you. The credential is revoked
                   however the run ends, and your session stays signed in
  with a token     signed in with a bearer token, \`coffre login <url> --token\`,
                   as CI is: one that reads the canary's environment and
                   holds auditor on its project. Its value nowhere but its
                   reveal, the reveal audited, nothing else in reach
  --canary         the canary the token reads; its value is asked for, or
                   piped in, so that it stays out of the shell's history

Before it writes anything as an owner, it prints the instance and who is signed
in, and asks you to confirm on a terminal. Without one it refuses, unless
--yes says so. Nothing is sent to the instance before that.

Each run adds a few entries to the instance's audit log, which is
append-only, so they stay: the canary's read, and the reads it was refused.
A run as an owner leaves its project, environment and service for the next,
and writes its canary and its grants. Exits 1 when a check fails.`;

/** What the run issued, to revoke at its end. */
type Issued = { member: string; id: string };

/**
 * The instance a run means, and why: named on the command line, or by where it runs (a `coffre.json`, or a pin,
 * which `coffre login <url>` in a directory makes). Never the default session's: the run writes, so it is told where, or it stops.
 */
export function namedInstance(positional: string | undefined, session: SessionFlags, local: () => Local | null, current: string | null): { requested: string; why: string } {
  const explicit = positional ?? session.url;
  if (explicit !== undefined) return { requested: explicit, why: 'named on the command line' };
  // What names it where the command runs is read only now: a broken file there is no matter to one that names its instance.
  const here = local();
  if (here === null) {
    const unasked = current === null ? '' : ` The default session, ${current}, is not used unasked.`;
    stop(
      2,
      'coffre: verify instance creates a project, an environment, a service account, grants and a secret on the instance it checks, and walks its whole audit log, ' +
        `so it never picks one for you: name it, \`coffre verify instance <url>\`, or run it where a ${REPO_FILE} or a pin (\`coffre login <url>\` here) names it.${unasked}`,
    );
  }
  return { requested: here.origin, why: here.by === 'pin' ? `this directory is pinned at ${here.directory}` : `${join(here.directory, REPO_FILE)} names it` };
}

export async function verifyInstance(
  args: string[],
  store: Store,
  session: SessionFlags,
  local: () => Local | null,
  out: Output = process.stdout,
): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { canary: { type: 'string' }, yes: { type: 'boolean', short: 'y' }, help: { type: 'boolean', short: 'h' } },
  });
  if (values.help) stop(0, INSTANCE_USAGE);
  if (positionals.length > 1) stop(2, INSTANCE_USAGE);
  if (positionals[0] !== undefined && session.url !== undefined) {
    stop(2, 'coffre: name the instance once: coffre verify instance <url>, or coffre --url <url> verify instance');
  }
  // As no one, then with a bearer token, or as you: never as a CI run's ID token.
  if (session.service !== undefined) {
    stop(
      2,
      'coffre: verify instance checks as no one, then with a bearer token `coffre login --token` saved, or as you with the session `coffre login` saved: ' +
        '--service is for other commands',
    );
  }
  const { requested, why } = namedInstance(positionals[0], session, local, store.current);
  let origin: string;
  try {
    origin = instanceOrigin(requested);
  } catch (error) {
    stop(2, `coffre: ${error instanceof Error ? error.message : String(error)}`);
  }
  const s = style(out);
  const report = new Checks(out);
  const saved = store.instances[origin];
  if (saved?.kind === 'access' || saved?.kind === 'run') {
    stop(2, `coffre: verify instance checks as no one, then with a bearer token, or as you: the session saved for ${origin} is ${saved.kind === 'access' ? 'an Access service token' : "a run's ID token"}`);
  }

  if (saved?.kind === 'token' && saved.token !== undefined) {
    const token = saved.token;
    if (values.canary === undefined) stop(2, 'coffre: with a token, name its canary: --canary <project>/<environment>/<KEY>');
    if (values.canary.includes('=')) stop(2, "coffre: the canary's value is asked for, never an argument: paste it, or pipe it in");
    let canary: Canary;
    try {
      // The path, checked before its value is asked for.
      parseCanary(values.canary, '-');
      canary = parseCanary(values.canary, await readSecret({ label: 'Canary value', hint: `The value of ${values.canary}, which the token reads. Hidden as you type.` }));
    } catch (error) {
      stop(2, `coffre: ${error instanceof Error ? error.message : String(error)}`);
    }
    out.write(`${s.bold(`Checking ${origin}`)}, as no one and with the bearer token \`coffre login --token\` saved\n`);
    out.write(s.dim("  The token's reads add a few entries to the instance's audit log, for good.\n\n"));
    await anonymousChecks(report, origin);
    await tokenChecks(report, origin, { token, canary });
    return finish(out, report);
  }
  if (values.canary !== undefined) {
    stop(2, 'coffre: --canary goes with a bearer token, `coffre login <url> --token`; as an owner, the run writes a canary of its own');
  }

  // The session `coffre login` made for this instance, and none other: no second sign-in, and never another instance's.
  if (saved === undefined) {
    const by = why === 'named on the command line' ? '' : ` (${why})`;
    stop(1, `coffre: ${signInError(`not signed in: run \`coffre login ${origin}\` first${by}`, askedMode(session.authMode))}`);
  }
  let api: CoffreClient;
  try {
    const to = resolveTarget({ ...session, url: origin }, store);
    if (to.mode === 'cloudflare') {
      stop(
        1,
        `coffre: ${origin} is behind Cloudflare Access, which turns everyone away before coffre answers, so it cannot be checked from outside. ` +
          '`coffre verify log` verifies its audit log, as you.',
      );
    }
    api = createClient({ url: origin, headers: () => credentialHeaders(to.mode, to.credential) });
  } catch (error) {
    stop(1, `coffre: ${error instanceof Error ? error.message : String(error)}`);
  }
  await confirm(out, { origin, why, principal: saved.principal?.id ?? null, yes: values.yes === true });
  out.write(`${s.bold(`Checking ${origin}`)}, as no one, then as you\n`);
  out.write(
    s.dim(
      `  It keeps ${PROBE.project}/${PROBE.environment} and ${shownMember(PROBE.service)} for the next run, and its reads stay in the audit log, for good.\n\n`,
    ),
  );
  await anonymousChecks(report, origin);
  await ownerChecks(report, origin, api);
  finish(out, report);
}

/**
 * Before the run writes as an owner: the instance and who is signed in, said, and a yes, from a terminal, or `--yes`.
 * Without either it stops, having sent nothing.
 */
async function confirm(out: Output, to: { origin: string; why: string; principal: string | null; yes: boolean }): Promise<void> {
  const s = style(out);
  out.write(`${s.bold('Writes to')} ${to.origin} ${s.dim(`(${to.why})`)}\n`);
  out.write(`${s.bold('Signed in as')} ${to.principal ?? 'someone the saved session does not name'}, with this CLI's session\n`);
  out.write(
    s.dim(
      `  It makes ${PROBE.project}/${PROBE.environment}, ${shownMember(PROBE.service)}, their grants and a canary there if they are missing, and walks the whole audit log.\n`,
    ),
  );
  if (to.yes) {
    out.write(s.dim('  --yes: going on.\n\n'));
    return;
  }
  const terminal = openTerminal();
  if (terminal === null) {
    stop(2, `coffre: not on a terminal to ask: nothing was sent to ${to.origin}. Run it again with --yes to write there`);
  }
  terminal.out.write(`${s.accent('?')} ${s.bold(`Write to ${to.origin}?`)} ${s.dim('y/N')} `);
  let confirmed: boolean;
  try {
    confirmed = await yes(terminal.keys);
  } catch (error) {
    if (error instanceof Cancelled) process.exit(130);
    throw error;
  } finally {
    release(terminal.keys);
  }
  terminal.out.write(`${confirmed ? 'yes' : 'no'}\n\n`);
  if (!confirmed) stop(1, `coffre: not confirmed: nothing was sent to ${to.origin}`);
}

/**
 * As the signed-in owner: who they are, set up, the token's checks,
 * verification; and, however it ends, a Ctrl-C included, the credential
 * revoked. The session stays as it was.
 */
export async function ownerChecks(report: Checks, origin: string, api: CoffreClient): Promise<void> {
  const owner = await report.check('owner', {}, () => signedIn(api, origin));
  if (owner === undefined) return;
  const issued: Issued[] = [];
  let ended: Promise<string> | null = null;
  const end = () => (ended ??= cleanUp(api, issued));
  // Ctrl-C, or a SIGTERM: the credential goes before the process does.
  const interrupted = (code: number) => () => void end().finally(() => process.exit(code));
  const onInt = interrupted(130);
  const onTerm = interrupted(143);
  process.once('SIGINT', onInt);
  process.once('SIGTERM', onTerm);
  try {
    const live = await report.check('setup', {}, () => setUp(api, issued));
    // Without the token's own verification, which it can only skip: the owner verifies the whole chain next.
    await tokenChecks(report, origin, live ?? {}, { verification: false });
    await report.check('owner verification', {}, () => verification(api));
  } finally {
    process.off('SIGINT', onInt);
    process.off('SIGTERM', onTerm);
    await report.check('clean-up', {}, end);
  }
}

/** The session's admin or owner of the whole instance: anyone else is stopped before anything is made. */
async function signedIn(api: CoffreClient, origin: string): Promise<{ detail: string; value: string }> {
  let me;
  try {
    me = await api.me();
  } catch (error) {
    if (error instanceof CoffreError && error.status === 401) {
      throw new Failure(`your session on ${origin} is missing, expired or revoked: run \`coffre login ${origin}\`, then again`, SIGN_IN_HINT);
    }
    throw error;
  }
  const who = me.principal.id;
  if (!me.runsInstance) {
    throw new Failure(`${who} is not an admin or owner of all of ${origin}: nothing was made. Sign in as one, or with a bearer token, \`coffre login ${origin} --token\`, and name its --canary`);
  }
  return { detail: `${who}, ${/^[aeiou]/.test(me.instanceRole) ? 'an' : 'a'} ${me.instanceRole}, with this CLI's session`, value: who };
}

/** Make what is missing of the run's place, and the service's two grants; then a fresh canary, and a fresh credential. */
async function setUp(api: CoffreClient, issued: Issued[]): Promise<{ detail: string; value: { token: string; canary: Canary } }> {
  const place = `${PROBE.project}/${PROBE.environment}`;
  const made: string[] = [];
  const { projects } = await api.projects.list();
  const project = projects.find(({ slug }) => slug === PROBE.project);
  expect(project?.archivedAt == null, `${PROBE.project} is archived: unarchive it, or the run has nowhere to go`);
  if (project === undefined) {
    await api.projects.create(PROBE.project, { name: 'Conformance' });
    made.push(`the project ${PROBE.project}`);
  }
  const environment = project?.environments.find(({ slug }) => slug === PROBE.environment);
  expect(environment?.details?.archivedAt == null, `${place} is archived: unarchive it, or the run has nowhere to go`);
  if (environment === undefined) {
    await api.environments.create(place, { name: 'Live' });
    made.push(`the environment ${place}`);
  }
  if ((await api.members.add(PROBE.service)).created) made.push(`the service account ${shownMember(PROBE.service)}`);
  const { changes } = await api.access.set(PROBE.service, { [place]: 'viewer', [PROBE.project]: 'auditor' });
  const granted = Object.entries(changes).filter(([, change]) => change !== 'unchanged');
  if (granted.length > 0) made.push(`its grants on ${granted.map(([where]) => where).join(' and ')}`);
  const value = `coffre-canary-${randomBytes(12).toString('hex')}`;
  await api.secrets.set(place, { [PROBE.key]: value });
  const credential = await api.tokens.issue(PROBE.service, { label: 'coffre verify instance, one run', expiresInDays: 1 });
  issued.push({ member: PROBE.service, id: credential.id });
  return {
    detail: `${made.length === 0 ? 'all found' : `made ${made.join(', ')}`}; a fresh ${place}/${PROBE.key} and a fresh credential for ${shownMember(PROBE.service)}`,
    value: { token: credential.token, canary: { project: PROBE.project, environment: PROBE.environment, key: PROBE.key, value } },
  };
}

/** What the whole audit chain says, walked from its first entry by the owner, which a token cannot be. */
async function verification(api: CoffreClient): Promise<string> {
  const verified = await api.audit.verifyWhole();
  expect(verified.ok, 'the audit log does not verify', verified);
  // A server older than 0.10.1 says nothing of what it left, and walked it all.
  expect((verified.remaining ?? 0) === 0, 'the audit log is not verified to its end: the checkpoints are catching up', verified);
  // 0.15's log, where the instance keeps it: its newest checkpoint and every entry since, as the audit page checks it.
  const trees = await api.audit.verifyTrees();
  expect(!trees.kept || trees.problems.length === 0, "0.15's log does not verify from its newest checkpoint", trees);
  // Not checked to its head, as 0.14's checkpoints catching up above: a checkpointer behind, no break of the log, and
  // no pass either (review r4 of W240).
  expect(!trees.kept || !trees.capped, "0.15's log is not checked to its head: more entries wait above its newest checkpoint than a check reads, the checkpointer behind", trees);
  const sealed = !trees.kept ? '' : trees.checkpoint === null ? "; 0.15's log too, nothing sealed yet" : `; 0.15's log too, from its newest checkpoint, up to entry ${trees.checkpoint.upto}`;
  return `the whole chain verifies, as you: ${verified.entries} entries, through entry ${verified.through}${sealed}`;
}

/** Revoke what the run issued, and say what stays: the session among it. */
async function cleanUp(api: CoffreClient, issued: Issued[]): Promise<string> {
  for (const { member, id } of issued) await api.tokens.revoke(member, id);
  const { tokens } = await api.tokens.list(PROBE.service).catch(() => ({ tokens: [] as unknown[] }));
  const others = tokens.length === 0 ? 'no working credential' : `${tokens.length} credential${tokens.length === 1 ? '' : 's'} this run did not issue, left as they are`;
  return (
    `${issued.length === 0 ? 'nothing issued' : 'the credential revoked'}; your session stays. Staying: ${PROBE.project}/${PROBE.environment} and its ` +
    `${PROBE.key}, ${shownMember(PROBE.service)} with ${others}, and this run's entries in the audit log`
  );
}

/** The verdict, under the checks, and the exit code: 0 when every one passed, or was skipped for a reason given. */
function finish(out: Output, report: Checks): void {
  const s = style(out);
  const { failed } = report;
  out.write(failed.length === 0 ? `\n${s.green('✓')} ${s.bold('Conformant')}\n` : `\n${s.red('✗')} ${s.bold('Not conformant:')} ${failed.join(', ')}\n`);
  process.exitCode = failed.length === 0 ? 0 : 1;
}
