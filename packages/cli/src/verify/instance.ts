// `coffre verify instance`: an instance checked from outside. First as
// anyone on the network sees it; then with a service token that reads one
// canary. The token is the operator's, from CI, with its canary; or, with
// this CLI signed in as an owner or a root admin, one the run issues itself:
// it finds or makes its own place, writes a fresh canary, runs the token's
// checks, then verifies the whole audit log as the owner. However it ends,
// the credential it issued is revoked. The session is the one `coffre login`
// made, and it stays signed in. Neither credential, nor the canary, is ever
// printed or written down.
//
// What stays: the project, the environment and the service, which the next
// run finds, the canary's versions, and the run's entries in the audit log.
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import { CoffreError, createClient, type CoffreClient } from '@coffre/client';

import { secretFile } from '../flags.ts';
import { credentialHeaders, instanceOrigin, resolveTarget, type SessionFlags, type Store } from '../instance.ts';
import { style, type Output } from '../tty.ts';
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
  coffre verify instance [<url>]
  coffre --token-file <path|-> verify instance [<url>] --canary <project>/<environment>/<KEY>
         [--canary-value-file <path|->]

Checks an instance from outside, the current one unless <url> names another:

  as no one        health, headers, every route refusing no one, changes from
                   another site refused, /api/auth, nothing like a value shown
  as an owner      with your \`coffre login\` session, as an owner or a root
                   admin: finds or makes conformance/live and
                   token:conformance-probe, issues it a credential, writes a
                   fresh canary, runs the token's checks below, then verifies
                   the whole audit log as you. The credential is revoked
                   however the run ends, and your session stays signed in
  with a token     a service token in --token-file, for CI, that reads the
                   canary's environment and holds auditor on its project: its
                   value nowhere but its reveal, the reveal audited, nothing
                   else in reach
  --canary         the canary the token reads, and its value after =; or
  --canary-value-file
                   its value, from this file, or stdin for -, so that it
                   stays out of the shell's history

Each run adds a few entries to the instance's audit log, which is
append-only, so they stay: the canary's read, and the reads it was refused.
A run as an owner leaves its project, environment and service for the next,
and writes its canary and its grants. Exits 1 when a check fails.`;

/** What the run issued, to revoke at its end. */
type Issued = { member: string; id: string };

export async function verifyInstance(args: string[], store: Store, session: SessionFlags, out: Output = process.stdout): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { canary: { type: 'string' }, 'canary-value-file': { type: 'string' }, help: { type: 'boolean', short: 'h' } },
  });
  if (values.help) stop(0, INSTANCE_USAGE);
  if (positionals.length > 1) stop(2, INSTANCE_USAGE);
  if (positionals[0] !== undefined && session.url !== undefined) {
    stop(2, 'coffre: name the instance once: coffre verify instance <url>, or coffre --url <url> verify instance');
  }
  // As no one, then with a token, or as you: never as a CI run or through Access.
  const other = (['service', 'idToken', 'accessClientId', 'accessClientSecret'] as const).filter((name) => session[name] !== undefined);
  if (other.length > 0) {
    stop(
      2,
      'coffre: verify instance checks as no one, then with a service token in --token-file, or as you with the session `coffre login` saved: ' +
        '--service, --id-token-file and the Access flags are for other commands',
    );
  }
  const requested = positionals[0] ?? session.url ?? store.current;
  if (!requested) stop(1, 'coffre: not signed in anywhere yet: run `coffre login <url>` first');
  let origin: string;
  try {
    origin = instanceOrigin(requested);
  } catch (error) {
    stop(2, `coffre: ${error instanceof Error ? error.message : String(error)}`);
  }
  const s = style(out);
  const report = new Checks(out);
  const token = session.token;
  const valueFile = values['canary-value-file'];

  if (token !== undefined) {
    if (values.canary === undefined) stop(2, 'coffre: with a token, name its canary: --canary <project>/<environment>/<KEY>[=<value>]');
    if (valueFile !== undefined && values.canary.includes('=')) stop(2, 'coffre: the canary has its value after =, and in --canary-value-file: give one');
    let canary: Canary;
    try {
      canary = parseCanary(values.canary, valueFile === undefined ? undefined : secretFile('--canary-value-file', valueFile));
    } catch (error) {
      stop(2, `coffre: ${error instanceof Error ? error.message : String(error)}`);
    }
    out.write(`${s.bold(`Checking ${origin}`)}, as no one and with the token in --token-file\n`);
    out.write(s.dim("  The token's reads add a few entries to the instance's audit log, for good.\n\n"));
    await anonymousChecks(report, origin);
    await tokenChecks(report, origin, { token, canary });
    return finish(out, report);
  }
  if (values.canary !== undefined || valueFile !== undefined) {
    stop(2, "coffre: --canary goes with a service token in --token-file; as an owner, the run writes a canary of its own");
  }

  // The session `coffre login` made, and none other: no second sign-in.
  if (store.instances[origin] === undefined) stop(1, `coffre: not signed in to ${origin}: run \`coffre login ${origin}\` first`);
  let api: CoffreClient;
  try {
    const to = resolveTarget({ ...session, url: origin, token: undefined }, store);
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
  out.write(`${s.bold(`Checking ${origin}`)}, as no one, then as you\n`);
  out.write(
    s.dim(
      `  It keeps ${PROBE.project}/${PROBE.environment} and ${PROBE.service} for the next run, and its reads stay in the audit log, for good.\n\n`,
    ),
  );
  await anonymousChecks(report, origin);
  await ownerChecks(report, origin, api);
  finish(out, report);
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

/** The session's owner, or a root admin: anyone else is stopped before anything is made. */
async function signedIn(api: CoffreClient, origin: string): Promise<{ detail: string; value: string }> {
  let me;
  try {
    me = await api.me();
  } catch (error) {
    if (error instanceof CoffreError && error.status === 401) {
      throw new Failure(`your session on ${origin} is missing, expired or revoked: run \`coffre login ${origin}\`, then again`);
    }
    throw error;
  }
  const who = me.principal.id;
  if (me.instanceRole === 'user') {
    throw new Failure(`${who} is neither an owner nor a root admin of ${origin}: nothing was made. Sign in as one, or use a service token in --token-file with --canary`);
  }
  return { detail: `${who}, ${me.instanceRole === 'owner' ? 'an owner' : 'a root admin'}, with this CLI's session`, value: who };
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
  if ((await api.members.add(PROBE.service)).created) made.push(`the service ${PROBE.service}`);
  const { changes } = await api.access.set(PROBE.service, { [place]: 'viewer', [PROBE.project]: 'auditor' });
  const granted = Object.entries(changes).filter(([, change]) => change !== 'unchanged');
  if (granted.length > 0) made.push(`its grants on ${granted.map(([where]) => where).join(' and ')}`);
  const value = `coffre-canary-${randomBytes(12).toString('hex')}`;
  await api.secrets.set(place, { [PROBE.key]: value });
  const credential = await api.tokens.issue(PROBE.service, { label: 'coffre verify instance, one run', expiresInDays: 1 });
  issued.push({ member: PROBE.service, id: credential.id });
  return {
    detail: `${made.length === 0 ? 'all found' : `made ${made.join(', ')}`}; a fresh ${place}/${PROBE.key} and a fresh credential for ${PROBE.service}`,
    value: { token: credential.token, canary: { project: PROBE.project, environment: PROBE.environment, key: PROBE.key, value } },
  };
}

/** What the whole audit chain says, read by the owner, which a token cannot be. */
async function verification(api: CoffreClient): Promise<string> {
  const verified = await api.audit.verify();
  expect(verified.ok, 'the audit log does not verify', verified);
  return `the whole chain verifies, as you: ${verified.entries} entries, through entry ${verified.through}`;
}

/** Revoke what the run issued, and say what stays: the session among it. */
async function cleanUp(api: CoffreClient, issued: Issued[]): Promise<string> {
  for (const { member, id } of issued) await api.tokens.revoke(member, id);
  const { tokens } = await api.tokens.list(PROBE.service).catch(() => ({ tokens: [] as unknown[] }));
  const others = tokens.length === 0 ? 'no working credential' : `${tokens.length} credential${tokens.length === 1 ? '' : 's'} this run did not issue, left as they are`;
  return (
    `${issued.length === 0 ? 'nothing issued' : 'the credential revoked'}; your session stays. Staying: ${PROBE.project}/${PROBE.environment} and its ` +
    `${PROBE.key}, ${PROBE.service} with ${others}, and this run's entries in the audit log`
  );
}

/** The verdict, under the checks, and the exit code: 0 when every one passed, or was skipped for a reason given. */
function finish(out: Output, report: Checks): void {
  const s = style(out);
  const { failed } = report;
  out.write(failed.length === 0 ? `\n${s.green('✓')} ${s.bold('Conformant')}\n` : `\n${s.red('✗')} ${s.bold('Not conformant:')} ${failed.join(', ')}\n`);
  process.exitCode = failed.length === 0 ? 0 : 1;
}
