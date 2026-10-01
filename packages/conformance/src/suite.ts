// The checks, in the order they build on each other: people first, then
// what they may do, then what was written down, and last the tampering,
// which leaves the audit log broken for good.
import type { Deployment } from './harness.ts';
import { Report } from './report.ts';
import { bulkLimit, crossSite, grantScoping, membersOnly, offboarding } from './checks/access.ts';
import { checkpoints, deletedTail, forgedVaultEntry, missingEntry, noAuditNoValue, revealAudited, rewrittenEntry, verification, writesAgree } from './checks/audit.ts';
import { earlierCheckpoint } from './checks/checkpoints.ts';
import { appLogin, vaultLogin } from './checks/logins.ts';
import { accessAuthorship, memberTampering, noAuditNoAccess } from './checks/members.ts';
import { refusedCheckpoint, missingCheckpoint } from './checks/readiness.ts';
import { editedGeneration, forgedCredential, forgedIdentity, forgedApproval } from './checks/signin.ts';
import { canaryScan } from './checks/canaries.ts';
import { anonymousChecks, tokenChecks, type Canary } from './checks/live.ts';
import { personas, setUp, setUpLive, signInAdmin } from './checks/people.ts';
import { health } from './checks/surface.ts';

/** The names of the checks that failed. */
export async function conform(deployment: Deployment, options: { bulkLimit: number }): Promise<string[]> {
  const report = new Report();
  await report.check('health', {}, () => health(deployment));
  // What `probe` checks of a running instance, from outside: as no one, and
  // with a token reading one canary. The rest needs this run's own keys,
  // database and processes.
  await anonymousChecks(report, deployment.origin, { health: false });
  const admin = await report.check('sign-in', {}, () => signInAdmin(deployment));
  const canaries = await report.check('setup', { admin }, ({ admin }) => setUp(admin));
  const people = await report.check('personas', { admin, canaries }, ({ admin }) => personas(deployment, admin));
  const all = { people, canaries };

  await report.check('members only', { people }, ({ people }) => membersOnly(deployment, people));
  await report.check('grant scoping', all, ({ people, canaries }) => grantScoping(people, canaries));
  await report.check('reveals audited', all, ({ people, canaries }) => revealAudited(people, canaries, 'reveal', deployment));
  await report.check('runs audited', all, ({ people, canaries }) => revealAudited(people, canaries, 'run', deployment));
  await report.check('cross-site', all, ({ people, canaries }) => crossSite(people, canaries));
  const live = await report.check('live setup', { admin, canaries }, ({ admin, canaries }) => setUpLive(admin, canaries));
  await tokenChecks(report, deployment.origin, live ?? {});
  await report.check('offboarding', all, ({ people, canaries }) => offboarding(deployment, people, canaries));
  await report.check('bulk limit', { people }, ({ people }) => bulkLimit(people, options.bulkLimit));

  await report.check('checkpoints', { people }, ({ people }) => checkpoints(deployment, people));
  await report.check('keys behind writes', { people }, ({ people }) => writesAgree(deployment));
  await report.check('no audit, no value', all, ({ people, canaries }) => noAuditNoValue(deployment, people, canaries));

  await report.check('access authorship', { people }, ({ people }) => accessAuthorship(deployment, people));
  await report.check('no audit, no access', { people }, ({ people }) => noAuditNoAccess(deployment, people));
  await report.check('full verification', { people }, ({ people }) => verification(deployment, people));
  await report.check('checkpoint refused', {}, () => refusedCheckpoint(deployment));
  await report.check('checkpoint missing', {}, () => missingCheckpoint(deployment));
  await report.check('app login', {}, () => appLogin(deployment));
  await report.check('vault login', {}, () => vaultLogin(deployment));
  for (const kind of ['grant', 'member', 'old'] as const) {
    await report.check(`${kind} tampering`, { people }, ({ people }) => memberTampering(deployment, people, kind));
  }
  await report.check('forged credential', { people }, ({ people }) => forgedCredential(deployment, people));
  await report.check('forged identity', { people }, ({ people }) => forgedIdentity(deployment, people));
  await report.check('forged approval', { people }, ({ people }) => forgedApproval(deployment, people));
  await report.check('edited generation', { people }, ({ people }) => editedGeneration(deployment, people));
  await report.check('canary scan', all, ({ people, canaries }) => canaryScan(deployment, people, canaries));
  for (const author of ['app', 'vault'] as const) {
    await report.check(`${author} rewritten`, { people }, ({ people }) => rewrittenEntry(deployment, people, author));
  }
  await report.check('vault forged', { people }, ({ people }) => forgedVaultEntry(deployment, people));
  await report.check('middle deleted', { people }, ({ people }) => missingEntry(deployment, people));
  await report.check('first gap', { people }, ({ people }) => missingEntry(deployment, people, 'first'));
  await report.check('batch gap', { people }, ({ people }) => missingEntry(deployment, people, 'batch'));
  await report.check('earlier checkpoint', { people }, ({ people }) => earlierCheckpoint(deployment, people));
  await report.check('tail deleted', { people }, ({ people }) => deletedTail(deployment, people));
  return report.failed;
}

/**
 * What can be checked of an instance someone else runs: as no one, and with
 * a token that reads a canary when given one. Nothing is written but the
 * audit log's entries for the token's reads.
 */
export async function probe(origin: string, live: { token?: string; canary?: Canary }): Promise<string[]> {
  const report = new Report();
  await anonymousChecks(report, origin, { health: true });
  if (live.token !== undefined) await tokenChecks(report, origin, live);
  return report.failed;
}
