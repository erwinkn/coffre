// The checks, in the order they build on each other: people first, then
// what they may do, then what was written down, and last the tampering,
// which leaves the audit log broken for good.
import type { Deployment } from './harness.ts';
import { Report } from './report.ts';
import { bulkLimit, crossSite, grantScoping, membersOnly, offboarding } from './checks/access.ts';
import { appendOnly, checkpoints, logsAgree, noAuditNoValue, revealAudited, tamperApp, tamperVault } from './checks/audit.ts';
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
  await report.check('reveals audited', all, ({ people, canaries }) => revealAudited(people, canaries));
  await report.check('cross-site', all, ({ people, canaries }) => crossSite(people, canaries));
  const live = await report.check('live setup', { admin, canaries }, ({ admin, canaries }) => setUpLive(admin, canaries));
  await tokenChecks(report, deployment.origin, live ?? {});
  await report.check('offboarding', all, ({ people, canaries }) => offboarding(deployment, people, canaries));
  await report.check('bulk limit', { people }, ({ people }) => bulkLimit(people, options.bulkLimit));

  // The two logs agree only until the check after: the vault logs the keys
  // it opens for a reveal that the audit log then refuses.
  await report.check('checkpoints', { people }, ({ people }) => checkpoints(deployment, people));
  await report.check('two logs agree', { people }, ({ people }) => logsAgree(people));
  await report.check('no audit, no value', all, ({ people, canaries }) => noAuditNoValue(deployment, people, canaries));

  await report.check('canary scan', all, ({ people, canaries }) => canaryScan(deployment, people, canaries));
  await report.check('append-only', {}, () => appendOnly(deployment));
  await report.check('vault tampering', { people }, ({ people }) => tamperVault(deployment, people));
  await report.check('app tampering', { people }, ({ people }) => tamperApp(deployment, people));
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
