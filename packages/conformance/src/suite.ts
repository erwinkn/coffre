// The checks, in the order they build on each other: people first, then
// what they may do, then what was written down, and last the tampering,
// which leaves the audit log broken for good.
import type { Deployment } from './harness.ts';
import { Report } from './report.ts';
import { bulkLimit, crossSite, grantScoping, membersOnly, offboarding } from './checks/access.ts';
import { appendOnly, checkpoints, logsAgree, noAuditNoValue, revealAudited, tamper } from './checks/audit.ts';
import { canaryScan } from './checks/canaries.ts';
import { personas, setUp, signInAdmin } from './checks/people.ts';
import { headers, health, reachable } from './checks/surface.ts';

/** The names of the checks that failed. */
export async function conform(deployment: Deployment, options: { bulkLimit: number }): Promise<string[]> {
  const report = new Report();
  await report.check('health', {}, () => health(deployment));
  await report.check('headers', {}, () => headers(deployment.origin));
  const admin = await report.check('sign-in', {}, () => signInAdmin(deployment));
  const canaries = await report.check('setup', { admin }, ({ admin }) => setUp(admin));
  const people = await report.check('personas', { admin, canaries }, ({ admin }) => personas(deployment, admin));
  const all = { people, canaries };

  await report.check('members only', { people }, ({ people }) => membersOnly(deployment, people));
  await report.check('grant scoping', all, ({ people, canaries }) => grantScoping(people, canaries));
  await report.check('reveals audited', all, ({ people, canaries }) => revealAudited(people, canaries));
  await report.check('cross-site', all, ({ people, canaries }) => crossSite(people, canaries));
  await report.check('offboarding', all, ({ people, canaries }) => offboarding(deployment, people, canaries));
  await report.check('bulk limit', { people }, ({ people }) => bulkLimit(people, options.bulkLimit));

  // The two logs agree only until the check after: the vault logs the keys
  // it opens for a reveal that the audit log then refuses.
  await report.check('checkpoints', { people }, ({ people }) => checkpoints(deployment, people));
  await report.check('two logs agree', { people }, ({ people }) => logsAgree(people));
  await report.check('no audit, no value', all, ({ people, canaries }) => noAuditNoValue(deployment, people, canaries));

  await report.check('canary scan', all, ({ people, canaries }) => canaryScan(deployment, people, canaries));
  await report.check('append-only', {}, () => appendOnly(deployment));
  await report.check('tampering', { people }, ({ people }) => tamper(deployment, people));
  return report.failed;
}

/** What can be checked of an instance someone else runs, without signing in. */
export async function probe(origin: string): Promise<string[]> {
  const report = new Report();
  await report.check('health', {}, () => reachable(origin));
  await report.check('headers', {}, () => headers(origin));
  return report.failed;
}
