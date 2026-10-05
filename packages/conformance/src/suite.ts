// The checks, in the order they build on each other: people first, then
// what they may do, then what was written down, and last the tampering,
// which leaves the audit log broken for good.
import type { Deployment } from './harness.ts';
import { Report } from './report.ts';
import { bulkLimit, crossSite, everyProject, grantScoping, membersOnly, offboarding } from './checks/access.ts';
import { checkpoints, deletedTail, forgedVaultEntry, missingEntry, noAuditNoValue, revealAudited, rewrittenEntry, verification, writesAgree } from './checks/audit.ts';
import { earlierCheckpoint } from './checks/checkpoints.ts';
import { deletion } from './checks/deletion.ts';
import { appLogin, vaultLogin } from './checks/logins.ts';
import { accessAuthorship, memberTampering, noAuditNoAccess, sealingRace } from './checks/members.ts';
import { refusedCheckpoint, missingCheckpoint, middleCut } from './checks/readiness.ts';
import { editedGeneration, forgedCredential, forgedIdentity, forgedApproval } from './checks/signin.ts';
import { canaryScan } from './checks/canaries.ts';
import { Cli, cliLogin, manageByCli, verifyAsOwner, verifyAsUser, verifyInterrupted, verifyKeys, verifyLeftovers, verifyWithToken } from './checks/cli.ts';
import { pageLoad, personas, setUp, setUpLive, signInAdmin } from './checks/people.ts';
import { pagesInBrowser, signinErrorOnce } from './checks/pages.ts';
import { browserBundle, headers, health } from './checks/surface.ts';
import { cliSignsIn, exchangesLimited, runSignsIn, runsRefused, runUnbound, spentOnce, tokensUnlogged, trustRun } from './checks/workloads.ts';

/** The names of the checks that failed. */
export async function conform(deployment: Deployment, options: { bulkLimit: number; browser: string | null }): Promise<string[]> {
  const report = new Report();
  await report.check('health', {}, () => health(deployment));
  await report.check('browser bundle', {}, () => browserBundle(deployment));
  const admin = await report.check('sign-in', {}, () => signInAdmin(deployment));
  await report.check('page load', { admin }, ({ admin }) => pageLoad(admin));
  await report.check('security headers', { admin }, ({ admin }) => headers(deployment, admin));
  const canaries = await report.check('setup', { admin }, ({ admin }) => setUp(admin));
  await report.check('pages in a browser', { admin, canaries }, ({ admin }) => pagesInBrowser(deployment, admin, options.browser));
  await report.check('sign-in error, once', { admin }, ({ admin }) => signinErrorOnce(deployment, admin, options.browser));
  const people = await report.check('personas', { admin, canaries }, ({ admin }) => personas(deployment, admin));
  const all = { people, canaries };

  await report.check('members only', { people }, ({ people }) => membersOnly(deployment, people));
  await report.check('grant scoping', all, ({ people, canaries }) => grantScoping(people, canaries));
  await report.check('reveals audited', all, ({ people, canaries }) => revealAudited(deployment, people, canaries, 'reveal'));
  await report.check('runs audited', all, ({ people, canaries }) => revealAudited(deployment, people, canaries, 'run'));
  await report.check('cross-site', all, ({ people, canaries }) => crossSite(people, canaries));
  const live = await report.check('live setup', { admin, canaries }, ({ admin, canaries }) => setUpLive(admin, canaries));
  // `coffre verify`, as an operator runs it against an instance: with a
  // token from CI; then signed in with `coffre login`, a user turned away,
  // the admin twice, interrupted, and what stays; and the keys.
  const clis = [new Cli(deployment.origin), new Cli(deployment.origin), new Cli(deployment.origin)] as const;
  try {
    await report.check('verify with a token', { live }, ({ live }) => verifyWithToken(clis[0], live));
    const user = await report.check('login as a user', { people }, ({ people }) => cliLogin(clis[1], people.reader));
    const before = await report.check('verify as a user', { admin, people, user }, ({ admin, people, user }) => verifyAsUser(user, people.reader, admin));
    const owner = await report.check('login as the admin', { admin, before }, ({ admin }) => cliLogin(clis[2], admin));
    const first = await report.check('verify as the admin', { owner }, ({ owner }) => verifyAsOwner(owner));
    const second = await report.check('verify again', { owner, first }, ({ owner }) => verifyAsOwner(owner));
    await report.check('verify interrupted', { admin, owner, second }, ({ admin, owner }) => verifyInterrupted(owner, admin));
    await report.check('verify leftovers', { admin, owner, before, first, second, live }, ({ admin, owner, before, first, second, live }) =>
      verifyLeftovers(owner, admin, [first, second], before, live.canary),
    );
    await report.check('verify keys', { owner }, ({ owner }) => verifyKeys(owner));
    await report.check('manage by CLI', { owner }, ({ owner }) => manageByCli(owner));
    await report.check('delete by CLI', { owner, admin }, ({ owner, admin }) => deletion(deployment, owner, admin));
  } finally {
    for (const cli of clis) cli.remove();
  }
  await report.check('offboarding', all, ({ people, canaries }) => offboarding(deployment, people, canaries));
  await report.check('grants on every project', all, ({ people, canaries }) => everyProject(deployment, people, canaries));
  await report.check('bulk limit', { people }, ({ people }) => bulkLimit(people, options.bulkLimit));
  // A CI run signing in with its ID token, through a binding. The limit
  // comes last of these: it spends this address's exchanges for the minute.
  const binding = await report.check('trust a run', { admin }, ({ admin }) => trustRun(deployment, admin));
  const credential = await report.check('run signs in', { admin, canaries, binding }, ({ admin, canaries }) => runSignsIn(deployment, admin, canaries));
  await report.check('run token spent', { binding }, () => spentOnce(deployment));
  await report.check('runs refused', { admin, binding }, ({ admin }) => runsRefused(deployment, admin));
  await report.check('run signs in by CLI', { canaries, binding }, ({ canaries }) => cliSignsIn(deployment, canaries));
  await report.check('run unbound', { admin, binding, credential }, ({ admin, binding, credential }) => runUnbound(deployment, admin, binding, credential));
  await report.check('exchanges limited', { binding }, () => exchangesLimited(deployment));
  await report.check('tokens unlogged', { binding }, () => tokensUnlogged(deployment));

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
  await report.check('forged grant', { people }, ({ people }) => memberTampering(deployment, people, 'grant'));
  await report.check('forged member', { people }, ({ people }) => memberTampering(deployment, people, 'member'));
  await report.check('stale member', { people }, ({ people }) => memberTampering(deployment, people, 'stale'));
  await report.check('sealing race', { people }, ({ people }) => sealingRace(deployment, people));
  await report.check('forged credential', { people }, ({ people }) => forgedCredential(deployment, people));
  await report.check('forged identity', { people }, ({ people }) => forgedIdentity(deployment, people));
  await report.check('forged approval', { people }, ({ people }) => forgedApproval(deployment, people));
  await report.check('edited generation', { people }, ({ people }) => editedGeneration(deployment, people));
  await report.check('canary scan', all, ({ people, canaries }) => canaryScan(deployment, people, canaries));
  for (const author of ['app', 'vault'] as const) {
    await report.check(`${author} rewritten`, { people }, ({ people }) => rewrittenEntry(deployment, people, author));
  }
  await report.check('vault forged', { people }, ({ people }) => forgedVaultEntry(deployment, people));
  await report.check('middle gap', { people }, ({ people }) => missingEntry(deployment, people, 'middle'));
  await report.check('middle cut', { people }, ({ people }) => middleCut(deployment, people));
  await report.check('first gap', { people }, ({ people }) => missingEntry(deployment, people, 'first'));
  await report.check('batch gap', { people }, ({ people }) => missingEntry(deployment, people, 'batch'));
  await report.check('earlier checkpoint', { people }, ({ people }) => earlierCheckpoint(deployment, people));
  await report.check('tail deleted', { people }, ({ people }) => deletedTail(deployment, people));
  return report.failed;
}
