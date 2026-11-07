// The checks, in the order they build on each other: people first, then
// what they may do, then what was written down, and last the tampering,
// which leaves the audit log broken for good.
import type { Deployment } from './harness.ts';
import { Report } from './report.ts';
import { bulkLimit, crossSite, grantScoping, instanceRoles, membersOnly, offboarding } from './checks/access.ts';
import { checkpoints, deletedTail, forgedVaultEntry, missingEntry, noAuditNoValue, revealAudited, rewrittenEntry, verification, writesAgree } from './checks/audit.ts';
import { earlierCheckpoint } from './checks/checkpoints.ts';
import { deletion } from './checks/deletion.ts';
import { folders, forks, inheritance, loosening, missingKeys, personalConfigs, references } from './checks/environments.ts';
import { appLogin, hotLogin, vaultLogin } from './checks/logins.ts';
import { mcpRead, mcpChanges, mcpConnect, mcpValues } from './checks/mcp.ts';
import { backToOptional, ceremonies, ipPublicUrl, issuerReplaced, leaveAlone, passkeyChanges, passkeysRequired, readsStayReads, requiredFromCold, staleSession } from './checks/passkeys.ts';
import { accessAuthorship, memberTampering, noAuditNoAccess, sealingRace } from './checks/members.ts';
import { refusedCheckpoint, missingCheckpoint, middleCut } from './checks/readiness.ts';
import { editedGeneration, forgedCredential, forgedIdentity, forgedApproval } from './checks/signin.ts';
import { canaryScan } from './checks/canaries.ts';
import { Cli, cliLogin, manageByCli, verifyAsOwner, verifyAsUser, verifyInterrupted, verifyKeys, verifyLeftovers, verifyWithToken } from './checks/cli.ts';
import { pageLoad, personas, setUp, setUpLive } from './checks/people.ts';
import { pagesInBrowser, pastedValues, signinErrorOnce } from './checks/pages.ts';
import { bodies, browserBundle, headers, health } from './checks/surface.ts';
import { cliSignsIn, exchangesLimited, keysUploaded, runSignsIn, runsRefused, runUnbound, spentOnce, tokensUnlogged, trustRun } from './checks/workloads.ts';

/** The names of the checks that failed, and `afterwards`, what the run ends with when one did (`Report`). */
export async function conform(
  deployment: Deployment,
  options: { bulkLimit: number; browser: string | null },
): Promise<{ failed: string[]; afterwards: (output: string) => Promise<string | undefined> }> {
  const report = new Report({ mark: deployment.mark });
  await report.check('health', {}, () => health(deployment));
  await report.check('browser bundle', {}, () => browserBundle(deployment));
  // The first sign-in, under `required` from cold (docs/design/passkeys.md, section 13): the rest runs as booted.
  const admin = await report.check('sign-in', {}, () => requiredFromCold(deployment));
  await report.check('page load', { admin }, ({ admin }) => pageLoad(admin));
  await report.check('security headers', { admin }, ({ admin }) => headers(deployment, admin));
  const canaries = await report.check('setup', { admin }, ({ admin }) => setUp(admin));
  await report.check('bodies', { admin, canaries }, ({ admin }) => bodies(deployment, admin));
  await report.check('pages in a browser', { admin, canaries }, ({ admin }) => pagesInBrowser(deployment, admin, options.browser));
  await report.check('pasted values', { admin }, ({ admin }) => pastedValues(deployment, admin, options.browser));
  await report.check('sign-in error, once', { admin }, ({ admin }) => signinErrorOnce(deployment, admin, options.browser));
  const people = await report.check('personas', { admin, canaries }, ({ admin }) => personas(deployment, admin));
  const all = { people, canaries };
  // Touched now and left alone: stale by `stale session`, five minutes on at least.
  const alone = await report.check('a session left alone', { admin }, ({ admin }) => leaveAlone(deployment, admin));

  await report.check('members only', { people }, ({ people }) => membersOnly(deployment, people));
  await report.check('grant scoping', all, ({ people, canaries }) => grantScoping(people, canaries));
  await report.check('folders', all, ({ people, canaries }) => folders(people, canaries));
  await report.check('forks', all, ({ people, canaries }) => forks(people, canaries));
  await report.check('inheritance', all, ({ people, canaries }) => inheritance(people, canaries));
  await report.check('personal configs', { people }, ({ people }) => personalConfigs(deployment, people));
  await report.check('references', all, ({ people, canaries }) => references(deployment, people, canaries));
  await report.check('loosening', { people }, ({ people }) => loosening(people));
  await report.check('missing keys', { people }, ({ people }) => missingKeys(people));
  // Before offboarding: the leaver's CLI session is one of the credentials /mcp must refuse.
  await report.check('MCP connect', { people }, ({ people }) => mcpConnect(deployment, people));
  await report.check('MCP read', all, ({ people, canaries }) => mcpRead(deployment, people, canaries));
  await report.check('MCP changes', all, ({ people, canaries }) => mcpChanges(deployment, people, canaries));
  await report.check('MCP values', all, ({ people, canaries }) => mcpValues(deployment, people, canaries));
  await report.check('reveals audited', all, ({ people, canaries }) => revealAudited(deployment, people, canaries, 'reveal'));
  await report.check('runs audited', all, ({ people, canaries }) => revealAudited(deployment, people, canaries, 'run'));
  await report.check('cross-site', all, ({ people, canaries }) => crossSite(people, canaries));
  await report.check('passkey ceremonies', { people }, ({ people }) => ceremonies(deployment, people));
  await report.check('passkey changes', { people }, ({ people }) => passkeyChanges(deployment, people));
  await report.check('reads stay reads', all, ({ people, canaries }) => readsStayReads(deployment, people, canaries));
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
  await report.check('instance roles', all, ({ people, canaries }) => instanceRoles(deployment, people, canaries));
  await report.check('bulk limit', { people }, ({ people }) => bulkLimit(people, options.bulkLimit));
  await report.check('stale session', { people, alone }, ({ people, alone }) => staleSession(deployment, people, alone));
  // Under `required` from here to `back to optional`: the workload checks too, which no passkey touches.
  await report.check('passkeys required', { people, live }, ({ people, live }) => passkeysRequired(deployment, people, live));
  // A CI run signing in with its ID token, through a binding. The limit
  // comes last of these: it spends this address's exchanges for the minute.
  const binding = await report.check('trust a run', { admin }, ({ admin }) => trustRun(deployment, admin));
  const credential = await report.check('run signs in', { admin, canaries, binding }, ({ admin, canaries }) => runSignsIn(deployment, admin, canaries));
  await report.check('run token spent', { binding }, () => spentOnce(deployment));
  await report.check('runs refused', { admin, binding }, ({ admin }) => runsRefused(deployment, admin));
  await report.check('run signs in by CLI', { canaries, binding }, ({ canaries }) => cliSignsIn(deployment, canaries));
  await report.check('keys uploaded', { admin, canaries, binding }, ({ admin, canaries }) => keysUploaded(deployment, admin, canaries));
  await report.check('run unbound', { admin, binding, credential }, ({ admin, binding, credential }) => runUnbound(deployment, admin, binding, credential));
  await report.check('exchanges limited', { binding }, () => exchangesLimited(deployment));
  await report.check('tokens unlogged', { binding }, () => tokensUnlogged(deployment));
  await report.check('back to optional', {}, () => backToOptional(deployment));
  await report.check('issuer replaced', { people }, ({ people }) => issuerReplaced(deployment, people));
  await report.check('IP public URL', {}, () => ipPublicUrl(deployment));

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
  await report.check('hot login', {}, () => hotLogin(deployment));
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
  return { failed: report.failed, afterwards: (output) => report.afterwards(output) };
}
