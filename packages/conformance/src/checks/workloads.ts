// A CI run signing in as a service with the ID token its platform signs
// for it, through a trust binding an owner made (docs/design/oidc.md). The
// dev IdP plays GitHub Actions under /workloads: discovery, keys over
// HTTP, a runner's token endpoint, and a token for whatever run a check
// describes. What the exchange must never do: take a token twice, in
// either spelling of its signature; take one for another instance, expired,
// or from a run the binding does not name; keep a credential working once
// its binding is gone; or take more exchanges from one address than its
// limit.
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { bearer } from '../browser.ts';
import type { Deployment } from '../harness.ts';
import { GITHUB_RUN } from '../idp/index.ts';
import { expect, Skip } from '../report.ts';
import { Cli } from './cli.ts';
import { DEV, type Canaries, type Person } from './people.ts';

/** The service the runs sign in as: a viewer on dev. */
export const RUNNER = 'token:conformance-run';

/** `coffre trust conformance-run --github acme/api --workflow deploy.yml --branch main`, with the dev IdP as GitHub's issuer. */
const DEPLOY = {
  repository_owner_id: GITHUB_RUN.repository_owner_id,
  repository_id: GITHUB_RUN.repository_id,
  workflow_ref: GITHUB_RUN.workflow_ref,
  ref: GITHUB_RUN.ref,
  event_name: GITHUB_RUN.event_name,
};

/** Every ID token the checks sent and credential they were given: none may show in the processes' output. */
const sent: string[] = [];

/** A run's ID token from the dev IdP, for this deployment unless `audience` says otherwise. */
async function mint(deployment: Deployment, claims: Record<string, unknown> = {}, options: { alg?: 'RS256' | 'ES256'; audience?: string } = {}): Promise<string> {
  const token = await deployment.idp.workloads.mint(options.audience ?? deployment.origin, claims, options.alg);
  sent.push(token);
  return token;
}

/** What `POST /api/auth/oidc` answered, without the credential it may hold. */
type Answer = { status: number; reason?: string; message?: string; retryAfter: string | null };

async function exchange(deployment: Deployment, token: string, service = RUNNER): Promise<Answer & { token?: string; expiresAt?: string }> {
  const response = await fetch(`${deployment.origin}/api/auth/oidc`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ service, token }),
  });
  const body = (await response.json().catch(() => ({}))) as { token?: string; expiresAt?: string; reason?: string; message?: string };
  if (body.token !== undefined) sent.push(body.token);
  return { ...body, status: response.status, retryAfter: response.headers.get('retry-after') };
}

/** What a failure may show of an answer: never its credential. */
const shown = ({ status, reason, message }: Answer) => ({ status, reason, message });

/** The other spelling of an ES256 signature, (r, n − s), which verifies the same claims. */
function twin(jwt: string): string {
  const at = jwt.lastIndexOf('.');
  const signature = Buffer.from(jwt.slice(at + 1), 'base64url');
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt(`0x${signature.subarray(32).toString('hex')}`);
  const flipped = Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex');
  return `${jwt.slice(0, at)}.${Buffer.concat([signature.subarray(0, 32), flipped]).toString('base64url')}`;
}

/** A viewer on dev, and a binding that trusts deploy.yml pushed to main of acme/api. */
export async function trustRun(deployment: Deployment, admin: Person) {
  if (!(await admin.api.me()).features.workloads) throw new Skip("this deployment trusts no workloads: its signin({ workloads }) is off");
  await admin.api.members.add(RUNNER);
  await admin.api.access.set(RUNNER, { [DEV]: 'viewer' });
  const made = await admin.api.bindings.create(RUNNER, { profile: 'github', issuer: deployment.idp.workloads.issuer, claims: DEPLOY, label: 'conformance' });
  return { detail: `${RUNNER}, viewer on ${DEV}, trusts deploy.yml pushed to main of acme/api, from the dev IdP`, value: made.binding.id };
}

/**
 * A run's token buys a credential of five minutes, which reads as the
 * service; its read is logged with the credential, and the log leads from
 * it to the run.
 */
export async function runSignsIn(deployment: Deployment, admin: Person, canaries: Canaries) {
  const issued = await exchange(deployment, await mint(deployment));
  const { token } = issued;
  expect(issued.status === 200 && typeof token === 'string' && token.startsWith('coffre_svc_'), "the run's token bought no credential", shown(issued));
  const lifetime = Date.parse(issued.expiresAt ?? '') - Date.now();
  expect(lifetime > 0 && lifetime <= 5 * 60_000 + 5_000, `the credential lives ${Math.round(lifetime / 1000)} s, not five minutes`);
  const { values } = await bearer(deployment.origin, token).secrets.reveal(`${DEV}/API_KEY`);
  expect(values.API_KEY === canaries[`${DEV}/API_KEY`], 'the credential did not read the value as the service');

  const { entries } = await admin.api.audit.list({ actor: RUNNER, detail: '1' });
  const exchanged = entries.find((entry) => entry.action === 'token.exchange');
  const read = entries.find((entry) => entry.author === 'vault' && entry.action === 'secret.read' && entry.key === 'API_KEY');
  expect(exchanged !== undefined && read !== undefined, 'the exchange or the read is not in the log', entries.map((entry) => entry.action));
  const credentialId = exchanged.metadata.credentialId;
  expect(typeof credentialId === 'string', 'the exchange did not log its credential', exchanged.metadata);
  expect(read.metadata.credentialId === credentialId, "the vault's entry for the read does not name the credential", read.metadata);
  expect(
    read.run?.exchangeSeq === exchanged.seq && read.run.claims.run_id === GITHUB_RUN.run_id && read.run.claims.repository === GITHUB_RUN.repository,
    'the read does not lead to its run',
    read.run,
  );
  return {
    detail: `a five-minute credential for run ${GITHUB_RUN.run_id} of ${GITHUB_RUN.repository}; its read is logged with it, and leads to the run`,
    value: token,
  };
}

/** A token buys one credential, in either spelling of its signature. */
export async function spentOnce(deployment: Deployment): Promise<string> {
  const token = await mint(deployment);
  expect((await exchange(deployment, token)).status === 200, 'a fresh token was refused');
  const again = await exchange(deployment, token);
  expect(again.status === 401 && again.reason === 'replayed', 'a token was taken twice', shown(again));
  const signed = await mint(deployment, {}, { alg: 'ES256' });
  expect((await exchange(deployment, signed)).status === 200, 'a fresh ES256 token was refused');
  const respelled = await exchange(deployment, twin(signed));
  expect(respelled.status === 401 && respelled.reason === 'replayed', "an ES256 token was taken again, its signature's twin in place of its own", shown(respelled));
  return "taken once each: an RS256 token sent again, and an ES256 token's (r, n − s) twin, refused as replayed";
}

/** Tokens for another instance, expired, or from a run the binding does not name: refused, for a reason, and not logged. */
export async function runsRefused(deployment: Deployment, admin: Person): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const feature = 'refs/heads/feature';
  const cases = [
    ['for another instance', await mint(deployment, {}, { audience: 'https://secrets.elsewhere.example' }), 'audience'],
    ['expired', await mint(deployment, { iat: now - 600, nbf: now - 600, exp: now - 120 }), 'expired'],
    ['from a feature branch', await mint(deployment, { ref: feature, workflow_ref: GITHUB_RUN.workflow_ref.replace(/@.*/, `@${feature}`), sub: `repo:acme/api:ref:${feature}` }), 'no_match'],
    // Into the very branch the binding names: it lists push alone.
    ['from a pull request', await mint(deployment, { event_name: 'pull_request', ref: 'refs/pull/1/merge', base_ref: 'main', workflow_ref: GITHUB_RUN.workflow_ref.replace(/@.*/, '@refs/pull/1/merge'), sub: 'repo:acme/api:pull_request' }), 'no_match'],
    ['from another repository', await mint(deployment, { repository_id: '1', repository: 'acme/fork' }), 'no_match'],
  ] as const;
  const before = (await admin.api.audit.list({ actor: RUNNER, detail: '1' })).entries.filter((entry) => entry.action === 'token.exchange').length;
  for (const [what, token, reason] of cases) {
    const answer = await exchange(deployment, token);
    expect(answer.status === 401 && answer.reason === reason, `a token ${what} was not refused as ${reason}`, shown(answer));
    expect(!answer.message?.includes(GITHUB_RUN.ref), `the refusal of a token ${what} said what the binding expects`, answer.message);
  }
  const stranger = await exchange(deployment, await mint(deployment), 'token:conformance-nobody');
  expect(stranger.status === 401 && stranger.reason === 'no_match', 'a token was taken for a service no binding names', shown(stranger));
  const after = (await admin.api.audit.list({ actor: RUNNER, detail: '1' })).entries.filter((entry) => entry.action === 'token.exchange').length;
  expect(after === before, `${after - before} refused exchanges were logged as exchanges`);
  return `${cases.length + 1} refused, each for its reason, none saying what the binding expects, none logged: ${cases.map(([what]) => what).join(', ')}, for another service`;
}

/**
 * The CLI, as a CI job runs it, as a service by its ID token: on GitHub
 * Actions, `--service` and the runner's token endpoint, nothing else and
 * nothing kept; elsewhere, the token piped to `coffre login --service
 * --id-token`, whose credential the next command uses. No token printed.
 */
export async function cliSignsIn(deployment: Deployment, canaries: Canaries): Promise<string> {
  const issuer = deployment.idp.workloads;
  const cli = new Cli(deployment.origin);
  try {
    const read = async (where: string, args: string[], env: Record<string, string>, secrets: string[]) => {
      const run = await cli.run([...args, 'get', `${DEV}/API_KEY`], env);
      expect(run.code === 0, `coffre get ${where} exited ${run.code}`, run.output);
      expect(run.output.trim() === canaries[`${DEV}/API_KEY`], `coffre get ${where} did not print the value`);
      expect(!secrets.some((secret) => run.output.includes(secret)) && !/coffre_svc_/.test(run.output), `coffre get ${where} printed a token`);
    };
    await read('on GitHub Actions', ['--url', deployment.origin, '--service', RUNNER], { ACTIONS_ID_TOKEN_REQUEST_URL: issuer.requestUrl, ACTIONS_ID_TOKEN_REQUEST_TOKEN: issuer.requestToken }, [issuer.requestToken]);
    expect(!existsSync(join(cli.home, '.coffre', 'credentials.json')), 'the CLI kept a credential on disk, for one command');

    const given = await mint(deployment);
    const login = await cli.run(['login', deployment.origin, '--service', RUNNER, '--id-token'], {}, `${given}\n`);
    expect(login.code === 0, `coffre login --service --id-token exited ${login.code}`, login.output);
    expect(!login.output.includes(given) && !/coffre_svc_/.test(login.output), 'coffre login --service printed a token');
    await read('after coffre login --service --id-token', [], {}, [given]);
    return `\`coffre --service ${RUNNER} get\` on GitHub Actions, nothing kept; \`coffre login --service --id-token\` with the token piped in, then \`coffre get\`; no token printed`;
  } finally {
    cli.remove();
  }
}

/** Removing the binding ends the credentials it issued at once, and the next run gets none. */
export async function runUnbound(deployment: Deployment, admin: Person, bindingId: string, credential: string): Promise<string> {
  const me = (token: string) => fetch(`${deployment.origin}/api/me`, { headers: { authorization: `Bearer ${token}` } }).then((response) => response.status);
  expect((await me(credential)) === 200, 'the credential did not work before its binding was removed');
  await admin.api.bindings.remove(RUNNER, bindingId);
  expect((await me(credential)) === 401, 'the credential still worked once its binding was removed');
  const next = await exchange(deployment, await mint(deployment));
  expect(next.status === 401 && next.reason === 'no_match', 'a run was let in once its binding was removed', shown(next));
  const { bindings } = await admin.api.bindings.list(RUNNER);
  expect(bindings.length === 0, 'the removed binding is still listed', bindings);
  return 'its credential refused at once, and the next run refused as no binding matching';
}

/**
 * One address may exchange only so often: tokens that would be refused
 * anyway still count, before anything about them is read. Fixed windows
 * of a minute, so the 429 may wait for the next one.
 */
export async function exchangesLimited(deployment: Deployment): Promise<string> {
  const most = 200;
  for (let sent = 1; sent <= most; sent++) {
    const answer = await exchange(deployment, 'not.a.token');
    if (answer.status === 429) {
      expect(answer.reason === 'busy' && answer.retryAfter === '60', 'the 429 did not say to wait a minute', shown(answer));
      return `a 429 after ${sent} malformed tokens from one address, and Retry-After: 60`;
    }
    expect(answer.status === 401 && answer.reason === 'malformed', 'a malformed token was not refused as malformed', shown(answer));
  }
  throw new Error(`${most} exchanges from one address, and none was turned away`);
}

/** No ID token the checks sent, nor credential they were given, in what the deployment's processes printed. */
export async function tokensUnlogged(deployment: Deployment): Promise<string> {
  const output = deployment.output();
  // A token's header is the same for every token; its claims and signature are its own.
  const found = sent.filter((token) => token.split('.').slice(1).some((part) => output.includes(part)) || (token.startsWith('coffre_') && output.includes(token)));
  expect(found.length === 0, `${found.length} of the tokens and credentials the checks used are in the processes' output`);
  expect(!/coffre_svc_[A-Za-z0-9_-]{8,}/.test(output), "a service credential is in the processes' output");
  return `${sent.length} ID tokens and credentials, none in the processes' output`;
}
