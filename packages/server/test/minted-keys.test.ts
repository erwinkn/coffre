import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signWith, type KeyObject } from 'node:crypto';

import { DevIdp, fakeInstallations } from '@coffre/conformance/idp';
import { github, githubApp, signin, type BindingClaims } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { asc, eq } from 'drizzle-orm';

import { auditLog } from './db/tables.ts';
import { answer, type Pages } from './start-fixture.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { forgetKeys } from '../src/workloads/keys.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, testVault, type FixtureDeps, type TestVault } from './api-fixture.ts';

/*
 * W108's prototype, end to end: a CI run signs in with its ID token, reads
 * `infra/ci`, and finds GITHUB_TOKEN there, an installation token the
 * vault minted for it from a GitHub App whose key only the vault holds,
 * narrowed to `acme/infra`. Against the dev IdP's GitHub App, over HTTP.
 */

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'infra-release';
const MEMBER = `token:${SERVICE}`;
const ISSUER = 'https://token.actions.githubusercontent.com';
const KEYS = `${ISSUER}/.well-known/jwks`;
const IP = '203.0.113.9';

/** `release.yml`, pushed to `main` of `acme/infra`. */
const RELEASE: BindingClaims = {
  repository_owner_id: '9919',
  repository_id: '41540',
  workflow_ref: 'acme/infra/.github/workflows/release.yml@refs/heads/main',
  ref: 'refs/heads/main',
  event_name: 'push',
};

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

let signing: { privateKey: KeyObject; jwk: Record<string, unknown> };

/** A run's ID token, as GitHub signs it, for this instance. */
function idToken(): string {
  const input = `${part({ alg: 'RS256', kid: 'rs-1', typ: 'JWT' })}.${part({
    iss: ISSUER, aud: ORIGIN, sub: 'repo:acme/infra:ref:refs/heads/main',
    iat: seconds() - 5, exp: seconds() + 295, jti: crypto.randomUUID(),
    run_id: '9001', sha: 'a'.repeat(40), repository: 'acme/infra', ...RELEASE,
  })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), signing.privateKey).toString('base64url')}`;
}

const transport: WorkloadTransport = {
  json: async (url) => {
    const published: Record<string, unknown> = {
      [`${ISSUER}/.well-known/openid-configuration`]: { issuer: ISSUER, jwks_uri: KEYS },
      [KEYS]: { keys: [signing.jwk] },
    };
    if (!(url.href in published)) throw new FetchRefused(url, 'answered 404');
    return published[url.href];
  },
};

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let idp: DevIdp;
let vault: TestVault;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
const ui = {} as Pages;

before(async () => {
  db = await openTestDatabase();
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  signing = { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' } };
  idp = new DevIdp();
  await idp.start();
  // The release App: it may write contents where it is installed.
  idp.githubApp.permissions = { ...idp.githubApp.permissions, contents: 'write' };
  const release = githubApp({ appId: idp.githubApp.appId, privateKey: idp.githubApp.privateKey, apiUrl: idp.githubApp.options.apiUrl });
  vault = testVault([ROOT], {
    minted: [{ at: 'infra/ci', key: 'GITHUB_TOKEN', from: release.tokens({ account: 'acme', repositories: ['infra'], permissions: { contents: 'write' } }) }],
  });
});

after(async () => {
  await db.close();
  await idp.stop();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  forgetKeys();
  idp.githubApp.installations = fakeInstallations();
  idp.githubApp.down = false;
  deps = testDeps(db.runtime, [ROOT], { vault });
  const limits = processLimits({ perSource: 1000, total: 1000 });
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport);
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
  const root = clientFor(deps, ROOT);
  await root.projects.create('infra', { name: 'Infra' });
  await root.environments.create('infra/ci', { name: 'CI' });
  await root.environments.create('infra/dev', { name: 'Dev' });
  await root.secrets.set('infra/ci', { NPM_TOKEN: 'npm_stored' });
  await root.secrets.set('infra/dev', { NPM_TOKEN: 'npm_dev' });
  await root.access.set(MEMBER, { 'infra/ci': 'viewer', 'infra/dev': 'viewer' });
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, { profile: 'github', issuer: null, claims: RELEASE, label: 'release', replaces: [] }, { dryRun: false });
  assert.ok('binding' in made);
});

/** The run's credential: its ID token, exchanged. */
async function signIn(): Promise<string> {
  const response = await answer(
    new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: MEMBER, token: idToken() }) }),
    runtime, ui, IP,
  );
  assert.equal(response.status, 200);
  return ((await response.json()) as { token: string }).token;
}

/** `coffre export` / `coffre run`, as the CLI asks: one reveal of the environment. */
async function reveal(credential: string, path: string): Promise<{ status: number; values: Record<string, string>; body: Record<string, unknown> }> {
  const response = await answer(
    new Request(`${ORIGIN}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${credential}`, 'content-type': 'application/json' }, body: JSON.stringify({ path }) }),
    runtime, ui, IP,
  );
  const body = (await response.json()) as Record<string, unknown>;
  return { status: response.status, values: (body.values ?? {}) as Record<string, string>, body };
}

/** What a token reaches on GitHub, as the App's installation: the repositories it lists. */
async function reaches(token: string): Promise<string[] | number> {
  const response = await fetch(`${idp.githubApp.options.apiUrl}/installation/repositories`, { headers: { authorization: `Bearer ${token}` } });
  if (!response.ok) return response.status;
  return ((await response.json()) as { repositories: { full_name: string }[] }).repositories.map((each) => each.full_name);
}

async function logged(action: string) {
  const rows = await db.owner.select({ seq: auditLog.seq, actor: auditLog.actor, decision: auditLog.decision, code: auditLog.code, relatedSeq: auditLog.relatedSeq, metadata: auditLog.metadata })
    .from(auditLog).where(eq(auditLog.action, action)).orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test('a run that reads infra/ci gets GITHUB_TOKEN freshly minted, for acme/infra alone; the log ties each mint to its run, and never holds the token', async () => {
  const issued = idp.githubApp.tokensIssued;
  const credential = await signIn();
  const first = await reveal(credential, 'infra/ci');
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.values.NPM_TOKEN, 'npm_stored');
  assert.match(first.values.GITHUB_TOKEN!, /^ghs_/);
  assert.deepEqual(await reaches(first.values.GITHUB_TOKEN!), ['acme/infra'], 'narrowed to the repository the deployment named');
  // Each read mints its own: one job's token is never another's.
  const second = await reveal(credential, 'infra/ci');
  assert.notEqual(second.values.GITHUB_TOKEN, first.values.GITHUB_TOKEN);
  assert.equal(idp.githubApp.tokensIssued - issued, 2);
  // Another environment mints nothing.
  assert.deepEqual(Object.keys((await reveal(credential, 'infra/dev')).values), ['NPM_TOKEN']);

  const [exchange] = await logged('token.exchange');
  const intents = await logged('credential.mint');
  const outcomes = await logged('credential.minted');
  assert.equal(intents.length, 2);
  assert.equal(outcomes.length, 2);
  for (const [i, outcome] of outcomes.entries()) {
    assert.equal(outcome.actor, MEMBER);
    assert.equal(outcome.decision, 'allow');
    assert.equal(outcome.relatedSeq, intents[i]!.seq, 'each outcome names its intent');
    assert.equal(outcome.metadata.credentialId, exchange!.metadata.credentialId, "and the run's credential, so its run");
    assert.deepEqual(outcome.metadata.scope, { app: idp.githubApp.appId, account: 'acme', repositories: ['infra'], permissions: { contents: 'write' } });
    assert.deepEqual(outcome.metadata.granted, { permissions: { contents: 'write' }, repositories: ['infra'] });
    assert.equal(typeof outcome.metadata.expiresAt, 'string');
  }
  const token = first.values.GITHUB_TOKEN!;
  assert.equal(outcomes[0]!.metadata.fingerprint, createHash('sha256').update(token).digest('hex').slice(0, 16), 'a token found in a log leads back to its mint');
  const everything = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog);
  assert.ok(everything.every((row) => !row.metadata.includes(token) && !row.metadata.includes(second.values.GITHUB_TOKEN!)), 'no entry holds a token');

  // The audit page reads the mint's run, as it does a read's.
  const { entries } = await clientFor(deps, ROOT).audit.list({ detail: '1' });
  const shown = entries.find((entry) => entry.action === 'credential.minted')!;
  assert.equal(shown.run?.claims.run_id, '9001');
  // The vault's own log, the new entries in it, still verifies whole, and signs.
  assert.deepEqual((await deps.vault.verifyLog({})).ok, true);
  assert.equal((await deps.vault.checkpoint()).ok, true);
});

test('one key alone mints too; a person reads it as they would a value', async () => {
  const { values } = await clientFor(deps, ROOT).secrets.reveal('infra/ci/GITHUB_TOKEN');
  assert.match(values.GITHUB_TOKEN!, /^ghs_/);
  const [outcome] = await logged('credential.minted');
  assert.equal(outcome!.actor, `user:${ROOT}`);
  assert.equal(outcome!.metadata.purpose, 'reveal');
});

test('no read, no mint: a run whose service lost infra/ci is refused before GitHub is asked', async () => {
  const credential = await signIn();
  await clientFor(deps, ROOT).access.set(MEMBER, { 'infra/ci': null });
  const issued = idp.githubApp.tokensIssued;
  assert.equal((await reveal(credential, 'infra/ci')).status, 403);
  assert.equal(idp.githubApp.tokensIssued, issued);
  assert.equal((await logged('credential.mint')).length, 0, "the app's own check refuses first");
});

test('GitHub down: the whole read fails, 503, and the log shows the intent and why it came to nothing', async () => {
  const credential = await signIn();
  idp.githubApp.down = true;
  const { status, body } = await reveal(credential, 'infra/ci');
  assert.equal(status, 503, JSON.stringify(body));
  assert.equal(body.reason, 'unavailable');
  const [intent] = await logged('credential.mint');
  const [outcome] = await logged('credential.minted');
  assert.equal(intent!.decision, 'allow');
  assert.equal(outcome!.decision, 'deny');
  assert.equal(outcome!.code, 'unavailable');
  assert.equal(outcome!.relatedSeq, intent!.seq);
  assert.match(String(outcome!.metadata.error), /503/);
});

test('an installation that no longer reaches the repository: 503, nothing released', async () => {
  idp.githubApp.installations = fakeInstallations().map((each) => (each.account.login === 'acme' ? { ...each, repositories: each.repositories.filter((repo) => repo.name !== 'infra') } : each));
  const credential = await signIn();
  const { status } = await reveal(credential, 'infra/ci');
  assert.equal(status, 503);
  const [outcome] = await logged('credential.minted');
  assert.match(String(outcome!.metadata.error), /not installed on acme\/infra/);
});
