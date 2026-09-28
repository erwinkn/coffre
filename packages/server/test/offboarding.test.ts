import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { and, eq, isNull } from 'drizzle-orm';

import { defineSignin, github } from '../../core/src/identity/signin/config.ts';
import { auditLog, credentials, secrets, syncs } from '../../db/test/tables.ts';
import { SigninService } from '../src/api/signin.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const LEAD = 'lead@acme.example';
const DEV = 'dev@acme.example';
const SERVICE = 'ci-deploy';
const IP = '203.0.113.7';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let signin: SigninService;
let root: ReturnType<typeof clientFor>;
let lead: ReturnType<typeof clientFor>;
let dev: ReturnType<typeof clientFor>;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  signin = new SigninService({
    ...deps,
    signin: defineSignin({
      publicUrl: 'https://secrets.acme.example',
      providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })],
    }),
  });
  deps.signin = signin;
  root = clientFor(deps, ROOT);
  lead = clientFor(deps, LEAD);
  dev = clientFor(deps, DEV);
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.members.add(`user:${LEAD}`, { owner: true });
  await root.members.add(`user:${DEV}`);
  await root.members.add(`token:${SERVICE}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
});

function meta() {
  return { requestId: randomUUID(), sourceIp: IP, label: 'Firefox on macOS' };
}

async function browserSession(email: string, subject: string) {
  const result = await signin.completeSignin(
    { provider: 'github', subject, emails: [email], name: null },
    meta(),
  );
  assert.equal(result.ok, true, `expected ${email} to be let in`);
  if (!result.ok) throw new Error('unreachable');
  return result.credential;
}

async function cliSession(email: string) {
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: IP });
  await signin.decideDevice(await contextFor(deps, email), started.userCode, true);
  const polled = await signin.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: IP });
  assert.equal(polled.status, 'approved');
  if (polled.status !== 'approved') throw new Error('unreachable');
  return polled.credential;
}

// --- removal ------------------------------------------------------------------

test('removing someone revokes every way in, so re-adding them starts from nothing', async () => {
  const browser = await browserSession(DEV, 'gh-101');
  const cli = await cliSession(DEV);

  const { revoked } = await root.members.remove(`user:${DEV}`);
  assert.deepEqual(revoked, { grants: 1, sessions: 2, tokens: 0, identities: 1 });
  await root.members.add(`user:${DEV}`);

  await assert.rejects(signin.verify(browser.token), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(cli.token), /unknown, expired or revoked/);
  assert.deepEqual((await dev.me()).environments, [], 'grants stay gone');

  // The same account signs in again, bound afresh by email.
  const again = await browserSession(DEV, 'gh-101');
  assert.equal((await signin.verify(again.token)).id, DEV);

  const [removal] = await db.owner
    .select({ metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'directory.remove'), isNull(auditLog.projectId)));
  assert.deepEqual(JSON.parse(removal.metadata), {
    principalType: 'user',
    principalId: DEV,
    revoked: 1,
    sessions: 2,
    tokens: 0,
    identities: 1,
  });
});

test('a removed service loses its tokens for good', async () => {
  const token = await lead.tokens.issue(`token:${SERVICE}`, { label: 'ci', expiresInDays: 30 });
  const { revoked } = await root.members.remove(`token:${SERVICE}`);
  assert.deepEqual(revoked, { grants: 0, sessions: 0, tokens: 1, identities: 0 });
  await root.members.add(`token:${SERVICE}`);
  await assert.rejects(signin.verify(token.token), /unknown, expired or revoked/);
});

test('a CLI sign-in approved before removal cannot be collected after re-adding', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await signin.decideDevice(await contextFor(deps, DEV), started.userCode, true);
  await root.members.remove(`user:${DEV}`);
  await root.members.add(`user:${DEV}`);

  assert.deepEqual(
    await signin.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: IP }),
    { status: 'denied' },
  );
  assert.equal((await db.owner.select().from(credentials).where(eq(credentials.kind, 'cli'))).length, 0);
});

// --- the report ---------------------------------------------------------------

test('the report lists the current values someone saw, until each is rotated', async () => {
  await root.secrets.set('market/prod', { API_KEY: 'api-1', DB_URL: 'postgres://one', SESSION_SECRET: 'secret-1' });
  await dev.secrets.reveal('market/prod/API_KEY');
  await dev.secrets.reveal('market/prod');
  await dev.secrets.set('market/prod', { NEW_FLAG: 'on' });

  const exposed = async () =>
    (await root.members.get(`user:${DEV}`)).exposed.map(({ key, version, how }) => `${key} v${version} ${how}`);

  assert.deepEqual(await exposed(), [
    'API_KEY v1 read',
    'DB_URL v1 read',
    'NEW_FLAG v1 wrote',
    'SESSION_SECRET v1 read',
  ]);

  // Rotating takes a value off; restoring a value they saw puts it back.
  await root.secrets.set('market/prod', { API_KEY: 'api-2', SESSION_SECRET: 'secret-2' });
  assert.deepEqual(await exposed(), ['DB_URL v1 read', 'NEW_FLAG v1 wrote']);
  assert.equal((await root.members.get(`user:${DEV}`)).rotated, 2);

  await root.secrets.restore('market/prod/API_KEY', 1);
  assert.deepEqual(await exposed(), ['API_KEY v3 read', 'DB_URL v1 read', 'NEW_FLAG v1 wrote']);

  // Archived values are not served any more, so they drop off too.
  await root.secrets.set('market/prod', { DB_URL: null });
  assert.deepEqual(await exposed(), ['API_KEY v3 read', 'NEW_FLAG v1 wrote']);

  const report = await root.members.get(`user:${DEV}`);
  assert.equal(report.exposed[0].project, 'market');
  assert.equal(report.exposed[0].environment, 'prod');
  assert.ok(Date.parse(report.exposed[0].at) <= Date.now());
});

test('removed people stay listed, with as many values to rotate as their report', async () => {
  await root.secrets.set('market/prod', { API_KEY: 'api-1', DB_URL: 'postgres://one' });
  await dev.secrets.reveal('market/prod');
  await dev.secrets.reveal('market/prod/API_KEY');
  assert.deepEqual((await root.members.list()).removed, []);

  const { report } = await root.members.remove(`user:${DEV}`);
  assert.equal(report.exposed.length, 2);
  await root.members.remove(`token:${SERVICE}`);
  const listed = async () =>
    (await root.members.list()).removed.map(
      ({ principalType, principalId, toRotate }) => `${principalType}:${principalId} ${toRotate}`,
    );
  assert.deepEqual(await listed(), [`service:${SERVICE} 0`, `user:${DEV} 2`]);
  assert.equal((await root.members.get(`user:${DEV}`)).exposed.length, 2);

  await root.secrets.set('market/prod', { API_KEY: 'api-2' });
  assert.deepEqual(await listed(), [`service:${SERVICE} 0`, `user:${DEV} 1`]);

  await root.members.add(`user:${DEV}`);
  assert.deepEqual(await listed(), [`service:${SERVICE} 0`]);
  await assert.rejects(dev.members.list(), { status: 403 });
});

test('the report tells who removed someone, and that nothing still lets them in', async () => {
  await browserSession(DEV, 'gh-101');
  const before = await root.members.get(`user:${DEV}`);
  assert.equal(before.status, 'active');
  assert.equal(before.instanceRole, 'user');
  assert.deepEqual(before.live, { grants: 1, sessions: 1, tokens: 0, identities: 1 });
  assert.equal(before.removedAt, null);

  await lead.members.remove(`user:${DEV}`);
  const after = await root.members.get(`user:${DEV}`);
  assert.equal(after.status, 'removed');
  assert.equal(after.removedBy, LEAD);
  assert.ok(after.removedAt !== null);
  assert.deepEqual(after.live, { grants: 0, sessions: 0, tokens: 0, identities: 0 });

  await root.members.add(`user:${DEV}`);
  const back = await root.members.get(`user:${DEV}`);
  assert.equal(back.status, 'active');
  assert.equal(back.removedAt, null);
});

test('the report lists service tokens someone issued, while they still work', async () => {
  const token = await lead.tokens.issue(`token:${SERVICE}`, { label: 'deploys', expiresInDays: 30 });
  await root.tokens.issue(`token:${SERVICE}`, { label: 'not theirs', expiresInDays: 30 });

  const issued = (await root.members.get(`user:${LEAD}`)).issuedTokens;
  assert.deepEqual(
    issued.map(({ id, service, label }) => ({ id, service, label })),
    [{ id: token.id, service: SERVICE, label: 'deploys' }],
  );

  await root.members.remove(`token:${SERVICE}`);
  assert.deepEqual((await root.members.get(`user:${LEAD}`)).issuedTokens, []);
});

test('the syncs someone set up are listed with where they push', async () => {
  await root.secrets.set('market/prod', { GITHUB_TOKEN_FOR_SYNC: 'ghp_fake' });
  const [credential] = await db.owner
    .select({ projectId: secrets.projectId, environmentId: secrets.environmentId, id: secrets.id })
    .from(secrets)
    .where(eq(secrets.key, 'GITHUB_TOKEN_FOR_SYNC'));
  const place = { projectId: credential.projectId, environmentId: credential.environmentId };
  await db.owner.insert(syncs).values([
    {
      id: randomUUID(),
      ...place,
      provider: 'github-actions',
      config: JSON.stringify({ owner: 'acme', repo: 'app' }),
      credentialSecretId: credential.id,
      createdBy: DEV,
    },
    {
      id: randomUUID(),
      ...place,
      provider: 'github-actions',
      config: JSON.stringify({ owner: 'acme', repo: 'other' }),
      credentialSecretId: credential.id,
      createdBy: ROOT,
    },
  ]);

  const listed = (await root.members.get(`user:${DEV}`)).syncs;
  assert.deepEqual(
    listed.map(({ project, environment, providerLabel, destination, credential }) => ({
      project,
      environment,
      providerLabel,
      destination,
      credential,
    })),
    [
      {
        project: 'market',
        environment: 'prod',
        providerLabel: 'GitHub Actions',
        destination: 'acme/app',
        credential: 'market/prod/GITHUB_TOKEN_FOR_SYNC',
      },
    ],
  );
});

test('only owners see reports, and only about someone who exists', async () => {
  await assert.rejects(dev.members.get(`user:${DEV}`), { status: 403 });
  await assert.rejects(root.members.get('user:nobody@acme.example'), { status: 404 });

  const rootReport = await lead.members.get(`user:${ROOT}`);
  assert.equal(rootReport.status, 'active');
  assert.equal(rootReport.instanceRole, 'root-admin');
});
