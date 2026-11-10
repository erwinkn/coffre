import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { defineSignin, generateToken, github, hashToken } from '@coffre/core/identity';
import { appendEntries } from '@coffre/db/log';
import { eq, isNull } from 'drizzle-orm';

import { auditLog, credentials, identities, secrets, secretVersions } from './db/tables.ts';
import { CredentialUncheckable, SigninService } from '../src/api/signin.ts';
import { authenticateRequest } from '../src/auth.ts';
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
  await root.members.add(`user:${LEAD}`, { role: 'admin' });
  await root.members.add(`user:${DEV}`);
  await root.members.add(`token:${SERVICE}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.access.set(`user:${DEV}`, { market: 'developer' });
  // A token reaches what its account holds when it is issued.
  await root.access.set(`token:${SERVICE}`, { 'market/prod': 'viewer' });
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

// --- an outage is not a sign-out ------------------------------------------------

test('a session the vault cannot check right now is an outage, answered 503, not a sign-out', async (t) => {
  const session = await browserSession(DEV, 'dev-account');
  const runtime = { auth: null, verifier: signin, vault: deps.vault, db: deps.db } as never;
  const authenticate = () => authenticateRequest(new Request('https://coffre.test/api/me'), runtime, randomUUID(), session.token);
  const hung = t.mock.method(deps.vault, 'access', async () => {
    throw new Error("The Workers runtime canceled this request because it detected that your Worker's code had hung");
  });
  await assert.rejects(signin.verify(session.token), CredentialUncheckable);
  const unchecked = await authenticate();
  assert.ok(unchecked instanceof Response);
  assert.equal(unchecked.status, 503, 'the page must not read a vault outage as signed out');
  hung.mock.restore();
  assert.ok(!((await authenticate()) instanceof Response), 'the same session, once the vault answers');
  // A row that answered and fails its MAC was checked: refused, a sign-out, never an outage.
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.tokenHash, hashToken(session.token)));
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) }).where(eq(credentials.id, row!.id));
  const tampered = await authenticate();
  assert.ok(tampered instanceof Response);
  assert.equal(tampered.status, 401);
  await db.owner.update(credentials).set({ expiresAt: row!.expiresAt }).where(eq(credentials.id, row!.id));
  // And one checked and revoked, too.
  await signin.signOut(session.token, meta());
  const refused = await authenticate();
  assert.ok(refused instanceof Response);
  assert.equal(refused.status, 401);
});

// --- removal ------------------------------------------------------------------

test('removing someone revokes every way in, so re-adding them starts from nothing', async () => {
  const browser = await browserSession(DEV, 'gh-101');
  const cli = await cliSession(DEV);

  const { revoked } = await root.members.remove(`user:${DEV}`);
  assert.deepEqual(revoked, { grants: 1, sessions: 2, tokens: 0, identities: 1, apps: 0 });
  await root.members.add(`user:${DEV}`);

  await assert.rejects(signin.verify(browser.token), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(cli.token), /unknown, expired or revoked/);
  assert.deepEqual((await dev.me()).environments, [], 'grants stay gone');

  // The same account signs in again, bound afresh by email.
  const again = await browserSession(DEV, 'gh-101');
  assert.equal((await signin.verify(again.token)).id, DEV);

  // The vault's record: the grant it took, and the generation that ends every session and token from before.
  const [removal] = await db.owner
    .select({ author: auditLog.author, subject: auditLog.subjectPrincipal, metadata: auditLog.metadata })
    .from(auditLog)
    .where(eq(auditLog.action, 'member.remove'));
  assert.deepEqual({ ...removal, metadata: JSON.parse(removal.metadata) }, {
    author: 'vault',
    subject: `user:${DEV}`,
    metadata: { revoked: 1, generation: 1 },
  });
});

test('a removed service loses its tokens for good', async () => {
  const token = await lead.tokens.issue(`token:${SERVICE}`, { label: 'ci', expiresInDays: 30 });
  const { revoked } = await root.members.remove(`token:${SERVICE}`);
  assert.deepEqual(revoked, { grants: 1, sessions: 0, tokens: 1, identities: 0, apps: 0 });
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

test('R4: a junk credential inserted by the app login does not break listings or offboarding', async (t) => {
  const report = t.mock.method(console, 'error', () => {});
  const browser = await browserSession(DEV, 'gh-101');
  const cli = await cliSession(DEV);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, cli.id));
  const token = generateToken('cli');
  const id = randomUUID();
  await db.runtime.insert(credentials).values({ ...row, id, tokenHash: hashToken(token) });

  assert.ok((await root.members.list()).members.some((entry) => entry.member === `user:${DEV}`));
  assert.deepEqual((await root.members.get(`user:${DEV}`)).live, { grants: 1, sessions: 2, tokens: 0, identities: 1, apps: 0 });
  assert.equal((await signin.verify(browser.token)).id, DEV);
  await assert.rejects(signin.verify(token), /authentic|tamper|unknown/i);
  assert.ok(report.mock.calls.some((call) => {
    const event = call.arguments[0] as { event: string; table: string; id: string };
    return event.event === 'auth_row_tampered' && event.table === 'credentials' && event.id === id;
  }));

  const { revoked } = await root.members.remove(`user:${DEV}`);
  assert.deepEqual(revoked, { grants: 1, sessions: 2, tokens: 0, identities: 1, apps: 0 });
  await root.members.add(`user:${DEV}`);
  await assert.rejects(signin.verify(browser.token), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(cli.token), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(token), /authentic|tamper|unknown/i);
  assert.equal((await signin.verify((await browserSession(DEV, 'gh-101')).token)).id, DEV);
});

test('R4: a bad identity and the session depending on it are dead while healthy sessions can be offboarded', async (t) => {
  const report = t.mock.method(console, 'error', () => {});
  const browser = await browserSession(DEV, 'gh-101');
  const cli = await cliSession(DEV);
  const [identity] = await db.owner.select().from(identities).where(eq(identities.principal, `user:${DEV}`));
  await db.owner.update(identities).set({ subject: 'edited-around-the-app' }).where(eq(identities.id, identity.id));

  assert.ok((await root.members.list()).members.some((entry) => entry.member === `user:${DEV}`));
  assert.deepEqual((await root.members.get(`user:${DEV}`)).live, { grants: 1, sessions: 1, tokens: 0, identities: 0, apps: 0 });
  assert.equal((await signin.verify(cli.token)).id, DEV);
  await assert.rejects(signin.verify(browser.token), /authentic|tamper|unknown/i);
  assert.ok(report.mock.calls.some((call) => {
    const event = call.arguments[0] as { event: string; table: string; id: string };
    return event.event === 'auth_row_tampered' && event.table === 'identities' && event.id === identity.id;
  }));

  const { revoked } = await root.members.remove(`user:${DEV}`);
  assert.deepEqual(revoked, { grants: 1, sessions: 1, tokens: 0, identities: 0, apps: 0 });
  await root.members.add(`user:${DEV}`);
  await assert.rejects(signin.verify(cli.token), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(browser.token), /authentic|tamper|unknown/i);
  assert.equal((await signin.verify((await browserSession(DEV, 'gh-101')).token)).id, DEV);
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

/** Each version of the key, by number: its IV and tag, the ciphertext's identity (`sameValue`). */
const ciphertexts = async (key: string) => new Map((await db.owner.select({ version: secretVersions.version, iv: secretVersions.iv, tag: secretVersions.authTag })
  .from(secretVersions).innerJoin(secrets, eq(secrets.id, secretVersions.secretId)).where(eq(secrets.key, key)))
  .map(({ version, iv, tag }) => [version, `${Buffer.from(iv).toString('hex')}:${Buffer.from(tag).toString('hex')}`]));

test('a value set again as it was is a new value: a fresh IV and tag, and the report counts the key rotated (T252)', async () => {
  await root.secrets.set('market/prod', { API_KEY: 'api-1' });
  await dev.secrets.reveal('market/prod/API_KEY');
  await root.secrets.set('market/prod', { API_KEY: 'api-1' });
  const seen = await ciphertexts('API_KEY');
  assert.deepEqual([...seen.keys()].sort(), [1, 2]);
  assert.notEqual(seen.get(2), seen.get(1));
  const report = await root.members.get(`user:${DEV}`);
  assert.deepEqual([report.exposed, report.rotated], [[], 1]);
});

test('every new value draws a ciphertext of its own, the same text however it is written: one key, several at once (an import), plain, generated, sensitive, a fork\'s copy (T252)', async () => {
  // What `sameValue` stands on: two versions share an IV and tag only when one is the other's copy (a restore, a mark).
  await root.secrets.set('market/prod', { API_KEY: 'api-1' });
  await dev.secrets.reveal('market/prod/API_KEY');
  await root.secrets.set('market/prod', { API_KEY: 'api-1', OTHER: 'api-1' });
  await root.secrets.set('market/prod', { API_KEY: { value: 'api-1', sensitivity: 'plain' } });
  await root.secrets.set('market/prod', { API_KEY: { value: 'api-1', generated: { recipe: 'bytes:32' } } });
  await root.secrets.set('market/prod', { API_KEY: { value: 'api-1', sensitivity: 'sensitive' } });
  await root.environments.create('market/copy', { from: 'prod' });
  const all = await db.owner.select({ secret: secretVersions.secretId, version: secretVersions.version, iv: secretVersions.iv, tag: secretVersions.authTag }).from(secretVersions);
  const keyed = await db.owner.select({ id: secrets.id, key: secrets.key, environment: secrets.environmentId }).from(secrets);
  assert.equal(keyed.length, 4, 'API_KEY and OTHER, in prod and in the copy');
  assert.equal(all.length, 5 + 1 + 2);
  const identities = all.map(({ iv, tag }) => `${Buffer.from(iv).toString('hex')}:${Buffer.from(tag).toString('hex')}`);
  assert.equal(new Set(identities).size, all.length, 'no two versions share an IV and tag');
  const report = await root.members.get(`user:${DEV}`);
  assert.deepEqual([report.exposed, report.rotated], [[], 1]);
});

test('a value put back again and again, each restore of the last restore, is the one they saw however long the chain (T252, review r2 of #559)', async () => {
  await root.secrets.set('market/prod', { API_KEY: 'api-1' });
  await dev.secrets.reveal('market/prod/API_KEY');
  // v2 a new value, v3 v1's put back; v4 new, v5 v3's put back; v6 new, v7 v5's.
  for (const [value, back] of [['api-2', 1], ['api-3', 3], ['api-4', 5]] as const) {
    await root.secrets.set('market/prod', { API_KEY: value });
    await root.secrets.restore('market/prod/API_KEY', back);
  }
  const seen = await ciphertexts('API_KEY');
  assert.deepEqual([3, 5, 7].map((version) => seen.get(version)), [1, 1, 1].map((version) => seen.get(version)), 'a restore copies the ciphertext');
  assert.deepEqual((await root.members.get(`user:${DEV}`)).exposed.map(({ key, version, how }) => `${key} v${version} ${how}`), ['API_KEY v7 read']);
});

test('a key marked stricter after they read it holds the value they read: not rotated (T252)', async () => {
  // Read v3, then sensitive: v4, v3's ciphertext rewrapped. Followed back by restores alone, v4 came from none, and the
  // report called the key rotated.
  for (const value of ['api-1', 'api-2', 'api-3']) await root.secrets.set('market/prod', { API_KEY: value });
  await dev.secrets.reveal('market/prod/API_KEY');
  await root.secrets.set('market/prod', { API_KEY: { sensitivity: 'sensitive' } });
  const seen = await ciphertexts('API_KEY');
  assert.equal(seen.get(4), seen.get(3), 'marking copies the ciphertext');
  const report = await root.members.get(`user:${DEV}`);
  assert.deepEqual([report.exposed.map(({ key, version, how }) => `${key} v${version} ${how}`), report.rotated], [['API_KEY v4 read'], 0]);
});

test("a restore's entry carries no value forward: the versions' own ciphertext says which hold the one they saw (T252)", async () => {
  // A database writer's restore entries, under the app's key, naming a version they read as the current one's source.
  await root.secrets.set('market/prod', { API_KEY: 'api-1' });
  await dev.secrets.reveal('market/prod/API_KEY');
  const [secret] = await db.owner.select({ id: secrets.id, projectId: secrets.projectId, environmentId: secrets.environmentId }).from(secrets).where(eq(secrets.key, 'API_KEY'));
  await root.secrets.set('market/prod', { API_KEY: 'api-2' });
  for (const metadata of ['{"key":"API_KEY","version":2,"from":1}', '{"key":"API_KEY","version":2,"from":1.0}']) {
    await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('app', deps.chainKey), [{
      actor: `user:${ROOT}`, action: 'secret.restore', decision: 'allow', secretId: secret!.id, projectId: secret!.projectId, environmentId: secret!.environmentId, metadata,
    }], undefined, undefined, [], true));
  }
  const report = await root.members.get(`user:${DEV}`);
  assert.deepEqual([report.exposed, report.rotated], [[], 1]);
});

test('the report reads any number of secrets a member\'s reads listed, past every engine\'s bound on a query\'s parameters', async () => {
  await root.secrets.set('market/prod', { API_KEY: 'api-1' });
  const [secret] = await db.owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, 'API_KEY'));
  // One read listing 33,000 secrets, the one still served among them: as the vault writes it, under its key.
  const listed = [...Array.from({ length: 33_000 }, () => ({ secretId: randomUUID(), subject: 'market/prod/GONE', version: 1 })), { secretId: secret!.id, subject: 'market/prod/API_KEY', version: 1 }];
  await db.owner.transaction((tx) => appendEntries(tx, deriveLogKey('vault', deps.vault.signingKey), [{
    actor: `user:${DEV}`, action: 'secret.read', decision: 'allow', metadata: JSON.stringify({ purpose: 'run', secrets: listed }),
  }]));
  assert.deepEqual((await root.members.get(`user:${DEV}`)).exposed.map(({ key, version, how }) => `${key} v${version} ${how}`), ['API_KEY v1 read']);
});

test('removed people stay listed, with as many values to rotate as their report', async () => {
  await root.secrets.set('market/prod', { API_KEY: 'api-1', DB_URL: 'postgres://one' });
  await dev.secrets.reveal('market/prod');
  await dev.secrets.reveal('market/prod/API_KEY');
  assert.deepEqual((await root.members.list()).removed, []);

  const { report } = await root.members.remove(`user:${DEV}`);
  assert.equal(report?.exposed.length, 2);
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
  assert.equal(before.instanceRole, 'member');
  assert.deepEqual(before.live, { grants: 1, sessions: 1, tokens: 0, identities: 1, apps: 0 });
  assert.equal(before.removedAt, null);

  await lead.members.remove(`user:${DEV}`);
  const after = await root.members.get(`user:${DEV}`);
  assert.equal(after.status, 'removed');
  assert.equal(after.removedBy, LEAD);
  assert.ok(after.removedAt !== null);
  assert.deepEqual(after.live, { grants: 0, sessions: 0, tokens: 0, identities: 0, apps: 0 });

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

test('only owners see reports, and only about someone who exists', async () => {
  await assert.rejects(dev.members.get(`user:${DEV}`), { status: 403 });
  await assert.rejects(root.members.get('user:nobody@acme.example'), { status: 404 });

  const rootReport = await lead.members.get(`user:${ROOT}`);
  assert.equal(rootReport.status, 'active');
  assert.equal(rootReport.instanceRole, 'owner');
});

for (const readmitFirst of [false, true]) {
  test(`a linking callback authenticated before removal is refused${readmitFirst ? ' after re-admission too' : ''}`, async () => {
    const browser = await browserSession(DEV, 'original');
    const stale = { ...await contextFor(deps, DEV), credentialId: browser.id };
    await root.members.remove(`user:${DEV}`);
    if (readmitFirst) await root.members.add(`user:${DEV}`);
    assert.deepEqual(await signin.linkIdentity(stale, {
      provider: 'github', subject: 'personal', emails: ['personal@example.com'], name: null,
    }), { ok: false, reason: 'deactivated' });
    if (!readmitFirst) await root.members.add(`user:${DEV}`);
    assert.deepEqual(await signin.completeSignin({
      provider: 'github', subject: 'personal', emails: ['personal@example.com'], name: null,
    }, meta()), { ok: false, reason: 'not_registered' });
  });
}

test('a linking callback rechecks the session that authenticated it', async () => {
  const browser = await browserSession(DEV, 'original');
  const stale = { ...await contextFor(deps, DEV), credentialId: browser.id };
  await signin.signOut(browser.token, meta());
  assert.deepEqual(await signin.linkIdentity(stale, {
    provider: 'github', subject: 'personal', emails: [], name: null,
  }), { ok: false, reason: 'deactivated' });
});

test('a failed app transaction cannot revive credentials when the vault re-admits a member', async () => {
  const browser = await browserSession(DEV, 'original');
  const cli = await cliSession(DEV);
  const service = await lead.tokens.issue(`token:${SERVICE}`, { label: 'ci', expiresInDays: 30 });
  // The vault has committed, but none of the app transaction survives.
  const failed = new Proxy(deps.db, {
    get(target, property) {
      if (property !== 'transaction') return Reflect.get(target, property);
      return (work: Parameters<typeof target.transaction>[0]) => target.transaction(async (tx) => {
        await work(tx);
        throw new Error('simulated app commit failure');
      });
    },
  });
  const failingRoot = clientFor({ ...deps, db: failed }, ROOT);
  for (const principal of [`user:${DEV}`, `token:${SERVICE}`]) {
    await assert.rejects(failingRoot.members.remove(principal), { status: 500 });
    assert.equal((await deps.vault.access(principal)).status, 'removed');
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal })).ok, true);
  }
  assert.equal((await db.owner.select().from(credentials).where(isNull(credentials.revokedAt))).length, 3,
    'the directory sweep rolled back, so generation must enforce removal');
  for (const token of [browser.token, cli.token, service.token]) {
    await assert.rejects(signin.verify(token), /unknown, expired or revoked/);
  }
  assert.deepEqual(await signin.completeSignin({
    provider: 'github', subject: 'original', emails: [], name: null,
  }, meta()), { ok: false, reason: 'deactivated' });
  // Retrying admission cleans up stale directory records and allows a fresh binding.
  await root.members.add(`user:${DEV}`);
  const fresh = await browserSession(DEV, 'replacement');
  assert.equal((await signin.verify(fresh.token)).id, DEV);
});

test('device approval cannot survive removal when the vault clock moves backwards', async () => {
  const started = await signin.startDevice({ clientLabel: 'laptop', sourceIp: IP });
  await signin.decideDevice(await contextFor(deps, DEV), started.userCode, true);
  deps.vault.advance(-60_000);
  await root.members.remove(`user:${DEV}`);
  await root.members.add(`user:${DEV}`);
  assert.deepEqual(await signin.pollDevice(started.deviceCode, meta()), { status: 'denied' });
});

for (const flow of ['browser', 'link', 'device approval', 'device poll', 'service token'] as const) {
  test(`${flow} cannot finish with a generation observed before removal and re-admission`, async (t) => {
    if (flow === 'link') await browserSession(DEV, 'existing-account');
    const asker = await contextFor(deps, flow === 'service token' ? ROOT : DEV);
    const device = flow.startsWith('device') ? await signin.startDevice({ clientLabel: null, sourceIp: IP }) : null;
    if (flow === 'device poll') await signin.decideDevice(asker, device!.userCode, true);
    const member = flow === 'service token' ? `token:${SERVICE}` : `user:${DEV}`;
    const access = deps.vault.access;
    const generation = (await access(member)).generation;
    let interrupted = false;
    t.mock.method(deps.vault, 'access', async (principal: string) => {
      const standing = await access(principal);
      if (principal === member && !interrupted) {
        interrupted = true;
        await root.members.remove(member);
        await root.members.add(member);
      }
      return standing;
    });

    const profile = { provider: 'github', subject: 'late-account', emails: [DEV], name: null };
    switch (flow) {
      case 'browser':
        assert.deepEqual(await signin.completeSignin(profile, meta()), { ok: false, reason: 'deactivated' });
        break;
      case 'link':
        assert.deepEqual(await signin.linkIdentity(asker, profile), { ok: false, reason: 'deactivated' });
        break;
      case 'device approval':
        await assert.rejects(signin.decideDevice(asker, device!.userCode, true), { status: 403 });
        // Refused before it committed: the code waits for another decision.
        assert.deepEqual(await signin.pollDevice(device!.deviceCode, meta()), { status: 'pending' });
        break;
      case 'device poll':
        assert.deepEqual(await signin.pollDevice(device!.deviceCode, meta()), { status: 'denied' });
        break;
      case 'service token':
        await assert.rejects(signin.issueServiceToken(asker, SERVICE, { label: null, expiresInDays: 1 }), { status: 404 });
        break;
    }
    assert.equal(interrupted, true);
    assert.ok((await access(member)).generation > generation);
    assert.equal((await db.owner.select().from(credentials).where(isNull(credentials.revokedAt))).length, 0);
    if (flow !== 'service token') {
      const fresh = await browserSession(DEV, 'fresh-account');
      assert.equal((await signin.verify(fresh.token)).id, DEV);
    }
  });
}

test('a removal sweep delayed past re-admission preserves the new session and binding', async (t) => {
  const old = await browserSession(DEV, 'old-account');
  const remove = deps.vault.remove;
  let fresh: Awaited<ReturnType<typeof browserSession>> | undefined;
  t.mock.method(deps.vault, 'remove', async (input: Parameters<typeof remove>[0]) => {
    const removed = await remove(input);
    await root.members.add(`user:${DEV}`);
    fresh = await browserSession(DEV, 'fresh-account');
    return removed;
  });
  await root.members.remove(`user:${DEV}`);
  await assert.rejects(signin.verify(old.token));
  assert.ok(fresh);
  assert.equal((await signin.verify(fresh.token)).id, DEV);
  assert.equal((await signin.listIdentities(await contextFor(deps, DEV))).length, 1);
});
