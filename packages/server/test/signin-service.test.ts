import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { defineSignin, generateToken, github, google, oidc, hashToken, isCoffreToken } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { count, eq, isNotNull, isNull, sql, type SQL } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';

import {
  auditLog,
  credentials,
  deviceAuthorizations,
  identities,
  principals,
} from './db/tables.ts';
import { authMac } from '../src/auth-rows.ts';
import { verifyAudit } from '../src/api/audit.ts';
import {
  normalizeUserCode,
  SigninService,
  type Asker,
  type PendingState,
  type SignedInAccount,
} from '../src/api/signin.ts';
import {
  clientFor,
  contextFor,
  openTestDatabase,
  resetDatabase,
  testDeps,
  type FixtureDeps,
} from './api-fixture.ts';
import { actorParts } from '../src/db/audit.ts';

const ROOT = 'admin@acme.example';
const LEAD = 'lead@acme.example';
const DEV = 'dev@acme.example';
const GONE = 'gone@acme.example';
const SERVICE = 'ci-deploy';
const RETIRED = 'retired-bot';
const IP = '203.0.113.7';

const CONFIG = defineSignin({
  publicUrl: 'https://secrets.acme.example',
  providers: [
    github({ clientId: 'gh-id', clientSecret: 'gh-secret' }),
    google({ clientId: 'g-id', clientSecret: 'g-secret' }),
  ],
  browserSessionHours: 12,
  cliSessionDays: 30,
});

let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let signin: SigninService;
let root: Asker;
let lead: Asker;
let dev: Asker;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: CONFIG });
  deps.signin = signin;
  await db.owner.insert(principals).values(
    [
      ['user', LEAD],
      ['user', DEV],
      ['user', GONE],
      ['service', SERVICE],
      ['service', RETIRED],
    ].map(([principalType, principalId]) => ({ principalType, principalId, createdBy: ROOT })),
  );
  // Who is in is the vault's to say.
  for (const id of [LEAD, DEV, GONE, SERVICE, RETIRED]) {
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: member(id), owner: id === LEAD })).ok, true);
  }
  await deactivate(GONE);
  await deactivate(RETIRED);
  [root, lead, dev] = await Promise.all([as(ROOT), as(LEAD), as(DEV)]);
});

function as(id: string, type: 'user' | 'service' = 'user'): Promise<Asker> {
  return contextFor(deps, id, type);
}

function profile(provider: string, subject: string, emails: string[], name: string | null = null): SignedInAccount {
  return { provider, subject, emails, name };
}

function meta(label: string | null = 'Firefox on macOS') {
  return { requestId: randomUUID(), sourceIp: IP, label };
}

async function auditRows() {
  const rows = await db.owner
    .select({
      action: auditLog.action,
      decision: auditLog.decision,
      actor: auditLog.actor,
      sourceIp: auditLog.sourceIp,
      metadata: auditLog.metadata,
    })
    .from(auditLog)
    .where(eq(auditLog.author, 'app'))
    .orderBy(auditLog.seq);
  return rows.map(({ actor, ...row }) => ({
    ...row,
    ...actorParts(actor),
    metadata: JSON.parse(row.metadata) as Record<string, unknown>,
  }));
}

async function auditActions(): Promise<string[]> {
  return (await auditRows()).map((row) => `${row.action} ${row.decision} ${row.actorId}`);
}

async function countRows(table: PgTable, where?: SQL): Promise<number> {
  const [row] = await db.owner.select({ n: count() }).from(table).where(where);
  return row.n;
}

/** `user:dev@acme.example`, or `token:ci-deploy`: people have an @. */
function member(id: string): string {
  return id.includes('@') ? `user:${id}` : `token:${id}`;
}

/** Remove someone in the vault, or admit them again: the only switch there is. */
async function deactivate(id: string, active = false): Promise<void> {
  const change = { actor: `user:${ROOT}`, principal: member(id) };
  const result = active ? await deps.vault.admit(change) : await deps.vault.remove(change);
  assert.equal(result.ok, true);
}

async function identityEmail(): Promise<string | null> {
  const [row] = await db.owner.select({ email: identities.email }).from(identities);
  return row.email;
}

async function credentialRow(id: string) {
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, id));
  return row;
}

const aSecondAgo = () => new Date(Date.now() - 1000);

/** Set an authentic past expiry; tampering is tested separately. */
async function expire(table: typeof credentials | typeof deviceAuthorizations, where?: SQL) {
  const expiresAt = aSecondAgo();
  const kind = table === credentials ? 'credentials' : 'device_authorizations';
  for (const row of await db.owner.select().from(table).where(where)) {
    await db.owner.update(table).set({
      expiresAt, authMac: authMac(deps.chainKey, kind, { ...row, expiresAt }),
    }).where(eq(table.id, row.id));
  }
}

test('a credential inserted by the database owner cannot authenticate', async (t) => {
  const report = t.mock.method(console, 'error', () => {});
  const issued = await signin.issueServiceToken(root, SERVICE, { label: null, expiresInDays: 1 });
  const row = await credentialRow(issued.id);
  const token = generateToken('service');
  const id = randomUUID();
  await db.owner.insert(credentials).values({ ...row, id, tokenHash: hashToken(token) });
  await assert.rejects(signin.verify(token), /authentic|tamper|unknown/i);
  assert.deepEqual(report.mock.calls[0].arguments[0], { event: 'auth_row_tampered', table: 'credentials', id });
});

test('an identity binding edited by the database owner cannot sign in', async () => {
  await signedIn(profile('github', 'legitimate-account', [DEV]));
  await db.owner.update(identities).set({ subject: 'attacker-account' });
  await assert.rejects(signin.completeSignin(profile('github', 'attacker-account', []), meta()), /authentic|tamper/i);
});

test('editing a credential generation cannot revive a removed membership', async () => {
  const issued = await signin.issueServiceToken(root, SERVICE, { label: null, expiresInDays: 1 });
  await deactivate(SERVICE);
  await deactivate(SERVICE, true);
  const { generation } = await deps.vault.access(member(SERVICE));
  await db.owner.update(credentials).set({ generation }).where(eq(credentials.id, issued.id));
  await assert.rejects(signin.verify(issued.token), /authentic|tamper|unknown/i);
});

test('a device approval forged by the database owner cannot mint a session', async () => {
  const started = await signin.startDevice({ clientLabel: 'attacker', sourceIp: IP });
  const { generation } = await deps.vault.access(member(DEV));
  await db.owner.update(deviceAuthorizations).set({
    decision: 'approved', decidedAt: new Date(), principalType: 'user', principalId: DEV, generation,
  });
  await assert.rejects(signin.pollDevice(started.deviceCode, meta()), /authentic|tamper/i);
  assert.equal(await countRows(credentials), 0);
});

test('an undecided device row cannot name an approving principal', async () => {
  await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await assert.rejects(db.owner.update(deviceAuthorizations).set({ principalType: 'user', principalId: DEV }));
});

test('the database owner cannot extend a credential or undo its revocation', async () => {
  const issued = await signin.issueServiceToken(root, SERVICE, { label: null, expiresInDays: 1 });
  const original = await credentialRow(issued.id);
  await db.owner.update(credentials).set({ expiresAt: new Date(Date.now() + 7 * 86_400_000) });
  await assert.rejects(signin.verify(issued.token), /authentication/);
  await db.owner.update(credentials).set({ expiresAt: original.expiresAt });
  await signin.revokeCredential(root, issued.id);
  await db.owner.update(credentials).set({ revokedAt: null });
  await assert.rejects(signin.verify(issued.token), /authentication/);
});

test('the database owner cannot move a short device code to another request', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  const moved = started.userCode === 'BCDF-GHJK' ? 'BCDF-GHJL' : 'BCDF-GHJK';
  await db.owner.update(deviceAuthorizations).set({ userCode: moved });
  await assert.rejects(signin.decideDevice(dev, moved, true), /authentication/);
  assert.equal(await countRows(credentials), 0);
});

for (const mismatch of ['member', 'generation'] as const) {
  test(`a credential cannot reference an identity with a different ${mismatch}`, async () => {
    const { credential } = await signedIn(profile('github', '101', [DEV]));
    const row = await credentialRow(credential.id);
    await assert.rejects(db.owner.insert(credentials).values({
      ...row, id: randomUUID(), tokenHash: randomBytes(32),
      ...(mismatch === 'member' ? { principalId: LEAD } : { generation: row.generation + 1 }),
    }));
  });
}

/** Sign in, expecting success. */
async function signedIn(p: SignedInAccount) {
  const result = await signin.completeSignin(p, meta());
  assert.equal(result.ok, true, `expected ${p.emails.join(',')} to be let in`);
  if (!result.ok) throw new Error('unreachable');
  return result;
}

function hoursFromNow(iso: string): number {
  return (Date.parse(iso) - Date.now()) / 3_600_000;
}

// --- signing in ---------------------------------------------------------------

test('an email no one invited is refused and the refusal is audited', async () => {
  assert.deepEqual(
    await signin.completeSignin(profile('github', '9001', ['stranger@example.com']), meta()),
    { ok: false, reason: 'not_registered' },
  );
  assert.deepEqual(
    await signin.completeSignin(profile('github', '9002', []), meta()),
    { ok: false, reason: 'not_registered' },
  );

  const rows = await auditRows();
  assert.deepEqual(
    rows.map((row) => [row.action, row.decision, row.actorType, row.actorId, row.sourceIp]),
    [
      ['auth.signin', 'deny', 'user', 'stranger@example.com', IP],
      ['auth.signin', 'deny', 'user', 'github:9002', IP],
    ],
  );
  assert.deepEqual(rows[0].metadata, {
    provider: 'github',
    subject: '9001',
    emails: ['stranger@example.com'],
    reason: 'not_registered',
  });
  assert.equal(await countRows(identities), 0);
  assert.equal(await countRows(credentials), 0);
});

test('a first sign-in with an invited email binds the account and opens a browser session', async () => {
  const result = await signedIn(profile('github', '101', [DEV], 'Devon Dev'));
  assert.deepEqual(result.principal, { type: 'user', id: DEV });
  assert.match(result.credential.token, /^coffre_web_/);
  assert.ok(isCoffreToken(result.credential.token));
  assert.ok(Math.abs(hoursFromNow(result.credential.expiresAt) - 12) < 0.01);

  const identityRows = await db.owner.select().from(identities);
  assert.equal(identityRows.length, 1);
  const [identity] = identityRows;
  assert.equal(identity.provider, 'github');
  assert.equal(identity.subject, '101');
  assert.equal(identity.principalId, DEV);
  assert.equal(identity.email, DEV);
  assert.equal(identity.createdBy, DEV);
  assert.ok(identity.lastSignInAt);

  const credentialRows = await db.owner.select().from(credentials);
  assert.equal(credentialRows.length, 1);
  const [credential] = credentialRows;
  assert.equal(credential.id, result.credential.id);
  assert.equal(credential.kind, 'browser');
  assert.equal(credential.identityId, identity.id);
  assert.equal(credential.label, 'Firefox on macOS');
  assert.deepEqual(credential.tokenHash, hashToken(result.credential.token));
  assert.equal(credential.tokenHint, `coffre_web_…${result.credential.token.slice(-4)}`);
  assert.equal(
    JSON.stringify(credential).includes(result.credential.token.slice(11)),
    false,
    'the token itself is stored nowhere',
  );

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actorId}`), [
    `identity.bind allow ${DEV}`,
    `auth.signin allow ${DEV}`,
  ]);
  assert.deepEqual(rows[0].metadata, {
    provider: 'github',
    subject: '101',
    emails: [DEV],
    identityId: identity.id,
    matchedEmail: DEV,
  });
  assert.deepEqual(rows[1].metadata, {
    provider: 'github',
    subject: '101',
    emails: [DEV],
    identityId: identity.id,
    credentialId: result.credential.id,
  });

  assert.deepEqual(await signin.verify(result.credential.token), {
    type: 'user',
    id: DEV,
    email: DEV,
    subject: '101',
    credentialId: result.credential.id,
    credentialGeneration: 0,
  });
});

test('any verified email on the account may match, not only the primary one', async () => {
  const result = await signedIn(profile('google', 'g-7', ['personal@example.com', DEV]));
  assert.deepEqual(result.principal, { type: 'user', id: DEV });
  const [bind] = await auditRows();
  assert.equal(bind.metadata.matchedEmail, DEV);
  assert.equal(await identityEmail(), 'personal@example.com', 'the primary address is remembered');
});

test('once bound, the account signs in as its person whatever its email says', async () => {
  await signedIn(profile('github', '101', [DEV]));

  const renamed = await signedIn(profile('github', '101', ['devon@personal.example']));
  assert.deepEqual(renamed.principal, { type: 'user', id: DEV });
  assert.equal(await identityEmail(), 'devon@personal.example');

  const noEmail = await signedIn(profile('github', '101', []));
  assert.deepEqual(noEmail.principal, { type: 'user', id: DEV });
  assert.equal(
    await identityEmail(),
    'devon@personal.example',
    'an account without email keeps the last one seen',
  );

  // Even an email that names someone else: the binding wins.
  const confusing = await signedIn(profile('github', '101', [LEAD]));
  assert.deepEqual(confusing.principal, { type: 'user', id: DEV });

  assert.equal(await countRows(identities), 1);
  assert.equal(await countRows(credentials), 4);
  assert.deepEqual(await auditActions(), [
    `identity.bind allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signin allow ${DEV}`,
  ]);
});

test('another account with the same email is refused while one is bound', async () => {
  await signedIn(profile('github', '101', [DEV]));

  // A second GitHub account claiming the address, e.g. after it was recycled.
  assert.deepEqual(
    await signin.completeSignin(profile('github', '202', [DEV]), meta()),
    { ok: false, reason: 'account_mismatch' },
  );
  // Another provider is linked from the account page, not by email.
  assert.deepEqual(
    await signin.completeSignin(profile('google', 'g-1', [DEV]), meta()),
    { ok: false, reason: 'account_mismatch' },
  );

  const rows = await auditRows();
  assert.deepEqual(rows.slice(2).map((row) => [row.action, row.decision, row.actorId, row.metadata.reason]), [
    ['auth.signin', 'deny', DEV, 'account_mismatch'],
    ['auth.signin', 'deny', DEV, 'account_mismatch'],
  ]);
  assert.equal(await countRows(identities), 1);
  assert.equal(await countRows(credentials), 1);
});

test('racing first sign-ins bind one account per person', async () => {
  // Two different accounts claiming the same person at once: one wins.
  const raced = await Promise.all([
    signin.completeSignin(profile('github', '101', [DEV]), meta()),
    signin.completeSignin(profile('github', '202', [DEV]), meta()),
    signin.completeSignin(profile('google', 'g-dev', [DEV]), meta()),
  ]);
  assert.equal(raced.filter((result) => result.ok).length, 1);
  assert.deepEqual(
    raced.filter((result) => !result.ok),
    [
      { ok: false, reason: 'account_mismatch' },
      { ok: false, reason: 'account_mismatch' },
    ],
  );

  // The same account twice at once: bound once, both signed in.
  const twice = await Promise.all([
    signin.completeSignin(profile('github', '102', [LEAD]), meta()),
    signin.completeSignin(profile('github', '102', [LEAD]), meta()),
  ]);
  assert.deepEqual(twice.map((result) => result.ok), [true, true]);
  assert.equal(await countRows(identities, eq(identities.principalId, LEAD)), 1);
  assert.equal(await countRows(identities, eq(identities.principalId, DEV)), 1);
});

test('deactivated people are refused, bound or not, and their sessions stop', async () => {
  assert.deepEqual(
    await signin.completeSignin(profile('github', '303', [GONE]), meta()),
    { ok: false, reason: 'deactivated' },
  );

  const session = await signedIn(profile('github', '101', [DEV]));
  await deactivate(DEV);
  assert.deepEqual(
    await signin.completeSignin(profile('github', '101', [DEV]), meta()),
    { ok: false, reason: 'deactivated' },
  );
  // The credential belongs to the membership that just ended.
  await assert.rejects(signin.verify(session.credential.token), /unknown, expired or revoked/);
  assert.equal((await as(DEV)).caller.registered, false);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.decision, row.actorId, row.metadata.reason]), [
    ['auth.signin', 'deny', GONE, 'deactivated'],
    ['identity.bind', 'allow', DEV, undefined],
    ['auth.signin', 'allow', DEV, undefined],
    ['auth.signin', 'deny', DEV, 'deactivated'],
  ]);
  assert.equal(await countRows(identities, eq(identities.principalId, GONE)), 0);
});

test('a root admin needs no invitation, and nobody can remove them', async () => {
  const first = await signedIn(profile('google', 'g-root', [ROOT]));
  assert.deepEqual(first.principal, { type: 'user', id: ROOT });
  const [row] = await db.owner
    .select({ createdBy: principals.createdBy })
    .from(principals)
    .where(eq(principals.principalId, ROOT));
  assert.deepEqual(row, { createdBy: 'system:signin' });
  assert.equal((await signin.verify(first.credential.token)).id, ROOT);

  const removed = await deps.vault.remove({ actor: `user:${ROOT}`, principal: member(ROOT) });
  assert.equal(removed.ok || removed.refusal.code, 'root_admin');
  const again = await signedIn(profile('google', 'g-root', [ROOT]));
  assert.equal((await signin.verify(again.credential.token)).id, ROOT);
});

// --- verifying, signing out, revoking -------------------------------------------

test('verify refuses what is not a live coffre credential', async () => {
  const { credential } = await signedIn(profile('github', '101', [DEV]));

  await assert.rejects(signin.verify('eyJhbGciOiJSUzI1NiJ9.e30.x'), /not a coffre credential/);
  await assert.rejects(signin.verify(`coffre_web_${'A'.repeat(43)}`), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(credential.token.replace('coffre_web_', 'coffre_cli_')), /unknown/);

  await expire(credentials);
  await assert.rejects(signin.verify(credential.token), /unknown, expired or revoked/);
  assert.deepEqual(await signin.listSessions(dev, null), []);
});

test('verify records when and where a credential was last used, at most every five minutes', async () => {
  const { credential } = await signedIn(profile('github', '101', [DEV]));
  const lastUsed = async () => {
    const { lastUsedAt, lastUsedIp } = await credentialRow(credential.id);
    return { lastUsedAt, lastUsedIp };
  };

  assert.equal((await lastUsed()).lastUsedAt, null);
  await signin.verify(credential.token, { sourceIp: '198.51.100.1' });
  const first = await lastUsed();
  assert.ok(first.lastUsedAt);
  assert.equal(first.lastUsedIp, '198.51.100.1');

  await signin.verify(credential.token, { sourceIp: '198.51.100.2' });
  assert.deepEqual(await lastUsed(), first, 'not rewritten within five minutes');

  await db.owner.update(credentials).set({ lastUsedAt: new Date(Date.now() - 6 * 60_000) });
  await signin.verify(credential.token, { sourceIp: '198.51.100.3' });
  assert.equal((await lastUsed()).lastUsedIp, '198.51.100.3');
});

test('signing out revokes that credential only, once, and is audited', async () => {
  const kept = await signedIn(profile('github', '101', [DEV]));
  const ended = await signedIn(profile('github', '101', [DEV]));

  await signin.signOut(ended.credential.token, { requestId: randomUUID(), sourceIp: IP });
  await assert.rejects(signin.verify(ended.credential.token), /revoked/);
  assert.equal((await signin.verify(kept.credential.token)).id, DEV);

  // A second sign-out, an unknown token and garbage are all quiet no-ops.
  await signin.signOut(ended.credential.token, { requestId: randomUUID(), sourceIp: IP });
  await signin.signOut(`coffre_web_${'B'.repeat(43)}`, { requestId: randomUUID(), sourceIp: IP });
  await signin.signOut('not a token', { requestId: randomUUID(), sourceIp: IP });

  const revoked = await credentialRow(ended.credential.id);
  assert.equal(revoked.revokedBy, DEV);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actorId}`), [
    `identity.bind allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signout allow ${DEV}`,
  ]);
  assert.deepEqual(rows[3].metadata, { credentialId: ended.credential.id, kind: 'browser' });
});

test('sign-ins stay in the log, and the audit list leaves them out when asked', async () => {
  const kept = await signedIn(profile('github', '101', [DEV]));
  await signin.completeSignin(profile('github', '9001', ['stranger@example.com']), meta());
  await signin.signOut(kept.credential.token, { requestId: randomUUID(), sourceIp: IP });

  const audit = clientFor(deps, ROOT).audit;
  const actions = async (query: Parameters<typeof audit.list>[0]) =>
    (await audit.list(query)).entries.map((entry) => `${entry.action} ${entry.decision}`);
  assert.deepEqual(await actions({}), [
    'auth.signout allow',
    'auth.signin deny',
    'auth.signin allow',
    'identity.bind allow',
  ]);
  assert.deepEqual(await actions({ exclude: 'sign-ins' }), ['identity.bind allow']);
  // Filtered by the query, so a page of one is not an empty page.
  assert.deepEqual(await actions({ exclude: 'sign-ins', limit: 1 }), ['identity.bind allow']);
  // And the chain still covers what the list left out.
  assert.equal((await audit.verify()).ok, true);
});

test('people revoke their own credentials; only owners revoke anyone else\'s', async () => {
  const devSession = await signedIn(profile('github', '101', [DEV]));
  const devOther = await signedIn(profile('github', '101', [DEV]));
  const leadSession = await signedIn(profile('github', '102', [LEAD]));
  const token = await signin.issueServiceToken(lead, SERVICE, { label: 'deploys', expiresInDays: 30 });
  const setup = (await auditRows()).length;

  await assert.rejects(signin.revokeCredential(dev, leadSession.credential.id), { status: 403 });
  await assert.rejects(signin.revokeCredential(dev, token.id), { status: 403 });
  assert.equal((await signin.verify(leadSession.credential.token)).id, LEAD);

  assert.deepEqual(await signin.revokeCredential(dev, devOther.credential.id), { revoked: true });
  await assert.rejects(signin.verify(devOther.credential.token), /revoked/);
  await assert.rejects(signin.revokeCredential(dev, devOther.credential.id), { status: 404 }, 'already revoked');
  await assert.rejects(signin.revokeCredential(dev, randomUUID()), { status: 404 });

  assert.deepEqual(await signin.revokeCredential(lead, devSession.credential.id), { revoked: true });
  assert.deepEqual(await signin.revokeCredential(root, token.id), { revoked: true });
  await assert.rejects(signin.verify(devSession.credential.token), /revoked/);
  await assert.rejects(signin.verify(token.token), /revoked/);

  const revokedBy = await db.owner
    .select({ id: credentials.id, revokedBy: credentials.revokedBy })
    .from(credentials)
    .where(isNotNull(credentials.revokedAt));
  assert.deepEqual(
    Object.fromEntries(revokedBy.map((row) => [row.id, row.revokedBy])),
    { [devOther.credential.id]: DEV, [devSession.credential.id]: LEAD, [token.id]: ROOT },
  );

  const rows = (await auditRows()).slice(setup);
  assert.deepEqual(
    rows.map((row) => [row.action, row.decision, row.actorId, row.metadata.reason ?? null]),
    [
      ['credential.revoke', 'deny', DEV, 'requires_instance_owner'],
      ['credential.revoke', 'deny', DEV, 'requires_instance_owner'],
      ['credential.revoke', 'allow', DEV, null],
      ['credential.revoke', 'deny', DEV, 'unknown_credential'],
      ['credential.revoke', 'deny', DEV, 'unknown_credential'],
      ['credential.revoke', 'allow', LEAD, null],
      ['credential.revoke', 'allow', ROOT, null],
    ],
  );
  assert.deepEqual(rows[5].metadata, {
    credentialId: devSession.credential.id,
    kind: 'browser',
    principalType: 'user',
    principalId: DEV,
  });
  assert.deepEqual(rows[6].metadata, {
    credentialId: token.id,
    kind: 'service',
    principalType: 'service',
    principalId: SERVICE,
  });
});

// --- linking and unlinking --------------------------------------------------------

test('a signed-in person links another account, which then signs them in', async () => {
  await signedIn(profile('github', '101', [DEV]));

  // The linked account's email need not match anything.
  assert.deepEqual(
    await signin.linkIdentity(dev, profile('google', 'g-dev', ['devon@gmail.example'])),
    { ok: true },
  );
  const viaGoogle = await signedIn(profile('google', 'g-dev', ['devon@gmail.example']));
  assert.deepEqual(viaGoogle.principal, { type: 'user', id: DEV });

  // Linking the same account again changes nothing and writes nothing.
  const before = await auditRows();
  assert.deepEqual(await signin.linkIdentity(dev, profile('google', 'g-dev', [])), { ok: true });
  assert.equal((await auditRows()).length, before.length);

  const identities = await signin.listIdentities(dev);
  assert.deepEqual(identities.map((row) => [row.provider, row.email]), [
    ['github', DEV],
    ['google', 'devon@gmail.example'],
  ]);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actorId}`), [
    `identity.bind allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `identity.bind allow ${DEV}`,
    `auth.signin allow ${DEV}`,
  ]);
  assert.deepEqual(rows[2].metadata, {
    provider: 'google',
    subject: 'g-dev',
    emails: ['devon@gmail.example'],
    identityId: identities[1].id,
  });
});

test('an account bound to someone else cannot be linked, and services link nothing', async () => {
  await signedIn(profile('github', '102', [LEAD]));
  assert.deepEqual(
    await signin.linkIdentity(dev, profile('github', '102', [LEAD])),
    { ok: false, reason: 'already_linked' },
  );
  await assert.rejects(
    signin.linkIdentity(await as(SERVICE, 'service'), profile('github', '555', [])),
    { status: 403 },
  );

  assert.equal(await countRows(identities), 1);
  const rows = await auditRows();
  assert.deepEqual(rows.slice(2).map((row) => [row.action, row.decision, row.actorId, row.metadata.reason]), [
    ['identity.bind', 'deny', DEV, 'already_linked'],
  ]);
});

test('unlinking an account ends the sessions it opened, and no others', async () => {
  const viaGithub = await signedIn(profile('github', '101', [DEV]));
  await signin.linkIdentity(dev, profile('google', 'g-dev', []));
  const viaGoogle = await signedIn(profile('google', 'g-dev', []));
  const cli = await approvedCliSession(dev);

  const [githubIdentity] = await signin.listIdentities(dev);
  assert.equal(githubIdentity.provider, 'github');
  assert.deepEqual(await signin.unlinkIdentity(dev, githubIdentity.id), { unlinked: true });

  await assert.rejects(signin.verify(viaGithub.credential.token), /revoked/);
  assert.equal((await signin.verify(viaGoogle.credential.token)).id, DEV);
  assert.equal((await signin.verify(cli.token)).id, DEV);
  assert.deepEqual((await signin.listIdentities(dev)).map((row) => row.provider), ['google']);

  const unbind = (await auditRows()).find((row) => row.action === 'identity.unbind');
  assert.ok(unbind);
  assert.equal(unbind.decision, 'allow');
  assert.equal(unbind.actorId, DEV);
  assert.deepEqual(unbind.metadata, {
    identityId: githubIdentity.id,
    provider: 'github',
    subject: '101',
    sessionsEnded: 1,
  });

  // The GitHub account is a stranger again: it cannot sign in while the
  // Google one is bound, and cannot be unlinked twice.
  assert.deepEqual(
    await signin.completeSignin(profile('github', '101', [DEV]), meta()),
    { ok: false, reason: 'account_mismatch' },
  );
  await assert.rejects(signin.unlinkIdentity(dev, githubIdentity.id), { status: 404 });
});

test('an unlinked account can be bound again once the person has none', async () => {
  await signedIn(profile('github', '101', [DEV]));
  const [identity] = await signin.listIdentities(dev);
  await signin.unlinkIdentity(dev, identity.id);

  // A different account with the same email, now that none is bound.
  const result = await signedIn(profile('github', '202', [DEV]));
  assert.deepEqual(result.principal, { type: 'user', id: DEV });
  // And the old account again, after that one is gone too.
  const [second] = await signin.listIdentities(dev);
  await signin.unlinkIdentity(dev, second.id);
  await signedIn(profile('github', '101', [DEV]));
  assert.equal(await countRows(identities, isNull(identities.revokedAt)), 1);
  assert.equal(await countRows(identities), 3);
});

test('nobody unlinks someone else\'s account', async () => {
  await signedIn(profile('github', '102', [LEAD]));
  const [identity] = await signin.listIdentities(lead);
  await assert.rejects(signin.unlinkIdentity(dev, identity.id), { status: 404 });
  await assert.rejects(signin.unlinkIdentity(root, identity.id), { status: 404 });
  assert.equal((await signin.listIdentities(lead)).length, 1);

  const denied = (await auditRows()).filter((row) => row.action === 'identity.unbind');
  assert.deepEqual(denied.map((row) => [row.decision, row.actorId, row.metadata.reason]), [
    ['deny', DEV, 'unknown_identity'],
    ['deny', ROOT, 'unknown_identity'],
  ]);
});

test('the session list shows live browser and CLI sessions only, and marks the current one', async () => {
  const older = await signedIn(profile('github', '101', [DEV]));
  const current = await signedIn(profile('github', '101', [DEV]));
  const cli = await approvedCliSession(dev, 'coffre CLI on laptop');
  const ended = await signedIn(profile('github', '101', [DEV]));
  await signin.signOut(ended.credential.token, { requestId: randomUUID(), sourceIp: IP });
  const stale = await signedIn(profile('github', '101', [DEV]));
  await expire(credentials, eq(credentials.id, stale.credential.id));
  await signedIn(profile('github', '102', [LEAD]));

  await signin.verify(older.credential.token, { sourceIp: '198.51.100.9' });

  const sessions = await signin.listSessions(dev, current.credential.id);
  assert.deepEqual(
    sessions.map((row) => [row.id, row.kind, row.provider, row.current]),
    [
      [older.credential.id, 'browser', 'github', false],
      [cli.id, 'cli', null, false],
      [current.credential.id, 'browser', 'github', true],
    ],
  );
  assert.equal(sessions[0].lastUsedIp, '198.51.100.9');
  assert.equal(sessions[1].label, 'coffre CLI on laptop');
  assert.equal(sessions[2].label, 'Firefox on macOS');
  assert.equal(sessions[2].hint, `coffre_web_…${current.credential.token.slice(-4)}`);
});

// --- service tokens ---------------------------------------------------------------

test('owners issue service tokens that verify as the service', async () => {
  const issued = await signin.issueServiceToken(lead, SERVICE, { label: 'deploys', expiresInDays: 30 });
  assert.match(issued.token, /^coffre_svc_/);
  assert.ok(Math.abs(hoursFromNow(issued.expiresAt) - 30 * 24) < 0.01);
  assert.deepEqual(await signin.verify(issued.token), {
    type: 'service',
    id: SERVICE,
    commonName: SERVICE,
    credentialId: issued.id,
    credentialGeneration: 0,
  });

  const byRoot = await signin.issueServiceToken(root, SERVICE, { label: null, expiresInDays: 366 });
  assert.equal((await signin.verify(byRoot.token)).id, SERVICE);

  const row = await credentialRow(issued.id);
  assert.equal(row.kind, 'service');
  assert.equal(row.principalType, 'service');
  assert.equal(row.identityId, null);
  assert.equal(row.createdBy, LEAD);
  assert.equal(row.label, 'deploys');

  const rows = await auditRows();
  assert.deepEqual(rows.map((r) => `${r.action} ${r.decision} ${r.actorId}`), [
    `credential.issue allow ${LEAD}`,
    `credential.issue allow ${ROOT}`,
  ]);
  assert.deepEqual(rows[0].metadata, {
    kind: 'service',
    principalType: 'service',
    principalId: SERVICE,
    label: 'deploys',
    credentialId: issued.id,
    expiresAt: issued.expiresAt,
  });

  // A service's tokens do not show up as anyone's sessions.
  assert.deepEqual(await signin.listSessions(lead, null), []);
});

test('only owners issue service tokens, for active services, for 1 to 366 whole days', async () => {
  await assert.rejects(
    signin.issueServiceToken(dev, SERVICE, { label: null, expiresInDays: 30 }),
    { status: 403 },
  );
  await assert.rejects(
    signin.issueServiceToken(await as(SERVICE, 'service'), SERVICE, { label: null, expiresInDays: 30 }),
    { status: 403 },
    'a service does not mint its own tokens',
  );
  await assert.rejects(
    signin.issueServiceToken(lead, RETIRED, { label: null, expiresInDays: 30 }),
    { status: 404 },
  );
  await assert.rejects(
    signin.issueServiceToken(lead, 'no-such-service', { label: null, expiresInDays: 30 }),
    { status: 404 },
  );
  await assert.rejects(
    signin.issueServiceToken(lead, DEV, { label: null, expiresInDays: 30 }),
    { status: 404 },
    'a person is not a service',
  );
  for (const days of [0, 367, 1.5, Number.NaN]) {
    await assert.rejects(
      signin.issueServiceToken(lead, SERVICE, { label: null, expiresInDays: days }),
      { status: 400 },
      String(days),
    );
  }
  assert.equal(await countRows(credentials), 0);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.decision, row.actorId, row.metadata.reason]), [
    ['credential.issue', 'deny', DEV, 'requires_instance_owner'],
    ['credential.issue', 'deny', SERVICE, 'requires_instance_owner'],
    ['credential.issue', 'deny', LEAD, 'unknown_principal'],
    ['credential.issue', 'deny', LEAD, 'unknown_principal'],
    ['credential.issue', 'deny', LEAD, 'unknown_principal'],
  ]);
});

test('a service token stops working when the service is deactivated, revoked or expired', async () => {
  const deactivated = await signin.issueServiceToken(lead, SERVICE, { label: null, expiresInDays: 1 });
  await deactivate(SERVICE);
  assert.equal((await as(SERVICE, 'service')).caller.registered, false);
  await deactivate(SERVICE, true);
  await assert.rejects(signin.verify(deactivated.token), /unknown, expired or revoked/);
  assert.equal((await as(SERVICE, 'service')).caller.registered, true);

  await expire(credentials);
  await assert.rejects(signin.verify(deactivated.token), /unknown, expired or revoked/);
});

test('owners and the service itself list its live tokens; nobody else does', async () => {
  const first = await signin.issueServiceToken(lead, SERVICE, { label: 'first', expiresInDays: 30 });
  const second = await signin.issueServiceToken(root, SERVICE, { label: 'second', expiresInDays: 30 });
  const revoked = await signin.issueServiceToken(root, SERVICE, { label: 'revoked', expiresInDays: 30 });
  await signin.revokeCredential(root, revoked.id);

  const listed = await signin.listServiceTokens(lead, SERVICE);
  assert.deepEqual(listed.map((row) => [row.id, row.label, row.createdBy]), [
    [second.id, 'second', ROOT],
    [first.id, 'first', LEAD],
  ]);
  assert.equal(listed[0].hint, `coffre_svc_…${second.token.slice(-4)}`);
  assert.deepEqual(
    (await signin.listServiceTokens(await as(SERVICE, 'service'), SERVICE)).map((row) => row.id),
    [second.id, first.id],
  );
  assert.equal((await signin.listServiceTokens(root, SERVICE)).length, 2);

  await assert.rejects(signin.listServiceTokens(dev, SERVICE), { status: 403 });
  await assert.rejects(signin.listServiceTokens(await as(RETIRED, 'service'), SERVICE), { status: 403 });
});

// --- device flow ------------------------------------------------------------------

/** Run `coffre login` to completion for this person. */
async function approvedCliSession(ctx: Asker, clientLabel: string | null = null) {
  const started = await signin.startDevice({ clientLabel, sourceIp: IP });
  await signin.decideDevice(ctx, started.userCode, true);
  const polled = await signin.pollDevice(started.deviceCode, { requestId: randomUUID(), sourceIp: IP });
  assert.equal(polled.status, 'approved');
  if (polled.status !== 'approved') throw new Error('unreachable');
  return polled.credential;
}

function poll(deviceCode: string) {
  return signin.pollDevice(deviceCode, { requestId: randomUUID(), sourceIp: IP });
}

test('device flow: start, describe, approve, then one poll gets a CLI session', async () => {
  const started = await signin.startDevice({ clientLabel: 'coffre CLI on laptop', sourceIp: IP });
  assert.match(started.userCode, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
  assert.match(started.deviceCode, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(started.verificationUri, 'https://secrets.acme.example/auth/device');
  assert.equal(started.verificationUriComplete, `https://secrets.acme.example/auth/device?code=${started.userCode}`);
  assert.equal(started.expiresIn, 600);
  assert.equal(started.interval, 5);

  const [stored] = await db.owner.select().from(deviceAuthorizations);
  assert.deepEqual(stored.deviceCodeHash, hashToken(started.deviceCode), 'only a hash is stored');

  assert.deepEqual(await poll(started.deviceCode), { status: 'pending' });

  // People type the code any which way.
  const typed = started.userCode.toLowerCase().replace('-', ' ');
  const described = await signin.describeDevice(typed);
  assert.ok(described);
  assert.equal(described.userCode, started.userCode);
  assert.equal(described.clientLabel, 'coffre CLI on laptop');
  assert.equal(described.clientIp, IP);
  assert.ok(Math.abs((Date.parse(described.expiresAt) - Date.now()) / 1000 - 600) < 5);

  assert.deepEqual(await signin.decideDevice(dev, typed, true), { decided: true });
  assert.equal(await signin.describeDevice(started.userCode), null, 'a decided code is gone');

  const approved = await poll(started.deviceCode);
  assert.equal(approved.status, 'approved');
  if (approved.status !== 'approved') return;
  assert.deepEqual(approved.principal, { type: 'user', id: DEV });
  assert.match(approved.credential.token, /^coffre_cli_/);
  assert.ok(Math.abs(hoursFromNow(approved.credential.expiresAt) - 30 * 24) < 0.01);
  assert.deepEqual(await signin.verify(approved.credential.token), {
    type: 'user',
    id: DEV,
    email: DEV,
    subject: DEV,
    credentialId: approved.credential.id,
    credentialGeneration: 0,
  });

  // Exactly once.
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' });
  assert.equal(await countRows(credentials, eq(credentials.kind, 'cli')), 1);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actorId}`), [
    `device.approve allow ${DEV}`,
    `credential.issue allow ${DEV}`,
  ]);
  assert.deepEqual(rows[0].metadata, {
    deviceAuthorizationId: stored.id,
    clientLabel: 'coffre CLI on laptop',
    clientIp: IP,
  });
  assert.deepEqual(rows[1].metadata, {
    kind: 'cli',
    credentialId: approved.credential.id,
    deviceAuthorizationId: stored.id,
    clientLabel: 'coffre CLI on laptop',
    clientIp: IP,
  });
});

test('device flow: racing polls on an approved code yield one session', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await signin.decideDevice(dev, started.userCode, true);
  const polls = await Promise.all([1, 2, 3, 4].map(() => poll(started.deviceCode)));
  assert.deepEqual(polls.map((result) => result.status).sort(), ['approved', 'expired', 'expired', 'expired']);
  assert.equal(await countRows(credentials, eq(credentials.kind, 'cli')), 1);
});

test('device flow: a denied code polls as denied and never yields a token', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  assert.deepEqual(await signin.decideDevice(dev, started.userCode, false), { decided: true });
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });

  // Decided once: approving afterwards is refused.
  await assert.rejects(signin.decideDevice(dev, started.userCode, true), { status: 404 });
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });
  assert.equal(await countRows(credentials), 0);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.decision, row.actorId, row.metadata.reason]), [
    ['device.deny', 'allow', DEV, undefined],
    ['device.approve', 'deny', DEV, 'unknown_code'],
  ]);
});

test('device flow: an expired code cannot be described, decided or polled', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await expire(deviceAuthorizations);

  assert.equal(await signin.describeDevice(started.userCode), null);
  await assert.rejects(signin.decideDevice(dev, started.userCode, true), { status: 404 });
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' });

  const [row] = await auditRows();
  assert.deepEqual([row.action, row.decision, row.metadata], [
    'device.approve',
    'deny',
    { userCode: started.userCode, reason: 'unknown_code' },
  ]);
});

test('device flow: an approved code left unpolled past its expiry yields nothing', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await signin.decideDevice(dev, started.userCode, true);
  await expire(deviceAuthorizations);
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' });
  assert.equal(await countRows(credentials), 0);
});

test('device flow: unknown and malformed codes', async () => {
  assert.deepEqual(await poll('not-a-device-code'), { status: 'expired' });
  assert.equal(await signin.describeDevice('BCDF-GHJK'), null);
  assert.equal(await signin.describeDevice('AEIO-UUUU'), null, 'vowels are never issued');
  assert.equal(await signin.describeDevice('BCD'), null);

  await assert.rejects(signin.decideDevice(dev, 'BCDF-GHJK', true), { status: 404 });
  await assert.rejects(signin.decideDevice(dev, 'nonsense', false), { status: 404 });
  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.metadata.userCode, row.metadata.reason]), [
    ['device.approve', 'BCDF-GHJK', 'unknown_code'],
    ['device.deny', 'nonsense', 'unknown_code'],
  ]);

  assert.equal(normalizeUserCode(' bcdf ghjk '), 'BCDF-GHJK');
  assert.equal(normalizeUserCode('BCDFGHJK'), 'BCDF-GHJK');
  assert.equal(normalizeUserCode('BCDF-GHJ1'), null);
});

test('device flow: only people approve, and a person removed before the poll gets nothing', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await assert.rejects(
    signin.decideDevice(await as(SERVICE, 'service'), started.userCode, true),
    { status: 403 },
  );
  assert.ok(await signin.describeDevice(started.userCode), 'still waiting');

  await signin.decideDevice(dev, started.userCode, true);
  await deactivate(DEV);
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' }, 'consumed all the same');
  assert.equal(await countRows(credentials), 0);
});

test('device flow: open requests are capped per address and freed by a decision', async () => {
  const codes = [];
  for (let i = 0; i < 5; i += 1) codes.push(await signin.startDevice({ clientLabel: null, sourceIp: IP }));
  await assert.rejects(signin.startDevice({ clientLabel: null, sourceIp: IP }), { status: 429 });

  // Another address is unaffected.
  await signin.startDevice({ clientLabel: null, sourceIp: '198.51.100.20' });

  // A decided or expired request no longer counts.
  await signin.decideDevice(dev, codes[0].userCode, false);
  await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await assert.rejects(signin.startDevice({ clientLabel: null, sourceIp: IP }), { status: 429 });
  await db.owner
    .update(deviceAuthorizations)
    .set({ expiresAt: aSecondAgo() })
    .where(eq(deviceAuthorizations.userCode, codes[1].userCode));
  await signin.startDevice({ clientLabel: null, sourceIp: IP });

  // Starting writes no audit rows: the caller is anonymous.
  assert.deepEqual(await auditActions(), [`device.deny allow ${DEV}`]);
});

test('device flow: the client label is kept short', async () => {
  const credential = await approvedCliSession(dev, 'x'.repeat(500));
  const row = await credentialRow(credential.id);
  assert.equal(row.label?.length, 120);
});

// --- pending state ------------------------------------------------------------------

test('pending sign-ins survive the round trip sealed, and only for this instance', () => {
  const state: PendingState = {
    provider: 'github',
    state: 'st',
    codeVerifier: 'v'.repeat(43),
    nonce: null,
    next: '/projects/market',
    link: null,
  };
  const sealed = signin.sealPending(state);
  assert.equal(sealed.maxAge, 600);
  assert.equal(sealed.value.includes('market'), false);
  assert.deepEqual(signin.openPending(sealed.value), state);

  const other = new SigninService({
    db: deps.db,
    chainKey: randomBytes(32),
    vault: deps.vault,
    signin: CONFIG,
  });
  assert.equal(other.openPending(sealed.value), null);
  assert.equal(signin.openPending(null), null);
  assert.equal(signin.openPending(`${sealed.value.slice(0, -2)}AA`), null);
});

// --- the audit chain ------------------------------------------------------------------

test('everything the sign-in service writes keeps the audit chain intact', async () => {
  await signin.completeSignin(profile('github', '9001', ['stranger@example.com']), meta());
  const session = await signedIn(profile('github', '101', [DEV]));
  await signin.linkIdentity(dev, profile('google', 'g-dev', []));
  await approvedCliSession(dev);
  const token = await signin.issueServiceToken(lead, SERVICE, { label: null, expiresInDays: 7 });
  await signin.revokeCredential(lead, token.id);
  const [, google] = await signin.listIdentities(dev);
  await signin.unlinkIdentity(dev, google.id);
  await signin.signOut(session.credential.token, { requestId: randomUUID(), sourceIp: IP });

  const verified = await verifyAudit(await contextFor(deps, ROOT));
  assert.equal(verified.ok, true);
  // Every entry, the vault's for the members set up here included; ten of them the app's.
  const [{ n }] = await db.owner.select({ n: count() }).from(auditLog);
  if (verified.ok) assert.equal(verified.rows, n);
  assert.equal((await auditRows()).length, 10);
});

// --- through the API --------------------------------------------------------------

test('service tokens are issued, listed and revoked through the API, in signin mode only', async () => {
  const owner = clientFor(deps, LEAD);
  const member = `token:${SERVICE}`;
  const issued = await owner.tokens.issue(member, { label: 'deploys', expiresInDays: 30 });
  assert.match(issued.token, /^coffre_svc_/);
  assert.equal((await signin.verify(issued.token)).id, SERVICE);

  const { tokens } = await owner.tokens.list(member);
  assert.deepEqual(tokens.map((row) => [row.id, row.label, row.createdBy]), [[issued.id, 'deploys', LEAD]]);
  assert.equal((await clientFor(deps, SERVICE, 'service').tokens.list(member)).tokens.length, 1);

  await assert.rejects(clientFor(deps, DEV).tokens.list(member), { status: 403 });
  await assert.rejects(owner.tokens.list(`user:${DEV}`), { status: 404 }, 'a person holds no service tokens');
  await assert.rejects(owner.tokens.issue(member, { label: null, expiresInDays: 367 }), { status: 400 });

  assert.deepEqual(await owner.tokens.revoke(member, issued.id), { revoked: true });
  assert.deepEqual((await owner.tokens.list(member)).tokens, []);

  // Behind Cloudflare Access, coffre issues no tokens at all.
  const access = clientFor({ ...deps, signin: undefined }, ROOT);
  await assert.rejects(access.tokens.list(member), { status: 404 });
  await assert.rejects(access.tokens.issue(member, { label: null, expiresInDays: 30 }), { status: 404 });
});


test('replacing an issuer requires an explicit re-link and invalidates its browser sessions', async () => {
  const atIssuer = (issuer: string) => new SigninService({
    ...deps,
    signin: defineSignin({ publicUrl: CONFIG.publicUrl, providers: [
      ...CONFIG.providers,
      oidc({ id: 'company', label: 'Company', issuer, clientId: 'client', clientSecret: 'secret' }),
    ] }),
  });
  signin = atIssuer('https://old-idp.example');
  const old = await signedIn(profile('company', 'same-subject', [DEV]));
  await signin.linkIdentity(dev, profile('github', 'backup', [DEV]));
  const backup = await signedIn(profile('github', 'backup', [DEV]));
  signin = atIssuer('https://new-idp.example');
  assert.deepEqual(await signin.completeSignin(profile('company', 'same-subject', [DEV]), meta()),
    { ok: false, reason: 'account_mismatch' });
  await assert.rejects(signin.verify(old.credential.token), /unknown, expired or revoked/);
  assert.equal((await signin.verify(backup.credential.token)).id, DEV);
  assert.deepEqual(await signin.linkIdentity(dev, profile('company', 'same-subject', [])), { ok: true });
  assert.equal((await signedIn(profile('company', 'same-subject', []))).principal.id, DEV);
});

test('a binding without an issuer is rejected by the baseline', async () => {
  await assert.rejects(db.owner.insert(identities).values({
    id: randomUUID(), provider: 'github', subject: 'legacy', principalType: 'user', principalId: DEV,
    issuerHash: sql`NULL`, generation: 0, authMac: Buffer.alloc(32), email: DEV, createdBy: DEV,
  }));
});
