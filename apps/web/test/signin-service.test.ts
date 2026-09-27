import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';

import {
  defineSignin,
  github,
  google,
} from '../../../packages/core/src/identity/signin/config.ts';
import type { SigninProfile } from '../../../packages/core/src/identity/signin/types.ts';
import { hashToken, isCoffreToken } from '../../../packages/core/src/identity/tokens.ts';
import {
  TEST_OWNER_DATABASE_URL,
  TEST_RUNTIME_DATABASE_URL,
} from '../../../packages/db/test/connections.ts';
import { AuditService } from '../src/server/services/audit.ts';
import { AccessDenied, NotFound } from '../src/server/services/secrets.ts';
import {
  normalizeUserCode,
  SigninService,
  type PendingState,
} from '../src/server/services/signin.ts';
import { requestContext } from './service-fixture.ts';

const CHAIN_KEY = randomBytes(32);
const ROOT = 'admin@acme.example';
const LEAD = 'lead@acme.example';
const DEV = 'dev@acme.example';
const GONE = 'gone@acme.example';
const SERVICE = 'ci-deploy';
const RETIRED = 'retired-bot';
const IP = '203.0.113.7';

const root = requestContext(ROOT);
const lead = requestContext(LEAD);
const dev = requestContext(DEV);

const CONFIG = defineSignin({
  publicUrl: 'https://secrets.acme.example',
  providers: [
    github({ clientId: 'gh-id', clientSecret: 'gh-secret' }),
    google({ clientId: 'g-id', clientSecret: 'g-secret' }),
  ],
  browserSessionHours: 12,
  cliSessionDays: 30,
});

let pool: pg.Pool;
let runtimePool: pg.Pool;
let signin: SigninService;
let audit: AuditService;

async function clean(): Promise<void> {
  await pool.query('DELETE FROM credentials');
  await pool.query('DELETE FROM device_authorizations');
  await pool.query('DELETE FROM identities');
  await pool.query('DELETE FROM audit_log');
  await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
  );
  await pool.query('DELETE FROM grants');
  await pool.query('DELETE FROM principals');
}

before(() => {
  pool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
  runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
  signin = new SigninService({
    pool: runtimePool,
    auditChainKey: CHAIN_KEY,
    rootAdmins: [ROOT],
    signin: CONFIG,
  });
  audit = new AuditService({ pool: runtimePool, chainKey: CHAIN_KEY, rootAdmins: [ROOT] });
});

after(async () => {
  // Later suites delete principals, which these tables reference.
  await clean();
  await runtimePool.end();
  await pool.end();
});

beforeEach(async () => {
  await clean();
  await pool.query(
    `INSERT INTO principals (principal_type, principal_id, instance_role, created_by, active)
     VALUES
       ('user', $1, 'owner', $5, true),
       ('user', $2, 'user', $5, true),
       ('user', $3, 'user', $5, false),
       ('service', $4, 'user', $5, true),
       ('service', $6, 'user', $5, false)`,
    [LEAD, DEV, GONE, SERVICE, ROOT, RETIRED],
  );
});

function profile(provider: string, subject: string, emails: string[], name: string | null = null): SigninProfile {
  return { provider, subject, emails, name };
}

function meta(label: string | null = 'Firefox on macOS') {
  return { requestId: randomUUID(), sourceIp: IP, label };
}

type AuditRow = {
  action: string;
  decision: string;
  actor_type: string;
  actor_id: string;
  source_ip: string | null;
  metadata: Record<string, unknown>;
};

async function auditRows(): Promise<AuditRow[]> {
  const result = await pool.query(
    'SELECT action, decision, actor_type, actor_id, source_ip, metadata FROM audit_log ORDER BY seq',
  );
  return result.rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) }));
}

async function auditActions(): Promise<string[]> {
  return (await auditRows()).map((row) => `${row.action} ${row.decision} ${row.actor_id}`);
}

async function count(sql: string, params: unknown[] = []): Promise<number> {
  return (await pool.query(`SELECT count(*)::int AS n FROM ${sql}`, params)).rows[0].n;
}

/** Sign in, expecting success. */
async function signedIn(p: SigninProfile) {
  const result = await signin.completeSignin(p, meta());
  assert.equal(result.ok, true, `expected ${p.emails.join(',')} to be let in`);
  if (!result.ok) throw new Error('unreachable');
  return result;
}

function hoursFromNow(iso: string): number {
  return (Date.parse(iso) - Date.now()) / 3_600_000;
}

function statusCode(expected: number) {
  return (error: unknown) => (error as { statusCode?: number }).statusCode === expected;
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
    rows.map((row) => [row.action, row.decision, row.actor_type, row.actor_id, row.source_ip]),
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
  assert.equal(await count('identities'), 0);
  assert.equal(await count('credentials'), 0);
});

test('a first sign-in with an invited email binds the account and opens a browser session', async () => {
  const result = await signedIn(profile('github', '101', [DEV], 'Devon Dev'));
  assert.deepEqual(result.principal, { type: 'user', id: DEV });
  assert.match(result.credential.token, /^coffre_web_/);
  assert.ok(isCoffreToken(result.credential.token));
  assert.ok(Math.abs(hoursFromNow(result.credential.expiresAt) - 12) < 0.01);

  const identities = await pool.query('SELECT * FROM identities');
  assert.equal(identities.rowCount, 1);
  const identity = identities.rows[0];
  assert.equal(identity.provider, 'github');
  assert.equal(identity.subject, '101');
  assert.equal(identity.principal_id, DEV);
  assert.equal(identity.email, DEV);
  assert.equal(identity.created_by, DEV);
  assert.ok(identity.last_sign_in_at);

  const credentials = await pool.query('SELECT * FROM credentials');
  assert.equal(credentials.rowCount, 1);
  const credential = credentials.rows[0];
  assert.equal(credential.id, result.credential.id);
  assert.equal(credential.kind, 'browser');
  assert.equal(credential.identity_id, identity.id);
  assert.equal(credential.label, 'Firefox on macOS');
  assert.deepEqual(credential.token_hash, hashToken(result.credential.token));
  assert.equal(credential.token_hint, `coffre_web_…${result.credential.token.slice(-4)}`);
  assert.equal(
    JSON.stringify(credential).includes(result.credential.token.slice(11)),
    false,
    'the token itself is stored nowhere',
  );

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actor_id}`), [
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
  });
});

test('any verified email on the account may match, and case does not matter', async () => {
  await pool.query(
    `INSERT INTO principals (principal_type, principal_id, instance_role, created_by, active)
     VALUES ('user', 'Mixed.Case@Acme.example', 'user', $1, true)`,
    [ROOT],
  );
  const result = await signedIn(
    profile('google', 'g-7', ['personal@example.com', 'mixed.case@acme.example']),
  );
  assert.deepEqual(result.principal, { type: 'user', id: 'Mixed.Case@Acme.example' });
  const [bind] = await auditRows();
  assert.equal(bind.metadata.matchedEmail, 'mixed.case@acme.example');
  const identity = (await pool.query('SELECT email FROM identities')).rows[0];
  assert.equal(identity.email, 'personal@example.com', 'the primary address is remembered');
});

test('once bound, the account signs in as its person whatever its email says', async () => {
  await signedIn(profile('github', '101', [DEV]));

  const renamed = await signedIn(profile('github', '101', ['devon@personal.example']));
  assert.deepEqual(renamed.principal, { type: 'user', id: DEV });
  assert.equal((await pool.query('SELECT email FROM identities')).rows[0].email, 'devon@personal.example');

  const noEmail = await signedIn(profile('github', '101', []));
  assert.deepEqual(noEmail.principal, { type: 'user', id: DEV });
  assert.equal(
    (await pool.query('SELECT email FROM identities')).rows[0].email,
    'devon@personal.example',
    'an account without email keeps the last one seen',
  );

  // Even an email that names someone else: the binding wins.
  const confusing = await signedIn(profile('github', '101', [LEAD]));
  assert.deepEqual(confusing.principal, { type: 'user', id: DEV });

  assert.equal(await count('identities'), 1);
  assert.equal(await count('credentials'), 4);
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
  assert.deepEqual(rows.slice(2).map((row) => [row.action, row.decision, row.actor_id, row.metadata.reason]), [
    ['auth.signin', 'deny', DEV, 'account_mismatch'],
    ['auth.signin', 'deny', DEV, 'account_mismatch'],
  ]);
  assert.equal(await count('identities'), 1);
  assert.equal(await count('credentials'), 1);
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
  assert.equal(await count('identities WHERE principal_id = $1', [LEAD]), 1);
  assert.equal(await count('identities WHERE principal_id = $1', [DEV]), 1);
});

test('deactivated people are refused, bound or not, and their sessions stop', async () => {
  assert.deepEqual(
    await signin.completeSignin(profile('github', '303', [GONE]), meta()),
    { ok: false, reason: 'deactivated' },
  );

  const session = await signedIn(profile('github', '101', [DEV]));
  await pool.query("UPDATE principals SET active = false WHERE principal_id = $1", [DEV]);
  assert.deepEqual(
    await signin.completeSignin(profile('github', '101', [DEV]), meta()),
    { ok: false, reason: 'deactivated' },
  );
  await assert.rejects(signin.verify(session.credential.token), /unknown, expired or revoked/);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.decision, row.actor_id, row.metadata.reason]), [
    ['auth.signin', 'deny', GONE, 'deactivated'],
    ['identity.bind', 'allow', DEV, undefined],
    ['auth.signin', 'allow', DEV, undefined],
    ['auth.signin', 'deny', DEV, 'deactivated'],
  ]);
  assert.equal(await count('identities WHERE principal_id = $1', [GONE]), 0);
});

test('a root admin needs no invitation, and a deactivated row does not lock them out', async () => {
  const first = await signedIn(profile('google', 'g-root', [ROOT]));
  assert.deepEqual(first.principal, { type: 'user', id: ROOT });
  const row = (await pool.query(
    "SELECT instance_role, created_by, active FROM principals WHERE principal_id = $1",
    [ROOT],
  )).rows[0];
  assert.deepEqual(row, { instance_role: 'user', created_by: 'system:signin', active: true });
  assert.equal((await signin.verify(first.credential.token)).id, ROOT);

  await pool.query('UPDATE principals SET active = false WHERE principal_id = $1', [ROOT]);
  const again = await signedIn(profile('google', 'g-root', [ROOT]));
  assert.equal((await signin.verify(again.credential.token)).id, ROOT);
  assert.equal(
    (await pool.query('SELECT active FROM principals WHERE principal_id = $1', [ROOT])).rows[0].active,
    true,
  );
});

// --- verifying, signing out, revoking -------------------------------------------

test('verify refuses what is not a live coffre credential', async () => {
  const { credential } = await signedIn(profile('github', '101', [DEV]));

  await assert.rejects(signin.verify('eyJhbGciOiJSUzI1NiJ9.e30.x'), /not a coffre credential/);
  await assert.rejects(signin.verify(`coffre_web_${'A'.repeat(43)}`), /unknown, expired or revoked/);
  await assert.rejects(signin.verify(credential.token.replace('coffre_web_', 'coffre_cli_')), /unknown/);

  await pool.query("UPDATE credentials SET expires_at = now() - interval '1 second'");
  await assert.rejects(signin.verify(credential.token), /unknown, expired or revoked/);
  assert.deepEqual(await signin.listSessions(dev, null), []);
});

test('verify records when and where a credential was last used, at most every five minutes', async () => {
  const { credential } = await signedIn(profile('github', '101', [DEV]));
  const lastUsed = async () =>
    (await pool.query('SELECT last_used_at, last_used_ip FROM credentials WHERE id = $1', [credential.id])).rows[0];

  assert.equal((await lastUsed()).last_used_at, null);
  await signin.verify(credential.token, { sourceIp: '198.51.100.1' });
  const first = await lastUsed();
  assert.ok(first.last_used_at);
  assert.equal(first.last_used_ip, '198.51.100.1');

  await signin.verify(credential.token, { sourceIp: '198.51.100.2' });
  assert.deepEqual(await lastUsed(), first, 'not rewritten within five minutes');

  await pool.query("UPDATE credentials SET last_used_at = now() - interval '6 minutes'");
  await signin.verify(credential.token, { sourceIp: '198.51.100.3' });
  assert.equal((await lastUsed()).last_used_ip, '198.51.100.3');
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

  const revoked = (await pool.query('SELECT revoked_by FROM credentials WHERE id = $1', [ended.credential.id])).rows[0];
  assert.equal(revoked.revoked_by, DEV);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actor_id}`), [
    `identity.bind allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signin allow ${DEV}`,
    `auth.signout allow ${DEV}`,
  ]);
  assert.deepEqual(rows[3].metadata, { credentialId: ended.credential.id, kind: 'browser' });
});

test('people revoke their own credentials; only owners revoke anyone else\'s', async () => {
  const devSession = await signedIn(profile('github', '101', [DEV]));
  const devOther = await signedIn(profile('github', '101', [DEV]));
  const leadSession = await signedIn(profile('github', '102', [LEAD]));
  const token = await signin.issueServiceToken(lead, SERVICE, { label: 'deploys', expiresInDays: 30 });
  await pool.query('DELETE FROM audit_log');
  await pool.query("UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')");

  await assert.rejects(signin.revokeCredential(dev, leadSession.credential.id), AccessDenied);
  await assert.rejects(signin.revokeCredential(dev, token.id), AccessDenied);
  assert.equal((await signin.verify(leadSession.credential.token)).id, LEAD);

  assert.deepEqual(await signin.revokeCredential(dev, devOther.credential.id), { revoked: true });
  await assert.rejects(signin.verify(devOther.credential.token), /revoked/);
  await assert.rejects(signin.revokeCredential(dev, devOther.credential.id), NotFound, 'already revoked');
  await assert.rejects(signin.revokeCredential(dev, randomUUID()), NotFound);

  assert.deepEqual(await signin.revokeCredential(lead, devSession.credential.id), { revoked: true });
  assert.deepEqual(await signin.revokeCredential(root, token.id), { revoked: true });
  await assert.rejects(signin.verify(devSession.credential.token), /revoked/);
  await assert.rejects(signin.verify(token.token), /revoked/);

  const revokedBy = await pool.query('SELECT id, revoked_by FROM credentials WHERE revoked_at IS NOT NULL');
  assert.deepEqual(
    Object.fromEntries(revokedBy.rows.map((row) => [row.id, row.revoked_by])),
    { [devOther.credential.id]: DEV, [devSession.credential.id]: LEAD, [token.id]: ROOT },
  );

  const rows = await auditRows();
  assert.deepEqual(
    rows.map((row) => [row.action, row.decision, row.actor_id, row.metadata.reason ?? null]),
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
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actor_id}`), [
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
    signin.linkIdentity(requestContext(SERVICE, 'service'), profile('github', '555', [])),
    AccessDenied,
  );

  assert.equal(await count('identities'), 1);
  const rows = await auditRows();
  assert.deepEqual(rows.slice(2).map((row) => [row.action, row.decision, row.actor_id, row.metadata.reason]), [
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
  assert.equal(unbind.actor_id, DEV);
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
  await assert.rejects(signin.unlinkIdentity(dev, githubIdentity.id), NotFound);
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
  assert.equal(await count('identities WHERE revoked_at IS NULL'), 1);
  assert.equal(await count('identities'), 3);
});

test('nobody unlinks someone else\'s account', async () => {
  await signedIn(profile('github', '102', [LEAD]));
  const [identity] = await signin.listIdentities(lead);
  await assert.rejects(signin.unlinkIdentity(dev, identity.id), NotFound);
  await assert.rejects(signin.unlinkIdentity(root, identity.id), NotFound);
  assert.equal((await signin.listIdentities(lead)).length, 1);

  const denied = (await auditRows()).filter((row) => row.action === 'identity.unbind');
  assert.deepEqual(denied.map((row) => [row.decision, row.actor_id, row.metadata.reason]), [
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
  await pool.query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = $1", [stale.credential.id]);
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
  });

  const byRoot = await signin.issueServiceToken(root, SERVICE, { label: null, expiresInDays: 366 });
  assert.equal((await signin.verify(byRoot.token)).id, SERVICE);

  const row = (await pool.query('SELECT * FROM credentials WHERE id = $1', [issued.id])).rows[0];
  assert.equal(row.kind, 'service');
  assert.equal(row.principal_type, 'service');
  assert.equal(row.identity_id, null);
  assert.equal(row.created_by, LEAD);
  assert.equal(row.label, 'deploys');

  const rows = await auditRows();
  assert.deepEqual(rows.map((r) => `${r.action} ${r.decision} ${r.actor_id}`), [
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
    AccessDenied,
  );
  await assert.rejects(
    signin.issueServiceToken(requestContext(SERVICE, 'service'), SERVICE, { label: null, expiresInDays: 30 }),
    AccessDenied,
    'a service does not mint its own tokens',
  );
  await assert.rejects(
    signin.issueServiceToken(lead, RETIRED, { label: null, expiresInDays: 30 }),
    NotFound,
  );
  await assert.rejects(
    signin.issueServiceToken(lead, 'no-such-service', { label: null, expiresInDays: 30 }),
    NotFound,
  );
  await assert.rejects(
    signin.issueServiceToken(lead, DEV, { label: null, expiresInDays: 30 }),
    NotFound,
    'a person is not a service',
  );
  for (const days of [0, 367, 1.5, Number.NaN]) {
    await assert.rejects(
      signin.issueServiceToken(lead, SERVICE, { label: null, expiresInDays: days }),
      statusCode(400),
      String(days),
    );
  }
  assert.equal(await count('credentials'), 0);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.decision, row.actor_id, row.metadata.reason]), [
    ['credential.issue', 'deny', DEV, 'requires_instance_owner'],
    ['credential.issue', 'deny', SERVICE, 'requires_instance_owner'],
    ['credential.issue', 'deny', LEAD, 'unknown_principal'],
    ['credential.issue', 'deny', LEAD, 'unknown_principal'],
    ['credential.issue', 'deny', LEAD, 'unknown_principal'],
  ]);
});

test('a service token stops working when the service is deactivated, revoked or expired', async () => {
  const deactivated = await signin.issueServiceToken(lead, SERVICE, { label: null, expiresInDays: 1 });
  await pool.query('UPDATE principals SET active = false WHERE principal_id = $1', [SERVICE]);
  await assert.rejects(signin.verify(deactivated.token), /unknown, expired or revoked/);
  await pool.query('UPDATE principals SET active = true WHERE principal_id = $1', [SERVICE]);
  assert.equal((await signin.verify(deactivated.token)).id, SERVICE);

  await pool.query("UPDATE credentials SET expires_at = now() - interval '1 second'");
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
    (await signin.listServiceTokens(requestContext(SERVICE, 'service'), SERVICE)).map((row) => row.id),
    [second.id, first.id],
  );
  assert.equal((await signin.listServiceTokens(root, SERVICE)).length, 2);

  await assert.rejects(signin.listServiceTokens(dev, SERVICE), AccessDenied);
  await assert.rejects(signin.listServiceTokens(requestContext(RETIRED, 'service'), SERVICE), AccessDenied);
});

// --- device flow ------------------------------------------------------------------

/** Run `coffre login` to completion for this person. */
async function approvedCliSession(ctx: ReturnType<typeof requestContext>, clientLabel: string | null = null) {
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

  const stored = (await pool.query('SELECT * FROM device_authorizations')).rows[0];
  assert.deepEqual(stored.device_code_hash, hashToken(started.deviceCode), 'only a hash is stored');

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
  });

  // Exactly once.
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' });
  assert.equal(await count("credentials WHERE kind = 'cli'"), 1);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => `${row.action} ${row.decision} ${row.actor_id}`), [
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
  assert.equal(await count("credentials WHERE kind = 'cli'"), 1);
});

test('device flow: a denied code polls as denied and never yields a token', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  assert.deepEqual(await signin.decideDevice(dev, started.userCode, false), { decided: true });
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });

  // Decided once: approving afterwards is refused.
  await assert.rejects(signin.decideDevice(dev, started.userCode, true), NotFound);
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });
  assert.equal(await count('credentials'), 0);

  const rows = await auditRows();
  assert.deepEqual(rows.map((row) => [row.action, row.decision, row.actor_id, row.metadata.reason]), [
    ['device.deny', 'allow', DEV, undefined],
    ['device.approve', 'deny', DEV, 'unknown_code'],
  ]);
});

test('device flow: an expired code cannot be described, decided or polled', async () => {
  const started = await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await pool.query("UPDATE device_authorizations SET expires_at = now() - interval '1 second'");

  assert.equal(await signin.describeDevice(started.userCode), null);
  await assert.rejects(signin.decideDevice(dev, started.userCode, true), NotFound);
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
  await pool.query("UPDATE device_authorizations SET expires_at = now() - interval '1 second'");
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' });
  assert.equal(await count('credentials'), 0);
});

test('device flow: unknown and malformed codes', async () => {
  assert.deepEqual(await poll('not-a-device-code'), { status: 'expired' });
  assert.equal(await signin.describeDevice('BCDF-GHJK'), null);
  assert.equal(await signin.describeDevice('AEIO-UUUU'), null, 'vowels are never issued');
  assert.equal(await signin.describeDevice('BCD'), null);

  await assert.rejects(signin.decideDevice(dev, 'BCDF-GHJK', true), NotFound);
  await assert.rejects(signin.decideDevice(dev, 'nonsense', false), NotFound);
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
    signin.decideDevice(requestContext(SERVICE, 'service'), started.userCode, true),
    AccessDenied,
  );
  assert.ok(await signin.describeDevice(started.userCode), 'still waiting');

  await signin.decideDevice(dev, started.userCode, true);
  await pool.query('UPDATE principals SET active = false WHERE principal_id = $1', [DEV]);
  assert.deepEqual(await poll(started.deviceCode), { status: 'denied' });
  assert.deepEqual(await poll(started.deviceCode), { status: 'expired' }, 'consumed all the same');
  assert.equal(await count('credentials'), 0);
});

test('device flow: open requests are capped per address and freed by a decision', async () => {
  const codes = [];
  for (let i = 0; i < 5; i += 1) codes.push(await signin.startDevice({ clientLabel: null, sourceIp: IP }));
  await assert.rejects(signin.startDevice({ clientLabel: null, sourceIp: IP }), statusCode(429));

  // Another address is unaffected.
  await signin.startDevice({ clientLabel: null, sourceIp: '198.51.100.20' });

  // A decided or expired request no longer counts.
  await signin.decideDevice(dev, codes[0].userCode, false);
  await signin.startDevice({ clientLabel: null, sourceIp: IP });
  await assert.rejects(signin.startDevice({ clientLabel: null, sourceIp: IP }), statusCode(429));
  await pool.query("UPDATE device_authorizations SET expires_at = now() - interval '1 second' WHERE user_code = $1", [
    codes[1].userCode,
  ]);
  await signin.startDevice({ clientLabel: null, sourceIp: IP });

  // Starting writes no audit rows: the caller is anonymous.
  assert.deepEqual(await auditActions(), [`device.deny allow ${DEV}`]);
});

test('device flow: the client label is kept short', async () => {
  const credential = await approvedCliSession(dev, 'x'.repeat(500));
  const row = (await pool.query('SELECT label FROM credentials WHERE id = $1', [credential.id])).rows[0];
  assert.equal(row.label.length, 120);
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
    pool: runtimePool,
    auditChainKey: randomBytes(32),
    rootAdmins: [ROOT],
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

  const verified = await audit.verify(root);
  assert.equal(verified.ok, true);
  if (verified.ok) assert.equal(verified.rows, 10);
});
