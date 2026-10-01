// A sign-in row written by the database's owner mints nothing: a chosen
// token, an account binding, an approval or an edited generation is refused
// where it is used, and reported.
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { Browser } from '../browser.ts';
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { defaultGitHubAccount } from '../idp/people.ts';
import { expect, until } from '../report.ts';
import { member } from './members.ts';
import { signIn, type People } from './people.ts';
import { insertRow, query, restoreRow } from './storage.ts';

const hash = (value: string) => createHash('sha256').update(value).digest();

// Wrangler can forward console output after the HTTP refusal arrives.
async function reported(deployment: Deployment, id: string): Promise<void> {
  const event = new RegExp(`auth_row_tampered[^}]*${id}`);
  await until(`the sign-in row failure report for ${id}`, async () => event.test(deployment.output()), 10);
}

/** Knowing the database password and a chosen token must not mint a credential. */
export async function forgedCredential(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'forged-credential');
  const token = `coffre_cli_${randomBytes(32).toString('base64url')}`;
  await using(deployment.database(), async (sql) => {
    const [row] = await query(sql, 'SELECT * FROM credentials WHERE principal = $1 AND revoked_at IS NULL LIMIT 1', [person.member]);
    expect(row !== undefined, 'no genuine credential to copy');
    const forged = { ...row, id: randomUUID(), kind: 'cli', token_hash: hash(token), identity_id: null };
    await insertRow(sql, 'credentials', forged);
    try {
      const response = await fetch(`${deployment.origin}/api/me`, { headers: { authorization: `Bearer ${token}` } });
      expect(response.status === 401, 'an owner-forged credential authenticated', await response.text());
      await reported(deployment, forged.id);
    } finally {
      await query(sql, 'DELETE FROM credentials WHERE id = $1', [forged.id]);
    }
  });
  expect((await person.api.me()).principal.id === person.email, 'the genuine credential stopped working');
  return 'a chosen token in an owner-inserted credential cannot authenticate, and is reported';
}

/** An account binding inserted by the owner must not sign someone in as a member. */
export async function forgedIdentity(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'forged-identity');
  const email = 'identity-forger@conformance.example';
  const browser = new Browser(deployment.origin);
  await using(deployment.database(), async (sql) => {
    const [row] = await query(sql, 'SELECT * FROM identities WHERE principal = $1 AND revoked_at IS NULL LIMIT 1', [person.member]);
    expect(row !== undefined, 'no genuine identity to copy');
    const forged = { ...row, id: randomUUID(), subject: String(defaultGitHubAccount(email).id) };
    await insertRow(sql, 'identities', forged);
    try {
      // The callback can answer a sanitized server error for a row it cannot authenticate.
      await signIn(deployment, browser, email).catch(() => {});
      expect((await browser.fetch('/api/me')).status === 401, 'an owner-forged identity minted a session');
      await reported(deployment, forged.id);
    } finally {
      await query(sql, 'DELETE FROM credentials WHERE identity_id = $1', [forged.id]);
      await query(sql, 'DELETE FROM identities WHERE id = $1', [forged.id]);
    }
  });
  expect((await person.api.me()).principal.id === person.email, 'the genuine identity stopped working');
  return 'an owner-inserted account binding cannot mint a session, and is reported';
}

export async function startDevice(deployment: Deployment): Promise<{ device_code: string; user_code: string }> {
  const response = await fetch(`${deployment.origin}/api/auth/device`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  expect(response.ok, 'the device fixture did not start', await response.clone().text());
  return response.json();
}

export function pollDevice(deployment: Deployment, code: string): Promise<Response> {
  return fetch(`${deployment.origin}/api/auth/device/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ device_code: code }) });
}

/** An authentic pending row, changed to approved around the app, grants nothing. */
export async function forgedApproval(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'forged-approval');
  const device = await startDevice(deployment);
  await using(deployment.database(), async (sql) => {
    const [row] = await query(sql, 'SELECT * FROM device_authorizations WHERE user_code = $1', [device.user_code]);
    const [standing] = await query<{ generation: number }>(sql, 'SELECT generation FROM vault_members WHERE principal = $1', [person.member]);
    expect(row !== undefined, 'no device row to forge');
    await query(sql, `UPDATE device_authorizations SET decision = 'approved', decided_at = $1, principal = $2, generation = $3 WHERE id = $4`,
      [sql.engine === 'sqlite' ? Date.now() : new Date(), person.member, standing.generation, row.id]);
    try {
      const response = await pollDevice(deployment, device.device_code);
      const body = await response.text();
      expect(!response.ok && !body.includes('access_token'), 'an owner-forged approval minted a session', body);
      await reported(deployment, String(row.id));
    } finally {
      await query(sql, 'DELETE FROM device_authorizations WHERE id = $1', [row.id]);
    }
  });
  const control = await startDevice(deployment);
  await person.api.deviceLogins.decide(control.user_code, true);
  expect((await pollDevice(deployment, control.device_code)).ok, 'a genuine approval no longer works');
  return 'an owner-edited device approval grants nothing and is reported; a genuine approval works';
}

/** Changing an old credential's generation cannot bring its chosen token back. */
export async function editedGeneration(deployment: Deployment, people: People): Promise<string> {
  const principal = 'token:generation-mac';
  const { admin } = people;
  await admin.api.members.add(principal);
  await admin.api.access.set(principal, { 'conformance/dev': 'viewer' });
  const issued = await admin.api.tokens.issue(principal, { expiresInDays: 1 });
  await using(deployment.database(), async (sql) => {
    const [old] = await query(sql, 'SELECT * FROM credentials WHERE token_hash = $1', [hash(issued.token)]);
    expect(old !== undefined, 'no old token row to save');
    await admin.api.members.remove(principal);
    await admin.api.members.add(principal);
    await admin.api.access.set(principal, { 'conformance/dev': 'viewer' });
    const [current] = await query(sql, 'SELECT * FROM credentials WHERE id = $1', [old.id]);
    const [standing] = await query<{ generation: number }>(sql, 'SELECT generation FROM vault_members WHERE principal = $1', [principal]);
    await restoreRow(sql, 'credentials', { ...old, generation: standing.generation }, 'id');
    try {
      const response = await fetch(`${deployment.origin}/api/me`, { headers: { authorization: `Bearer ${issued.token}` } });
      expect(response.status === 401, 'editing the credential generation revived the token', await response.text());
      await reported(deployment, String(old.id));
    } finally {
      await restoreRow(sql, 'credentials', current, 'id');
    }
  });
  const fresh = await admin.api.tokens.issue(principal, { expiresInDays: 1 });
  expect((await fetch(`${deployment.origin}/api/me`, { headers: { authorization: `Bearer ${fresh.token}` } })).ok, 'a newly issued token does not work');
  return 'an old token with its generation edited to the current membership is refused and reported';
}
