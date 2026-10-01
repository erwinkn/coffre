import { Browser } from '../browser.ts';
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import { DEV, PROD, signIn, type People, type Person } from './people.ts';
import { logRefuses } from './readiness.ts';
import { query, restoreRow } from './storage.ts';

export async function member(deployment: Deployment, { admin }: People, name: string): Promise<Person> {
  const email = `${name}@conformance.example`;
  const principal = `user:${email}`;
  await admin.api.members.add(principal);
  await admin.api.access.set(principal, { [DEV]: 'viewer' });
  const browser = new Browser(deployment.origin);
  expect((await signIn(deployment, browser, email)).ok, 'the fixture member could not sign in');
  return { email, member: principal, browser, api: browser.client() };
}

/** The row is refused at use, not only when someone explicitly verifies the log. */
export async function memberTampering(deployment: Deployment, people: People, kind: 'grant' | 'member' | 'old'): Promise<string> {
  const person = await member(deployment, people, `tamper-${kind}`);
  const { admin } = people;
  const path = kind === 'grant' ? PROD : DEV;
  const protectedValues = Object.values((await admin.api.secrets.reveal(path)).values);
  await using(deployment.database(), async (sql) => {
    const [before] = await query(sql, 'SELECT * FROM vault_members WHERE principal = $1', [person.member]);
    const grants = await query(sql, 'SELECT * FROM vault_grants WHERE principal = $1', [person.member]);
    expect(before !== undefined && grants.length === 1, 'the fixture has no member row and grant');
    let restored = before;
    let held = grants;
    if (kind === 'old') {
      await admin.api.access.set(person.member, { [DEV]: 'developer' });
      [restored] = await query(sql, 'SELECT * FROM vault_members WHERE principal = $1', [person.member]);
      held = await query(sql, 'SELECT * FROM vault_grants WHERE principal = $1', [person.member]);
      await restoreRow(sql, 'vault_members', before, 'principal');
      await query(sql, 'UPDATE vault_grants SET role = $1, granted_at = $2, granted_by = $3 WHERE principal = $4',
        [grants[0].role, grants[0].granted_at, grants[0].granted_by, person.member]);
    } else if (kind === 'member') {
      await query(sql, 'UPDATE vault_members SET owner = $1 WHERE principal = $2', [sql.engine === 'sqlite' ? 1 : true, person.member]);
    } else {
      const [place] = await query<{ id: string }>(sql, `SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id
        WHERE p.slug = 'conformance' AND e.slug = 'prod'`);
      expect(place !== undefined, 'no prod environment to forge a grant on');
      await query(sql, `INSERT INTO vault_grants (principal, environment_id, role, granted_at, granted_by) VALUES ($1, $2, 'viewer', $3, $4)`,
        [person.member, place.id, Date.now(), person.member]);
    }
    try {
      const response = await person.browser.send('POST', '/api/reveals', { path });
      const text = await response.text();
      expect(response.status === 401 && (JSON.parse(text) as { error: string }).error === 'unauthenticated', 'the tampered credential was not refused', text);
      expect(!protectedValues.some((value) => text.includes(value)), 'the tampered refusal carried a value', text);
      const reports = await query(sql, `SELECT seq FROM audit_log WHERE author = 'vault' AND action = 'vault.tampered'
        AND subject_principal = $1 AND code = $2`, [person.member, kind === 'old' ? 'stale' : 'mac']);
      expect(reports.length > 0, 'the tampering was not logged at use', reports);
      expect((await admin.api.members.get(person.member)).status === 'tampered', 'the refused member is not marked tampered');
      const verified = await admin.api.audit.verify();
      expect(!verified.ok && verified.author === 'vault' && verified.failedAtSeq === null, 'the tampered member verifies', verified);
    } finally {
      await restoreRow(sql, 'vault_members', restored, 'principal');
      await query(sql, 'DELETE FROM vault_grants WHERE principal = $1', [person.member]);
      for (const grant of held) {
        const fields = Object.keys(grant);
        await query(sql, `INSERT INTO vault_grants (${fields.join(', ')}) VALUES (${fields.map((_, i) => `$${i + 1}`).join(', ')})`, Object.values(grant));
      }
    }
  });
  expect((await person.api.secrets.reveal(DEV)).values.API_KEY !== undefined, 'restoring the member did not restore legitimate use');
  expect((await admin.api.audit.verify()).ok, 'the restored member did not verify');
  return `${kind === 'old' ? 'a genuine older row' : `a forged ${kind}`} refused as tampered, logged, then restored`;
}

/** Access changes have one author, the vault that commits the changed rows. */
export async function accessAuthorship(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'access-actions');
  const { admin } = people;
  await admin.api.access.set(person.member, { [DEV]: null });
  await admin.api.members.remove(person.member);
  await admin.api.members.add(person.member);
  await using(deployment.database(), async (sql) => {
    const access = await sql.query<{ author: string; action: string; subject_principal: string }>(`SELECT author, action, subject_principal FROM audit_log
      WHERE decision = 'allow' AND (action LIKE 'access.%' OR action LIKE 'member.%' OR action LIKE 'directory.%' OR action LIKE 'grant.%' OR action LIKE 'principal.%')`);
    expect(access.length > 0 && access.every((entry) => entry.author === 'vault'), 'an access change was written by the app', access.filter((entry) => entry.author !== 'vault'));
    const actions = access.filter((entry) => entry.subject_principal === person.member).map((entry) => entry.action);
    for (const action of ['member.add', 'member.remove', 'member.restore', 'access.grant', 'access.revoke']) {
      expect(actions.includes(action), `${action} left no vault entry`, actions);
    }
  });
  return 'admission, grant, revoke, removal and re-admission are only vault entries';
}

/** A failure to append may not commit an access change. */
export async function noAuditNoAccess(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'no-audit');
  const { admin } = people;
  await using(deployment.database(), async (sql) => {
    const snapshot = async () => ({
      members: await sql.query('SELECT * FROM vault_members ORDER BY principal'),
      grants: await sql.query('SELECT * FROM vault_grants ORDER BY principal, project_id, environment_id'),
    });
    const before = await snapshot();
    await logRefuses(sql, async () => {
      for (const change of [
        () => admin.api.access.set(person.member, { [DEV]: 'developer' }),
        () => admin.api.members.remove(person.member),
        () => admin.api.members.add('user:no-audit-new@conformance.example'),
      ]) {
        const outcome = await change().then(() => true, () => false);
        expect(!outcome, 'an access change succeeded while the log refused writes');
        expect(JSON.stringify(await snapshot()) === JSON.stringify(before), 'an access change committed without its entry');
      }
    });
  });
  expect((await person.api.secrets.reveal(DEV)).values.API_KEY !== undefined, 'legitimate reads did not recover');
  return 'grant, removal and admission commit nothing while the log refuses their entries';
}
