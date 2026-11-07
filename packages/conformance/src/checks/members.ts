// Who holds what is the vault's record: an access change is its entry or
// nothing, and a member row or grant written around it is refused at use.
import { CoffreError } from '@coffre/client';

import { Browser } from '../browser.ts';
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, Skip, until } from '../report.ts';
import { DEV, PROD, signIn, type People, type Person } from './people.ts';
import { insertRow, logRefuses, query, restoreRow } from './storage.ts';

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
export async function memberTampering(deployment: Deployment, people: People, kind: 'grant' | 'member' | 'stale'): Promise<string> {
  const person = await member(deployment, people, `tamper-${kind}`);
  const { admin } = people;
  const path = kind === 'grant' ? PROD : DEV;
  const protectedValues = Object.values((await admin.api.secrets.reveal(path)).values);
  await using(deployment.database(), async (sql) => {
    const [before] = await query(sql, 'SELECT * FROM principals WHERE principal = $1', [person.member]);
    const grants = await query(sql, 'SELECT * FROM grants WHERE principal = $1', [person.member]);
    expect(before !== undefined && grants.length === 1, 'the fixture has no member row and grant');
    let restored = before;
    let held = grants;
    if (kind === 'stale') {
      await admin.api.access.set(person.member, { [DEV]: 'developer' });
      [restored] = await query(sql, 'SELECT * FROM principals WHERE principal = $1', [person.member]);
      held = await query(sql, 'SELECT * FROM grants WHERE principal = $1', [person.member]);
      await restoreRow(sql, 'principals', before, 'principal');
      await query(sql, 'UPDATE grants SET role = $1, granted_at = $2, granted_by = $3 WHERE principal = $4',
        [grants[0].role, grants[0].granted_at, grants[0].granted_by, person.member]);
    } else if (kind === 'member') {
      // The instance role, as the database's owner could set it: an Owner reads every value.
      await query(sql, "UPDATE principals SET role = 'owner' WHERE principal = $1", [person.member]);
    } else {
      const [place] = await query<{ id: string }>(sql, `SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id
        WHERE p.slug = 'conformance' AND e.slug = 'prod'`);
      expect(place !== undefined, 'no prod environment to forge a grant on');
      await query(sql, `INSERT INTO grants (principal, environment_id, role, granted_at, granted_by) VALUES ($1, $2, 'viewer', $3, $4)`,
        [person.member, place.id, Date.now(), person.member]);
    }
    try {
      const response = await person.browser.send('POST', '/api/reveals', { path });
      const text = await response.text();
      expect(response.status === 401 && (JSON.parse(text) as { error: string }).error === 'unauthenticated', 'the tampered credential was not refused', text);
      expect(!protectedValues.some((value) => text.includes(value)), 'the tampered refusal carried a value', text);
      const reports = await query(sql, `SELECT seq FROM audit_log WHERE author = 'vault' AND action = 'vault.tampered'
        AND subject_principal = $1 AND code = $2`, [person.member, kind === 'stale' ? 'stale' : 'mac']);
      expect(reports.length > 0, 'the tampering was not logged at use', reports);
      expect((await admin.api.members.get(person.member)).status === 'tampered', 'the refused member is not marked tampered');
      const verified = await admin.api.audit.verify();
      expect(!verified.ok && verified.author === 'vault' && verified.failedAtSeq === null, 'the tampered member verifies', verified);
    } finally {
      await restoreRow(sql, 'principals', restored, 'principal');
      await query(sql, 'DELETE FROM grants WHERE principal = $1', [person.member]);
      for (const grant of held) await insertRow(sql, 'grants', grant);
    }
  });
  expect((await person.api.secrets.reveal(DEV)).values.API_KEY !== undefined, 'restoring the member did not restore legitimate use');
  expect((await admin.api.audit.verify()).ok, 'the restored member did not verify');
  return `${kind === 'stale' ? 'a genuine older member row, put back,' : `a forged ${kind}`} refused at use as tampered, logged, then restored`;
}

/**
 * Access changes have one author, the vault that commits the changed rows. A first add down the two-trip path (0.16,
 * on Postgres) writes no 0.14 entry: its record is its change in 0.15's log, `member.add` with the request it was
 * decided on, which only the vault makes (the app's login writes no row of `log_changes`).
 */
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
    if (!actions.includes('member.add')) {
      const changes = await sql.query<{ payload: string }>(`SELECT payload FROM log_changes WHERE payload LIKE '%"op":"member.add"%'`);
      const added = changes.some(({ payload }) => {
        const parsed = JSON.parse(payload) as { ref?: { id?: unknown }; request?: unknown; inputs?: unknown };
        return parsed.ref?.id === person.member && typeof parsed.request === 'object' && typeof parsed.inputs === 'string';
      });
      expect(added, 'member.add left no vault entry, nor a change in 0.15\'s log', actions);
    }
    for (const action of ['member.remove', 'member.restore', 'access.grant', 'access.revoke']) {
      expect(actions.includes(action), `${action} left no vault entry`, actions);
    }
  });
  return 'admission, grant, revoke, removal and re-admission are only the vault\'s records';
}

/** A failure to append may not commit an access change. */
export async function noAuditNoAccess(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'no-audit');
  const { admin } = people;
  await using(deployment.database(), async (sql) => {
    const snapshot = async () => ({
      members: await sql.query('SELECT * FROM principals ORDER BY principal'),
      grants: await sql.query('SELECT * FROM grants ORDER BY principal, project_id, environment_id'),
    });
    const before = await snapshot();
    // Both logs: since 0.16 a first add down the two-trip path appends to 0.15's alone.
    await logRefuses(sql, () => logRefuses(sql, async () => {
      for (const change of [
        () => admin.api.access.set(person.member, { [DEV]: 'developer' }),
        () => admin.api.members.remove(person.member),
        () => admin.api.members.add('user:no-audit-new@conformance.example'),
      ]) {
        const outcome = await change().then(() => true, () => false);
        expect(!outcome, 'an access change succeeded while the log refused writes');
        expect(JSON.stringify(await snapshot()) === JSON.stringify(before), 'an access change committed without its entry');
      }
    }, undefined, 'log_changes'));
  });
  expect((await person.api.secrets.reveal(DEV)).values.API_KEY !== undefined, 'legitimate reads did not recover');
  return 'grant, removal and admission commit nothing while the log refuses their entries';
}

/** Hold the head after the vault checked a member, then forge a grant before it seals them. */
export async function sealingRace(deployment: Deployment, people: People): Promise<string> {
  if (deployment.vaultRuntime === null) throw new Skip('SQLite prevents a write beside a decision; the vault suite covers review R2 on Postgres');
  const [login] = await using(deployment.vaultRuntime(), (sql) => sql.query<{ name: string }>('SELECT current_user AS name'));
  const person = await member(deployment, people, 'seal-race');
  const { admin } = people;
  let forged: string | undefined;
  try {
    await using(deployment.database(), (holder) => using(deployment.database(), async (sql) => {
      const [place] = await query<{ id: string }>(sql, `SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id
        WHERE p.slug = 'conformance' AND e.slug = 'prod'`);
      const [head] = await sql.query<{ next_seq: string | number }>('SELECT next_seq FROM audit_chain_head');
      const [owner] = await holder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      expect(place !== undefined, 'no prod environment for the sealing race');
      await holder.exec('BEGIN');
      let pending;
      try {
        await holder.query('SELECT 1 FROM audit_chain_head FOR UPDATE');
        pending = admin.api.access.set(person.member, { [DEV]: 'developer' }).then(
          (value) => ({ value }), (error: unknown) => ({ error }),
        );
        // The blocking PID proves where the request stopped; no sleep guesses the window.
        await until('the vault decision waiting on our head', async () => {
          const waiting = await query(sql, `SELECT pid FROM pg_stat_activity WHERE datname = current_database()
            AND usename = $1 AND $2 = ANY(pg_blocking_pids(pid))`, [login.name, owner.pid]);
          return waiting.length > 0;
        }, 10);
        await query(sql, `INSERT INTO grants (principal, environment_id, role, granted_at, granted_by)
          VALUES ($1, $2, 'viewer', $3, $4)`, [person.member, place.id, Date.now(), person.member]);
        forged = place.id;
      } finally {
        await holder.exec('ROLLBACK');
        if (pending !== undefined) await pending;
      }
      expect(pending !== undefined, 'the access decision was not started');
      const result = await pending;
      expect('error' in result && result.error instanceof CoffreError && result.error.status === 403
        && result.error.code === 'vault_refused' && result.error.reason === 'tampered',
      'a grant inserted during the decision was not refused as tampered', result);
      const reports = await query(sql, `SELECT seq FROM audit_log WHERE author = 'vault' AND action = 'vault.tampered'
        AND subject_principal = $1 AND code = 'mac' AND seq >= $2`, [person.member, head.next_seq]);
      expect(reports.length > 0, 'the grant inserted during the decision was not reported', reports);
      const response = await person.browser.send('POST', '/api/reveals', { path: PROD });
      const body = await response.json() as { error: string };
      expect(response.status === 401 && body.error === 'unauthenticated', 'the forged grant let its member read', body);
    }));
  } finally {
    // Under 0.15's log a tampered member is not started over until a reseal makes its row the
    // log's again, so the forgery is taken back first, as memberTampering restores its rows.
    if (forged !== undefined) {
      await using(deployment.database(), (sql) => query(sql, `DELETE FROM grants
        WHERE principal = $1 AND environment_id = $2`, [person.member, forged]));
    }
    await admin.api.members.remove(person.member);
  }
  expect((await admin.api.audit.verify()).ok, 'the log did not verify after recovering the sealing-race member');
  return 'a grant inserted while the vault waited on the head was refused as tampered and logged; taking it back and removing the member recovered';
}
