// Who holds what is the vault's record: an access change is its entry or
// nothing, and a member row or grant written around it is never honoured,
// or alerted on.
import { randomUUID } from 'node:crypto';

import { Browser } from '../browser.ts';
import { using, type Sql } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { DEV, PROD, signIn, type People, type Person } from './people.ts';
import { alerted, insertRow, logBodies, logRefuses, query, restoreRow } from './storage.ts';

export async function member(deployment: Deployment, { admin }: People, name: string): Promise<Person> {
  const email = `${name}@conformance.example`;
  const principal = `user:${email}`;
  await admin.api.members.add(principal);
  await admin.api.access.set(principal, { [DEV]: 'viewer' });
  const browser = new Browser(deployment.origin);
  expect((await signIn(deployment, browser, email)).ok, 'the fixture member could not sign in');
  return { email, member: principal, browser, api: browser.client() };
}

/** The conformance project's prod environment, by id. */
async function prodId(sql: Sql): Promise<string> {
  const [place] = await query<{ id: string }>(sql, `SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id
    WHERE p.slug = 'conformance' AND e.slug = 'prod'`);
  expect(place !== undefined, 'no prod environment to forge a grant on');
  return place.id;
}

/** A grant on prod, as the database's owner could write it: the member's own generation, and no MAC of the vault's. */
async function forgeGrant(sql: Sql, principal: string): Promise<string> {
  const id = randomUUID();
  await query(sql, `INSERT INTO grants (id, principal, generation, environment_id, role, granted_at, granted_by)
    SELECT $1, id, generation, $2, 'viewer', now(), id FROM principals WHERE id = $3`, [id, await prodId(sql), principal]);
  return id;
}

/**
 * A use that reads nothing, refused as `refusal` says: 401 for a member row
 * that is no longer the vault's, 403 for a place the member's sealed grants
 * do not reach. The vault may answer from its memory of the caller for up
 * to 2 seconds (D218), so it is asked again until then and a second more.
 */
async function readsNothing(person: Person, path: string, values: string[], what: string, refusal: { status: 401; error: 'unauthenticated' } | { status: 403; reason: 'no_access' }): Promise<number> {
  const started = Date.now();
  for (;;) {
    const response = await person.browser.send('POST', '/api/reveals', { path });
    const text = await response.text();
    expect(!response.ok, `${what} was honoured`, text);
    expect(!values.some((value) => text.includes(value)), `${what} was refused with a value`, text);
    const body = JSON.parse(text) as { error?: string; reason?: string };
    const as = 'error' in refusal ? body.error === refusal.error : body.reason === refusal.reason;
    if (response.status === refusal.status && as) return response.status;
    expect(Date.now() - started < 3000, `${what} was refused as ${response.status}, not ${refusal.status}`, text);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

const NO_ACCESS = { status: 403, reason: 'no_access' } as const;

/**
 * A member row or grant written around the vault: a forged grant or an
 * edited member is never honoured, since its MAC is not the vault's; a
 * genuine older grant put back is served until someone acts, as an
 * ordinary revocation is until the vault's memory lapses (D216). The
 * signer names a row inserted or put back in its alert within the minute;
 * a row edited under the MAC it had is refused at use and not named, since
 * the minute's check compares MACs (docs/design/0.16.md, "What it
 * promises" and "How long the log is kept"). 0.14 refused all three at
 * use and logged `vault.tampered`; 0.16 logs no such entry, and its
 * members' `tampered` is always false (docs/design/0.16.md, "Members").
 */
export async function memberTampering(deployment: Deployment, people: People, kind: 'grant' | 'member' | 'stale'): Promise<string> {
  const person = await member(deployment, people, `tamper-${kind}`);
  const { admin } = people;
  const protectedValues = Object.values((await admin.api.secrets.reveal(PROD)).values);
  let refused = 0;
  await using(deployment.database(), async (sql) => {
    const [before] = await query(sql, 'SELECT * FROM principals WHERE id = $1', [person.member]);
    const grants = await query<{ id: string }>(sql, 'SELECT * FROM grants WHERE principal = $1', [person.member]);
    expect(before !== undefined && grants.length === 1, 'the fixture has no member row and grant');
    let held = grants;
    let named: [string, string] | undefined;
    try {
      if (kind === 'stale') {
        // The viewer's grant, genuine and sealed, put back once the vault has made them a developer.
        await admin.api.access.set(person.member, { [DEV]: 'developer' });
        held = await query(sql, 'SELECT * FROM grants WHERE principal = $1', [person.member]);
        await query(sql, 'DELETE FROM grants WHERE principal = $1', [person.member]);
        for (const grant of grants) await insertRow(sql, 'grants', grant);
        named = ['grants', grants[0]!.id];
        // Served while it stands: the viewer's grant still reads dev.
        expect((await person.api.secrets.reveal(DEV)).values.API_KEY !== undefined, 'a genuine older grant put back was not served');
      } else if (kind === 'member') {
        // The instance role, as the database's owner could set it: an Owner reads every value.
        await query(sql, "UPDATE principals SET role = 'owner' WHERE id = $1", [person.member]);
        refused = await readsNothing(person, PROD, protectedValues, 'an edited member row', { status: 401, error: 'unauthenticated' });
      } else {
        named = ['grants', await forgeGrant(sql, person.member)];
        refused = await readsNothing(person, PROD, protectedValues, 'a forged grant', NO_ACCESS);
      }
      if (named !== undefined) await alerted(deployment, ...named);
    } finally {
      await restoreRow(sql, 'principals', before, 'id');
      await query(sql, 'DELETE FROM grants WHERE principal = $1', [person.member]);
      for (const grant of held) await insertRow(sql, 'grants', grant);
    }
  });
  expect((await person.api.secrets.reveal(DEV)).values.API_KEY !== undefined, 'restoring the member did not restore legitimate use');
  if (kind === 'stale') return 'a genuine older grant, put back, served and named in the signer\'s alert, then restored';
  if (kind === 'member') return `an edited member row refused at use (${refused}), then restored`;
  return `a forged grant refused at use (${refused}) and named in the signer's alert, then restored`;
}

/** Admission, grant, revoke, removal and re-admission are each the vault's entry, naming the member. */
export async function accessAuthorship(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'access-actions');
  const { admin } = people;
  await admin.api.access.set(person.member, { [DEV]: null });
  await admin.api.members.remove(person.member);
  await admin.api.members.add(person.member);
  // Read from the database: an entry the signer has not taken yet is not on the audit page, and the app writes none.
  const actions = (await using(deployment.database(), logBodies))
    .filter((body) => body.detail.refused === undefined && body.objects.includes(`principal:${person.member}`))
    .map((body) => body.action);
  for (const action of ['member.add', 'member.remove', 'member.restore', 'access.grant', 'access.revoke']) {
    expect(actions.includes(action), `${action} left no vault entry`, actions);
  }
  return 'admission, grant, revoke, removal and re-admission are each a vault entry';
}

/** A failure to append may not commit an access change. */
export async function noAuditNoAccess(deployment: Deployment, people: People): Promise<string> {
  const person = await member(deployment, people, 'no-audit');
  const { admin } = people;
  await using(deployment.database(), async (sql) => {
    const snapshot = async () => ({
      members: await sql.query('SELECT * FROM principals ORDER BY id'),
      grants: await sql.query('SELECT * FROM grants ORDER BY principal, project_id, environment_id'),
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

/**
 * The vault's change lock (`CHANGE_LOCK` in @coffre/vault's change.ts): a
 * change's write takes it, then writes each row only if its MAC is still
 * the one it read (docs/design/0.16.md, "A change").
 */
const CHANGE_LOCK = '109330110509669';

/**
 * Hold the change lock while a change waits to write, and forge a grant
 * meanwhile: the vault seals only the rows it decided on, so the forged
 * one stays unsealed and reaches nothing. 0.14's race held its log's head,
 * which a change of 0.16 never locks.
 */
export async function sealingRace(deployment: Deployment, people: People): Promise<string> {
  const [login] = await using(deployment.vaultRuntime(), (sql) => sql.query<{ name: string }>('SELECT current_user AS name'));
  const person = await member(deployment, people, 'seal-race');
  const { admin } = people;
  const protectedValues = Object.values((await admin.api.secrets.reveal(PROD)).values);
  let forged: string | undefined;
  try {
    await using(deployment.database(), (holder) => using(deployment.database(), async (sql) => {
      const [owner] = await holder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      await holder.exec('BEGIN');
      let pending;
      let outcome: { value: unknown } | { error: unknown } | undefined;
      try {
        await holder.query(`SELECT pg_advisory_xact_lock(${CHANGE_LOCK})`);
        pending = admin.api.access.set(person.member, { [DEV]: 'developer' }).then(
          (value) => ({ value }), (error: unknown) => ({ error }),
        );
        // The blocking PID proves where the request stopped; no sleep guesses the window.
        await until("the vault's change waiting on the change lock", async () => {
          const waiting = await query(sql, `SELECT pid FROM pg_stat_activity WHERE datname = current_database()
            AND usename = $1 AND $2 = ANY(pg_blocking_pids(pid))`, [login.name, owner.pid]);
          return waiting.length > 0;
        }, 10);
        forged = await forgeGrant(sql, person.member);
      } finally {
        await holder.exec('ROLLBACK');
        if (pending !== undefined) outcome = await pending;
      }
      // The change went through once the lock was let go: otherwise the grant keeps no MAC whatever sealing does.
      expect(outcome !== undefined && 'value' in outcome, 'the change that waited on the lock did not go through', outcome !== undefined && 'error' in outcome ? String(outcome.error) : outcome);
      const [dev] = await query<{ role: string }>(sql, `SELECT g.role FROM grants g JOIN environments e ON e.id = g.environment_id
        JOIN projects p ON p.id = e.project_id WHERE g.principal = $1 AND p.slug = 'conformance' AND e.slug = 'dev' AND length(g.mac) > 0`, [person.member]);
      expect(dev?.role === 'developer', 'the change that waited on the lock did not make the member a developer on dev', dev);
      const [row] = await query<{ mac: Uint8Array }>(sql, 'SELECT mac FROM grants WHERE id = $1', [forged]);
      expect(row !== undefined && row.mac.length === 0, 'the change sealed the grant inserted while it waited', row);
      await readsNothing(person, PROD, protectedValues, 'the grant inserted while the change waited', NO_ACCESS);
    }));
  } finally {
    if (forged !== undefined) await using(deployment.database(), (sql) => query(sql, 'DELETE FROM grants WHERE id = $1', [forged]));
    await admin.api.members.remove(person.member);
  }
  return 'a grant inserted while a change waited on the change lock was not sealed by it, and reaches nothing; removal recovered the member';
}
