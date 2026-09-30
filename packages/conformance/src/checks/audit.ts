// What is written down: every value opened, in both logs, which agree; no
// value without its entry; and a log changed behind coffre's back is caught.
import type { AuditEntryView, CoffreClient, RouteOutput } from '@coffre/client';

import { sqlite, using, type Sql } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, Skip } from '../report.ts';
import { DEV, valuesIn, type Canaries, type People } from './people.ts';

/** One reveal, one `secret.read` per value, all under the reveal's bundle. */
export async function revealAudited({ admin, reader }: People, canaries: Canaries): Promise<string> {
  const { bundleId } = await reader.api.secrets.reveal(DEV);
  const { entries } = await admin.api.audit.list({ path: DEV, actor: reader.member, limit: 100 });
  const bundle = entries.filter((entry) => entry.bundleId === bundleId);
  const keys = bundle.map((entry) => entry.metadata.key).sort();
  const expected = Object.keys(valuesIn(canaries, DEV)).sort();
  expect(JSON.stringify(keys) === JSON.stringify(expected), 'the reveal is not logged once per value', bundle);
  expect(
    bundle.every((entry) => entry.action === 'secret.read' && entry.decision === 'allow' && entry.requestId === bundle[0]!.requestId),
    "the reveal's entries are not one request's reads",
    bundle,
  );
  const { keys: listed } = await admin.api.secrets.list(DEV);
  for (const entry of bundle) {
    const current = listed.find((key) => key.key === entry.metadata.key);
    expect(entry.metadata.version === current?.version, `the entry for ${String(entry.metadata.key)} names another version`, entry);
  }
  return `${bundle.length} values revealed, ${bundle.length} secret.read entries under the reveal's bundle`;
}

/**
 * Each heartbeat has the vault sign the audit log's head, which must extend
 * the last head it signed, with its own log's. Two, so the second extends
 * the first; then both logs are verified from their first entry.
 */
export async function checkpoints(deployment: Deployment, { admin }: People): Promise<string> {
  const before = await admin.api.audit.verify();
  expect(before.ok, 'the logs do not verify', before);
  await deployment.scheduled();
  await deployment.scheduled();
  const after = await admin.api.audit.verify();
  expect(after.ok && after.checkpoint !== null, 'the audit log is not verified and checkpointed', after);
  expect(after.checkpoint.seq >= before.rows, 'the checkpoint does not cover what was written before it', { before, after });
  expect(after.vault.entries > 0, "the verification did not check the vault's log", after);
  const vault = await admin.api.audit.vault({ full: '1' });
  expect(vault.verification.ok, "the vault's log does not verify", vault.verification);
  return `${after.rows} audit entries and ${after.vault.entries} vault entries verified, checkpointed at ${after.checkpoint.seq}`;
}

/**
 * Every key the vault opened or sealed has the app's entry for it, and every
 * value the app says it read or wrote went through the vault: matched by who,
 * which request, which secret and which version, both ways.
 */
export async function logsAgree({ admin }: People): Promise<string> {
  const app = new Map<string, number>();
  for (const entry of await everyAuditEntry(admin.api)) {
    if (entry.decision !== 'allow' || typeof entry.metadata.key !== 'string') continue;
    const kind = entry.action === 'secret.read' ? 'read' : entry.action === 'secret.write' ? 'wrote' : null;
    if (kind === null) continue;
    const actor = `${entry.actorType === 'user' ? 'user' : 'token'}:${entry.actorId}`;
    const path = `${entry.project}/${entry.environment}/${entry.metadata.key}`;
    count(app, key(actor, kind, path, entry.metadata.version, entry.requestId));
  }
  const vault = new Map<string, number>();
  for (const entry of await everyVaultEntry(admin.api)) {
    if (entry.outcome !== 'allow') continue;
    const kind = entry.action === 'unwrap' ? 'read' : entry.action === 'wrap' ? 'wrote' : null;
    if (kind === null) continue;
    count(vault, key(entry.actor, kind, entry.subject, entry.detail.version, entry.detail.requestId));
  }
  for (const [one, other, missing] of [
    [vault, app, 'the vault opened or sealed a key the audit log does not account for'],
    [app, vault, 'the audit log records a value the vault never opened or sealed'],
  ] as const) {
    for (const [entry, n] of one) {
      expect((other.get(entry) ?? 0) === n, missing, JSON.parse(entry));
    }
  }
  const total = [...vault.values()].reduce((sum, n) => sum + n, 0);
  return `${total} keys opened or sealed, each once in each log, by the same member in the same request`;
}

/**
 * The app may not hand out a value it could not log: with the audit log
 * refusing writes (a trigger, as a full disk or a lost connection would), a
 * reveal fails and carries nothing.
 */
export async function noAuditNoValue(deployment: Deployment, { admin }: People, canaries: Canaries): Promise<string> {
  const [refuse, allow] =
    deployment.kind === 'workers'
      ? [
          `CREATE FUNCTION conformance_no_audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'coffre-conformance: the audit log refuses writes'; END $$;
           CREATE TRIGGER conformance_no_audit BEFORE INSERT ON audit_log
             FOR EACH ROW EXECUTE FUNCTION conformance_no_audit();`,
          'DROP TRIGGER conformance_no_audit ON audit_log; DROP FUNCTION conformance_no_audit();',
        ]
      : [
          `CREATE TRIGGER conformance_no_audit BEFORE INSERT ON audit_log
           BEGIN SELECT RAISE(ABORT, 'coffre-conformance: the audit log refuses writes'); END;`,
          'DROP TRIGGER conformance_no_audit;',
        ];
  let status = 0;
  await using(deployment.database(), async (sql) => {
    await sql.exec(refuse);
    try {
      const response = await admin.browser.send('POST', '/api/reveals', { path: DEV });
      const text = await response.text();
      status = response.status;
      expect(!response.ok, `a reveal answered ${response.status} while the audit log refused writes`, text);
      expect(!Object.values(canaries).some((value) => text.includes(value)), 'a reveal that could not be logged carried a value', text);
    } finally {
      await sql.exec(allow);
    }
  });
  const after = await admin.api.secrets.reveal(DEV);
  expect(after.values.API_KEY === canaries[`${DEV}/API_KEY`], 'reveals did not come back once the log took writes again');
  return `a reveal the audit log would not take: ${status}, and no value`;
}

/**
 * The login the app runs as may add to the log, and never change or remove
 * what is there, nor any version of a secret.
 */
export async function appendOnly(deployment: Deployment): Promise<string> {
  if (deployment.runtime === null) throw new Skip('SQLite has no logins; the file is as safe as its permissions');
  const statements = [
    "UPDATE audit_log SET action = 'rewritten'",
    'DELETE FROM audit_log',
    'TRUNCATE audit_log',
    'DROP TABLE audit_log',
    'UPDATE secret_versions SET id = id',
    'DELETE FROM secret_versions',
    'DELETE FROM secrets',
    'DELETE FROM principals',
    'CREATE TABLE conformance_probe (id integer)',
  ];
  await using(deployment.runtime(), async (sql) => {
    for (const statement of statements) {
      await sql.exec('BEGIN');
      const error = await sql.exec(statement).then(
        () => null,
        (failure: unknown) => failure,
      );
      await sql.exec('ROLLBACK');
      expect(error !== null, `the app's login could: ${statement}`);
      expect((error as { code?: string }).code === '42501', `${statement} failed, but not for want of privilege`, error);
    }
  });
  return `the app's login is refused ${statements.length} ways to change or remove what is written`;
}

/**
 * Change the logs where they are stored, as someone with the database or the
 * vault's file could, and the verification must say which broke. Each is put
 * back after, but the last: the newest audit entries, deleted.
 */
export async function tamper(deployment: Deployment, { admin }: People): Promise<string> {
  const caught: string[] = [];
  const verify = () => admin.api.audit.verify();
  const intact = await verify();
  expect(intact.ok && intact.checkpoint !== null, 'the logs do not verify before any tampering', intact);
  const signed = intact.checkpoint.seq;

  await using(deployment.database(), async (sql) => {
    const [row] = await sql.query<{ seq: number | string; actor_id: string }>(
      `SELECT seq, actor_id FROM audit_log WHERE action = 'secret.read' ORDER BY seq LIMIT 1`,
    );
    expect(row !== undefined, 'the audit log has no secret.read entry to rewrite');
    const seq = Number(row.seq);
    await update(sql, 'UPDATE audit_log SET actor_id = $1 WHERE seq = $2', ['user:nobody@conformance.example', seq]);
    const rewritten = await verify();
    expect(!rewritten.ok && rewritten.log === 'audit', 'an audit entry rewritten in the database verifies', rewritten);
    await update(sql, 'UPDATE audit_log SET actor_id = $1 WHERE seq = $2', [row.actor_id, seq]);
    const restored = await verify();
    expect(restored.ok, 'the audit log did not verify once put back', restored);
    caught.push(`an audit entry rewritten (at ${rewritten.failedAtSeq})`);
  });

  const store = deployment.vaultStore();
  if (store === null) {
    caught.push("the vault's store not found, so not tampered with");
  } else {
    await using(sqlite(store), async (vault) => {
      // A grant written straight into the store, which its log never gave.
      const [place] = await vault.query<{ project_id: string }>('SELECT project_id FROM grants LIMIT 1');
      expect(place !== undefined, "the vault's store holds no grant");
      const forged = ['user:forger@conformance.example', place.project_id, 'owner', Date.now(), 'user:forger@conformance.example'];
      await vault.query(
        'INSERT INTO grants (principal, project_id, environment_id, role, expires_at, granted_at, granted_by) VALUES (?, ?, NULL, ?, NULL, ?, ?)',
        forged,
      );
      const granted = await verify();
      await vault.query('DELETE FROM grants WHERE principal = ?', [forged[0]]);
      expect(!granted.ok && granted.log === 'vault', "a grant written into the vault's store verifies", granted);
      const revoked = await verify();
      expect(revoked.ok, "the vault's log did not verify once the grant was gone", revoked);
      caught.push('a grant the vault never gave');

      // An entry of its log rewritten, its trigger dropped for the time.
      const [trigger] = await vault.query<{ sql: string }>(`SELECT sql FROM sqlite_master WHERE name = 'log_no_update'`);
      const [entry] = await vault.query<{ seq: number; actor: string }>(`SELECT seq, actor FROM log WHERE action = 'unwrap' ORDER BY seq LIMIT 1`);
      expect(trigger !== undefined && entry !== undefined, "the vault's store has no log_no_update trigger, or no unwrap");
      await vault.exec('DROP TRIGGER log_no_update');
      try {
        await vault.query('UPDATE log SET actor = ? WHERE seq = ?', ['user:nobody@conformance.example', entry.seq]);
        const rewritten = await verify();
        await vault.query('UPDATE log SET actor = ? WHERE seq = ?', [entry.actor, entry.seq]);
        expect(!rewritten.ok && rewritten.log === 'vault', "an entry rewritten in the vault's log verifies", rewritten);
      } finally {
        await vault.exec(trigger.sql);
      }
      const restored = await verify();
      expect(restored.ok, "the vault's log did not verify once put back", restored);
      caught.push(`a vault entry rewritten (at ${entry.seq})`);
    });
  }

  // Last, since nothing puts them back: the entries the vault last signed for.
  await using(deployment.database(), (sql) => update(sql, 'DELETE FROM audit_log WHERE seq >= $1', [signed]));
  const truncated = await verify();
  expect(!truncated.ok && truncated.log === 'audit', 'the audit log verifies with its newest entries deleted', truncated);
  caught.push('the newest audit entries deleted');
  return `caught: ${caught.join('; ')}`;
}

/** `$1` on Postgres, `?` on SQLite. */
function update(sql: Sql, statement: string, params: unknown[]): Promise<unknown> {
  return sql.query(sql.engine === 'sqlite' ? statement.replace(/\$\d+/g, '?') : statement, params);
}

async function everyAuditEntry(api: CoffreClient): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: number | undefined; ; ) {
    const { entries } = await api.audit.list({ before, limit: 500 });
    all.push(...entries);
    if (entries.length < 500) return all;
    before = entries.at(-1)!.seq;
  }
}

async function everyVaultEntry(api: CoffreClient): Promise<RouteOutput<'GET /audit/vault'>['entries']> {
  const all: RouteOutput<'GET /audit/vault'>['entries'] = [];
  for (let before: number | undefined; ; ) {
    const { entries } = await api.audit.vault({ before, limit: 200 });
    all.push(...entries);
    if (entries.length < 200) return all;
    before = entries.at(-1)!.seq;
  }
}

function key(actor: string, kind: 'read' | 'wrote', path: string | null, version: unknown, requestId: unknown): string {
  return JSON.stringify({ actor, kind, path, version, requestId });
}

function count(counts: Map<string, number>, entry: string): void {
  counts.set(entry, (counts.get(entry) ?? 0) + 1);
}
