// What is written down: every value opened, by the vault that opened it;
// every version stored, naming the vault's wrap of its key; no value without
// its entry; and a log changed behind coffre's back is caught.
import { createHash } from 'node:crypto';

import type { AuditEntryView, CoffreClient } from '@coffre/client';

import { using, type Sql } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, Skip } from '../report.ts';
import { DEV, valuesIn, type Canaries, type People } from './people.ts';

/** One reveal, one `secret.read` per value, the vault's, all under the reveal's operation. */
export async function revealAudited({ admin, reader }: People, canaries: Canaries): Promise<string> {
  const { operationId } = await reader.api.secrets.reveal(DEV);
  const { entries } = await admin.api.audit.list({ path: DEV, actor: reader.member, limit: 100 });
  const bundle = entries.filter((entry) => entry.operationId === operationId);
  const keys = bundle.map((entry) => entry.key).sort();
  const expected = Object.keys(valuesIn(canaries, DEV)).sort();
  expect(JSON.stringify(keys) === JSON.stringify(expected), 'the reveal is not logged once per value', bundle);
  expect(
    bundle.every((entry) =>
      entry.author === 'vault' && entry.action === 'secret.read' && entry.decision === 'allow'
      && entry.metadata.purpose === 'run' && entry.requestId === bundle[0]!.requestId),
    "the reveal's entries are not the vault's reads for one request",
    bundle,
  );
  const { keys: listed } = await admin.api.secrets.list(DEV);
  for (const entry of bundle) {
    const current = listed.find((key) => key.key === entry.key);
    expect(entry.version === current?.version, `the entry for ${String(entry.key)} names another version`, entry);
  }
  return `${bundle.length} values revealed, ${bundle.length} secret.read entries of the vault's under the reveal's operation`;
}

/**
 * Each heartbeat has the vault sign the log up to its last entry, in an
 * entry of its own, after checking that the prefix it signed last is still
 * there. Two, so the second covers the first; then the log is verified from
 * its first entry, every checkpoint with it.
 */
export async function checkpoints(deployment: Deployment, { admin }: People): Promise<string> {
  const before = await admin.api.audit.verify();
  expect(before.ok, 'the log does not verify', before);
  await deployment.scheduled();
  await deployment.scheduled();
  const after = await admin.api.audit.verify();
  expect(after.ok && after.checkpoint !== null, 'the audit log is not verified and checkpointed', after);
  expect(after.checkpoint.seq > (before.through ?? -1), 'the checkpoint does not cover what was written before it', { before, after });
  const { entries } = await admin.api.audit.list({ detail: '1', limit: 20 });
  const signed = entries.filter((entry) => entry.action === 'audit.checkpoint' && entry.decision === 'allow');
  expect(
    signed.length >= 2 && signed.every((entry) => entry.author === 'vault' && entry.detail),
    "the checkpoints are not the vault's entries, hidden as detail",
    signed,
  );
  const [newest, previous] = signed as [AuditEntryView, AuditEntryView];
  expect(newest.metadata.seq === after.checkpoint.seq, 'the newest checkpoint entry is not the one verified', { signed, after });
  expect(previous.seq <= after.checkpoint.seq, 'the newest checkpoint does not cover the one before it', signed);
  return `${after.entries} entries verified through ${after.through}, checkpointed at ${after.checkpoint.seq}`;
}

/**
 * Every version the app says it stored names the vault's entry for the key
 * it was sealed with, `key.wrap` for a write and `key.rewrap` for a restore:
 * the same member, request and operation, the same secret and version. And
 * every value read is the vault's to log: the app keeps no reads of its own.
 */
export async function writesAgree({ admin }: People): Promise<string> {
  const entries = await everyAuditEntry(admin.api);
  const bySeq = new Map(entries.map((entry) => [entry.seq, entry]));
  let stored = 0;
  for (const entry of entries) {
    if (entry.author !== 'app' || entry.decision !== 'allow') continue;
    expect(entry.action !== 'secret.read' || entry.key === null, 'the app logged a read of a value, which only the vault opens', entry);
    const sealed = { 'secret.write': 'key.wrap', 'secret.restore': 'key.rewrap' }[entry.action];
    if (sealed === undefined) continue;
    const key = entry.relatedSeq === null ? undefined : bySeq.get(entry.relatedSeq);
    expect(
      key !== undefined && key.author === 'vault' && key.action === sealed && key.decision === 'allow',
      `a ${entry.action} names no ${sealed} of the vault's`,
      { entry, key },
    );
    const same = (fields: (keyof AuditEntryView)[]) => fields.every((field) => key[field] === entry[field]);
    expect(same(['actorType', 'actorId', 'requestId', 'operationId']), `a ${entry.action} names a key sealed for another call`, { entry, key });
    expect(same(['project', 'environment', 'key', 'version']), `a ${entry.action} names a key sealed for another version`, { entry, key });
    stored++;
  }
  return `${stored} versions stored, each naming the vault's seal of its key, by the same member in the same operation`;
}

/**
 * No value leaves without its entry: with the audit log refusing writes (a
 * trigger, as a full disk or a lost connection would), the vault cannot log
 * the read, so a reveal fails and carries nothing.
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
 * The logins the app and the vault run as may add to the log, each only as
 * itself, and never change or remove what is there, nor any version of a
 * secret. Only the vault's writes members and grants.
 */
export async function appendOnly(deployment: Deployment): Promise<string> {
  if (deployment.runtime === null || deployment.vaultRuntime === null) {
    throw new Skip('SQLite has no logins; the file is as safe as its permissions');
  }
  const changes = [
    "UPDATE audit_log SET action = 'rewritten'",
    'DELETE FROM audit_log',
    'TRUNCATE audit_log',
    'DROP TABLE audit_log',
    'UPDATE secret_versions SET id = id',
    'DELETE FROM secret_versions',
    'DELETE FROM secrets',
    'DELETE FROM vault_members',
    'CREATE TABLE conformance_probe (id integer)',
  ];
  const zeros = "decode(repeat('00', 32), 'hex')";
  const as = (author: string) =>
    `INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, prev_hash, mac, hash)
      VALUES (9000000000, '${author}', '${author}:0', 0, 'system:conformance', 'probe', 'allow', ${zeros}, ${zeros}, ${zeros})`;
  const logins = [
    ["the app's login", deployment.runtime, [...changes, as('vault'), "UPDATE vault_members SET owner = true", 'DELETE FROM vault_grants']],
    ["the vault's login", deployment.vaultRuntime, [...changes, as('app'), "UPDATE projects SET name = 'renamed'"]],
  ] as const;
  let refused = 0;
  for (const [login, open, statements] of logins) {
    await using(open(), async (sql) => {
      for (const statement of statements) {
        await sql.exec('BEGIN');
        const error = await sql.exec(statement).then(
          () => null,
          (failure: unknown) => failure,
        );
        await sql.exec('ROLLBACK');
        expect(error !== null, `${login} could: ${statement}`);
        expect((error as { code?: string }).code === '42501', `${statement} failed, but not for want of privilege`, error);
        refused++;
      }
    });
  }
  return `the app's and the vault's logins are refused ${refused} ways to change what is written, or to write as the other`;
}

/**
 * A grant and a vault entry written around the vault must both fail
 * verification: the grant by the vault's replay of its entries, the entry,
 * linked to the chain so every public check passes, by the vault's MAC,
 * which nobody without its key can make.
 */
export async function tamperVault(deployment: Deployment, { admin }: People): Promise<string> {
  const caught: string[] = [];
  const verify = () => admin.api.audit.verify();
  const intact = await verify();
  expect(intact.ok, 'the log does not verify before any vault tampering', intact);
  await using(deployment.database(), async (sql) => {
    // A grant written straight into the database, which the vault never gave.
    const [place] = await sql.query<{ principal: string; project_id: string }>(
      `SELECT m.principal, p.id AS project_id FROM vault_members m CROSS JOIN projects p
        WHERE m.status = 'active' AND NOT EXISTS (
          SELECT 1 FROM vault_grants g WHERE g.principal = m.principal AND g.project_id = p.id)
        LIMIT 1`,
    );
    expect(place !== undefined, 'no member is without a grant on some project');
    await update(
      sql,
      'INSERT INTO vault_grants (principal, project_id, role, granted_at, granted_by) VALUES ($1, $2, $3, $4, $5)',
      [place.principal, place.project_id, 'owner', Date.now(), place.principal],
    );
    const granted = await verify();
    await update(sql, 'DELETE FROM vault_grants WHERE principal = $1 AND project_id = $2', [place.principal, place.project_id]);
    expect(!granted.ok && granted.author === 'vault', 'a grant written into the database verifies', granted);
    const revoked = await verify();
    expect(revoked.ok, 'the log did not verify once the grant was gone', revoked);
    caught.push('a grant the vault never gave');

    // An entry in the vault's name, chained after the last, with a MAC made up.
    const [head] = await sql.query<{ next_seq: number | string; head_hash: Uint8Array }>(
      'SELECT next_seq, head_hash FROM audit_chain_head',
    );
    const seq = BigInt(head.next_seq);
    const forged = {
      seq, author: 'vault', keyId: 'vault:0000000000000000', occurredAt: Date.now(), actor: 'user:forger@conformance.example',
      action: 'secret.read', decision: 'allow', metadata: '{}',
    };
    const prevHash = Buffer.from(head.head_hash);
    const mac = Buffer.alloc(32, 0x41);
    const hash = chainHash(prevHash, forged, mac);
    await update(
      sql,
      `INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [seq, forged.author, forged.keyId, forged.occurredAt, forged.actor, forged.action, forged.decision, forged.metadata, prevHash, mac, hash],
    );
    await update(sql, 'UPDATE audit_chain_head SET next_seq = $1, head_hash = $2', [seq + 1n, hash]);
    const inserted = await verify();
    await appendOnlyLifted(sql, () => update(sql, 'DELETE FROM audit_log WHERE seq = $1', [seq]));
    await update(sql, 'UPDATE audit_chain_head SET next_seq = $1, head_hash = $2', [seq, prevHash]);
    expect(!inserted.ok && inserted.author === 'vault', "an entry in the vault's name, chained but not by the vault, verifies", inserted);
    const removed = await verify();
    expect(removed.ok, 'the log did not verify once the entry was gone', removed);
    caught.push(`an entry forged in the vault's name (at ${seq})`);
  });
  return `caught: ${caught.join('; ')}`;
}

/**
 * An entry's public chain hash, as the log's format defines it
 * (@coffre/core/audit): SHA-256 over a domain, the previous hash, each
 * field length-prefixed in order, a null as length -1, and the MAC. Only
 * the fields given are set; the rest are null.
 */
function chainHash(prevHash: Buffer, fields: Record<string, string | number | bigint>, mac: Buffer): Buffer {
  const order = [
    'seq', 'author', 'keyId', 'occurredAt', 'actor', 'action', 'decision', 'code', 'subjectPrincipal', 'projectId',
    'environmentId', 'secretId', 'secretVersionId', 'operationId', 'requestId', 'sourceIp', 'relatedSeq', 'metadata',
  ];
  const hash = createHash('sha256').update('coffre.audit.chain.v2').update(prevHash);
  for (const name of order) {
    const length = Buffer.alloc(4);
    const value = fields[name];
    if (value === undefined) {
      hash.update(length.fill(0xff));
      continue;
    }
    const bytes = Buffer.from(String(value), 'utf8');
    length.writeInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.update(mac).digest();
}

/**
 * Rewrite an entry and then remove the log's tail. The latter stays
 * broken, so this runs after every check that needs an intact log.
 */
export async function tamperApp(deployment: Deployment, { admin }: People): Promise<string> {
  const caught: string[] = [];
  const verify = () => admin.api.audit.verify();
  const intact = await verify();
  expect(intact.ok && intact.checkpoint !== null, 'the log does not verify before any tampering', intact);
  const signed = intact.checkpoint.seq;

  await using(deployment.database(), (sql) =>
    appendOnlyLifted(sql, async () => {
      const [row] = await sql.query<{ seq: number | string; actor: string }>(
        `SELECT seq, actor FROM audit_log WHERE action = 'secret.read' ORDER BY seq LIMIT 1`,
      );
      expect(row !== undefined, 'the audit log has no secret.read entry to rewrite');
      const seq = Number(row.seq);
      await update(sql, 'UPDATE audit_log SET actor = $1 WHERE seq = $2', ['user:nobody@conformance.example', seq]);
      const rewritten = await verify();
      expect(!rewritten.ok && rewritten.failedAtSeq === seq, 'an audit entry rewritten in the database verifies', rewritten);
      await update(sql, 'UPDATE audit_log SET actor = $1 WHERE seq = $2', [row.actor, seq]);
      const restored = await verify();
      expect(restored.ok, 'the audit log did not verify once put back', restored);
      caught.push(`an audit entry rewritten (at ${rewritten.failedAtSeq})`);
    }),
  );

  // Last, since nothing puts them back: the entries the vault last signed for.
  await using(deployment.database(), (sql) =>
    appendOnlyLifted(sql, async () => {
      // SQLite checks the link from a write to its key.wrap row by row: unlink the tail first.
      await update(sql, 'UPDATE audit_log SET related_seq = NULL WHERE seq >= $1', [signed]);
      await update(sql, 'DELETE FROM audit_log WHERE seq >= $1', [signed]);
    }),
  );
  const truncated = await verify();
  expect(!truncated.ok && truncated.author === 'app', 'the audit log verifies with its newest entries deleted', truncated);
  caught.push('the newest audit entries deleted');
  return `caught: ${caught.join('; ')}`;
}

/**
 * `work` with the audit log's append-only triggers lifted, as only its owner
 * can: Postgres disables them for the session, SQLite drops them and makes
 * them again after.
 */
async function appendOnlyLifted<T>(sql: Sql, work: () => Promise<T>): Promise<T> {
  if (sql.engine === 'postgres') {
    await sql.exec('ALTER TABLE audit_log DISABLE TRIGGER USER');
    try {
      return await work();
    } finally {
      await sql.exec('ALTER TABLE audit_log ENABLE TRIGGER USER');
    }
  }
  const triggers = await sql.query<{ name: string; sql: string }>(
    `SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'`,
  );
  for (const trigger of triggers) await sql.exec(`DROP TRIGGER ${trigger.name}`);
  try {
    return await work();
  } finally {
    for (const trigger of triggers) await sql.exec(trigger.sql);
  }
}

/** `$1` on Postgres, `?` on SQLite. */
function update(sql: Sql, statement: string, params: unknown[]): Promise<unknown> {
  return sql.query(sql.engine === 'sqlite' ? statement.replace(/\$\d+/g, '?') : statement, params);
}

/** The whole log, detail included, newest first. */
async function everyAuditEntry(api: CoffreClient): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: number | undefined; ; ) {
    const { entries } = await api.audit.list({ before, limit: 500, detail: '1' });
    all.push(...entries);
    if (entries.length < 500) return all;
    before = entries.at(-1)!.seq;
  }
}
