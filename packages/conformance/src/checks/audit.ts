// What is written down: every value opened, by the vault that opened it;
// every version stored, naming the vault's wrap of its key; no value without
// its entry; and a log changed behind coffre's back is caught.
import { createHash } from 'node:crypto';

import type { AuditEntryView, CoffreClient } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { appendOnlyLifted, entryFields, insertRow, LOG_REFUSAL, logRefuses, query } from './storage.ts';
import { DEV, PROJECT, valuesIn, type Canaries, type People } from './people.ts';

/** One read per returned value, committed by the vault under the response's operation. */
export async function revealAudited(deployment: Deployment, { admin, reader }: People, canaries: Canaries, purpose: 'reveal' | 'run'): Promise<string> {
  const path = purpose === 'reveal' ? `${DEV}/API_KEY` : DEV;
  const { operationId, values } = await reader.api.secrets.reveal(path);
  expect(typeof operationId === 'string' && operationId.length > 0, 'the read returned no operation id');
  const expected = purpose === 'reveal' ? { API_KEY: canaries[`${DEV}/API_KEY`] } : valuesIn(canaries, DEV);
  expect(JSON.stringify(Object.entries(values).sort()) === JSON.stringify(Object.entries(expected).sort()), 'the read returned different values', values);
  const entries = await everyAuditEntry(admin.api);
  const bundle = entries.filter((entry) => entry.operationId === operationId);
  const keys = bundle.map((entry) => entry.key).sort();
  expect(JSON.stringify(keys) === JSON.stringify(Object.keys(expected).sort()), 'the read is not logged once per value', bundle);
  expect(bundle.every((entry) => entry.author === 'vault' && entry.action === 'secret.read' && entry.decision === 'allow'),
    "the read's entries are not the vault's allowed reads", bundle);
  expect(bundle.every((entry) => entry.metadata.purpose === purpose && entry.requestId !== null && entry.requestId === bundle[0]!.requestId),
    'the reads do not name one request and its purpose', bundle);
  const { keys: listed } = await admin.api.secrets.list(DEV);
  for (const entry of bundle) {
    expect(entry.version === listed.find((key) => key.key === entry.key)?.version, `the entry for ${String(entry.key)} names another version`, entry);
  }
  await using(deployment.database(), async (sql) => {
    const rows = await query<{ author: string; action: string; decision: string; request_id: string | null; key: string; current_version: number; metadata: string }>(sql,
      `SELECT l.author, l.action, l.decision, l.request_id, l.metadata, s.key, s.current_version
       FROM audit_log l LEFT JOIN secrets s ON s.id = l.secret_id WHERE l.operation_id = $1`, [operationId]);
    expect(JSON.stringify(rows.map((row) => row.key).sort()) === JSON.stringify(Object.keys(expected).sort()), 'the committed read is not once per value', rows);
    for (const row of rows) {
      const metadata = JSON.parse(row.metadata) as { purpose: string; version: number };
      expect(row.author === 'vault' && row.action === 'secret.read' && row.decision === 'allow', 'the committed read is not the vault release', row);
      expect(row.request_id !== null && row.request_id === rows[0].request_id && metadata.purpose === purpose, 'the committed reads have different requests or purposes', rows);
      expect(metadata.version === row.current_version, 'the committed read names another version', row);
    }
  });
  return `${bundle.length} values, each read once by the vault for ${purpose}, under ${operationId}`;
}

/** Full verification must reach the stored head, not just some intact prefix. */
export async function verification(deployment: Deployment, { admin }: People): Promise<string> {
  const result = await admin.api.audit.verify();
  expect(result.ok, 'the full log does not verify', result);
  await using(deployment.database(), async (sql) => {
    const [head] = await sql.query<{ next_seq: string | number; head_hash: Uint8Array }>('SELECT next_seq, head_hash FROM audit_chain_head');
    const [last] = await sql.query<{ seq: string | number; hash: Uint8Array }>('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1');
    expect(head !== undefined && last !== undefined, 'the head or newest entry is missing');
    expect(BigInt(head.next_seq) === BigInt(last.seq) + 1n, 'the head does not name the newest entry');
    expect(Buffer.from(head.head_hash).equals(Buffer.from(last.hash)), 'the head has another hash');
    expect(result.through !== null && BigInt(result.through) === BigInt(last.seq), 'verification stopped before the head', { result, head: head.next_seq });
    expect(BigInt(result.entries) === BigInt(head.next_seq), 'verification did not count every entry', result);
  });
  return `${result.entries} entries verified through the head at ${result.through}`;
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
export async function writesAgree(deployment: Deployment): Promise<string> {
  return using(deployment.database(), async (sql) => {
    const entries = await sql.query<{
      seq: number | string; author: string; action: string; decision: string; actor: string; metadata: string;
      project_id: string | null; environment_id: string | null; secret_id: string | null;
      request_id: string | null; operation_id: string | null; related_seq: string | number | null;
    }>('SELECT * FROM audit_log ORDER BY seq');
    const bySeq = new Map(entries.map((entry) => [String(entry.seq), entry]));
    const writes = entries.filter((entry) => entry.author === 'app' && entry.decision === 'allow'
      && (entry.action === 'secret.write' || entry.action === 'secret.restore'));
    for (const entry of entries.filter((row) => row.author === 'app' && row.decision === 'allow')) {
      expect(entry.action !== 'secret.read', 'the app logged an allowed read of a value', entry);
    }
    for (const entry of writes) {
      const seal = entry.action === 'secret.write' ? 'key.wrap' : 'key.rewrap';
      const key = entry.related_seq === null ? undefined : bySeq.get(String(entry.related_seq));
      expect(key !== undefined && key.author === 'vault' && key.action === seal && key.decision === 'allow',
        `a ${entry.action} names no ${seal} of the vault's`, { entry, key });
      for (const field of ['actor', 'request_id', 'operation_id', 'project_id', 'environment_id'] as const) {
        expect(entry[field] === key[field], `the write and its seal have different ${field}`, { entry, key });
      }
      expect(entry.operation_id !== null && entry.request_id !== null, 'the committed write has no operation or request', entry);
      const metadata = JSON.parse(entry.metadata) as { version: number; key: string };
      const sealed = JSON.parse(key.metadata) as { secretId?: string; version: number; subject: string };
      expect((sealed.secretId ?? key.secret_id) === entry.secret_id && sealed.version === metadata.version
        && sealed.subject.split('/').at(-1) === metadata.key, 'the write names a seal of another secret or version', { entry, key });
    }
    const versions = await query<{ secret_id: string; version: number }>(sql,
      `SELECT v.secret_id, v.version FROM secret_versions v JOIN secrets s ON s.id = v.secret_id
       JOIN projects p ON p.id = s.project_id WHERE p.slug = $1`, [PROJECT]);
    expect(versions.length > 0, 'no stored versions were inspected');
    for (const version of versions) {
      const matching = writes.filter((entry) => entry.secret_id === version.secret_id
        && (JSON.parse(entry.metadata) as { version: number }).version === version.version);
      expect(matching.length === 1, 'a stored version has no unique app write entry', { version, matching });
    }
    return `${versions.length} stored versions, each with one app write naming the vault's seal in the same operation`;
  });
}

/**
 * No value leaves without its entry: with the audit log refusing writes (a
 * trigger, as a full disk or a lost connection would), the vault cannot log
 * the read, so a reveal fails and carries nothing.
 */
export async function noAuditNoValue(deployment: Deployment, { admin }: People, canaries: Canaries): Promise<string> {
  let status = 0;
  await using(deployment.database(), (sql) => logRefuses(sql, async () => {
    const before = deployment.output().split(LOG_REFUSAL).length;
    const response = await admin.browser.send('POST', '/api/reveals', { path: DEV });
    const text = await response.text();
    status = response.status;
    const body = JSON.parse(text) as { error: string; message: string; reason?: string };
    expect(status === 500 && body.error === 'internal_error' && body.reason === undefined,
      'the unlogged reveal did not fail as internal_error', { status, body });
    expect(body.message === 'something went wrong; see the server log', 'the audit failure exposed another reason', body);
    expect(!Object.values(canaries).some((value) => text.includes(value)), 'a reveal that could not be logged carried a value', text);
    // A lost vault gives the same public error; the trigger must be its cause.
    await until('the injected audit refusal in the processes\' output', async () => deployment.output().split(LOG_REFUSAL).length > before, 5);
  }, 'secret.read'));
  const after = await admin.api.secrets.reveal(DEV);
  expect(after.values.API_KEY === canaries[`${DEV}/API_KEY`], 'reveals did not come back once the log took writes again');
  return `a reveal the audit log would not take: ${status} internal_error, its injected cause in the log, and no value`;
}

/** A publicly chained entry still needs the vault's MAC. */
export async function forgedVaultEntry(deployment: Deployment, { admin }: People): Promise<string> {
  const verify = () => admin.api.audit.verify();
  expect((await verify()).ok, 'the log does not verify before the forged entry');
  await using(deployment.database(), async (sql) => {
    // An entry in the vault's name, chained after the last, with a MAC made up.
    const [head] = await sql.query<{ next_seq: number | string; head_hash: Uint8Array }>(
      'SELECT next_seq, head_hash FROM audit_chain_head',
    );
    const [writer] = await sql.query<{ key_id: string }>("SELECT key_id FROM audit_log WHERE author = 'vault' ORDER BY seq DESC LIMIT 1");
    expect(writer !== undefined, 'no vault key id to copy');
    const seq = BigInt(head.next_seq);
    const forged = {
      seq, author: 'vault', key_id: writer.key_id, occurred_at: Date.now(), actor: 'user:forger@conformance.example',
      action: 'secret.read', decision: 'allow', metadata: '{}',
    };
    const prevHash = Buffer.from(head.head_hash);
    const mac = Buffer.alloc(32, 0x41);
    const hash = createHash('sha256').update('coffre.audit.chain.v2').update(prevHash).update(entryFields(forged)).update(mac).digest();
    await insertRow(sql, 'audit_log', { ...forged, prev_hash: prevHash, mac, hash });
    await query(sql, 'UPDATE audit_chain_head SET next_seq = $1, head_hash = $2', [seq + 1n, hash]);
    let inserted;
    try {
      inserted = await verify();
    } finally {
      await appendOnlyLifted(sql, () => query(sql, 'DELETE FROM audit_log WHERE seq = $1', [seq]));
      await query(sql, 'UPDATE audit_chain_head SET next_seq = $1, head_hash = $2', [seq, prevHash]);
    }
    expect(!inserted.ok && inserted.author === 'vault' && inserted.failedAtSeq === Number(seq), "an entry in the vault's name, chained but not by the vault, verifies", inserted);
    const removed = await verify();
    expect(removed.ok, 'the log did not verify once the entry was gone', removed);
  });
  return 'a publicly chained vault entry with a made-up MAC was refused at its sequence';
}

/** Rewrite either author's entry and require a fault at that exact sequence. */
export async function rewrittenEntry(deployment: Deployment, { admin }: People, author: 'app' | 'vault'): Promise<string> {
  expect((await admin.api.audit.verify()).ok, 'the log does not verify before the rewrite');
  let seq = 0;
  await using(deployment.database(), (sql) => appendOnlyLifted(sql, async () => {
    const [row] = await query<{ seq: string | number; actor: string }>(sql,
      'SELECT seq, actor FROM audit_log WHERE author = $1 ORDER BY seq LIMIT 1', [author]);
    expect(row !== undefined, `no ${author} entry to rewrite`);
    seq = Number(row.seq);
    await query(sql, 'UPDATE audit_log SET actor = $1 WHERE seq = $2', ['user:nobody@conformance.example', row.seq]);
    try {
      const result = await admin.api.audit.verify();
      expect(!result.ok && result.failedAtSeq === Number(row.seq), 'a rewritten entry was not caught at its sequence', result);
    } finally {
      await query(sql, 'UPDATE audit_log SET actor = $1 WHERE seq = $2', [row.actor, row.seq]);
    }
  }));
  expect((await admin.api.audit.verify()).ok, 'the restored entry did not verify');
  return `entry ${seq}, the ${author}'s, rewritten: caught there, then put back`;
}

/** Remove an unreferenced entry, then put its exact bytes back. */
export async function missingEntry(deployment: Deployment, { admin }: People, position: 'middle' | 'first' | 'batch'): Promise<string> {
  expect((await admin.api.audit.verify()).ok, 'the log does not verify before deletion');
  let seq = 0;
  await using(deployment.database(), (sql) => appendOnlyLifted(sql, async () => {
    const [row] = await sql.query(`SELECT * FROM audit_log WHERE ${position !== 'middle' ? `seq = ${position === 'first' ? 0 : 1000}` :
      "seq > 0 AND action = 'audit.heartbeat' AND NOT EXISTS (SELECT 1 FROM audit_log linked WHERE linked.related_seq = audit_log.seq)"} ORDER BY seq LIMIT 1`);
    expect(row !== undefined, 'no unreferenced entry to delete');
    seq = Number(row.seq);
    const linked = await query(sql, 'SELECT * FROM audit_log WHERE related_seq = $1', [row.seq]);
    await query(sql, 'UPDATE audit_log SET related_seq = NULL WHERE related_seq = $1', [row.seq]);
    await query(sql, 'DELETE FROM audit_log WHERE seq = $1', [row.seq]);
    try {
      const result = await admin.api.audit.verify();
      expect(!result.ok, 'a log with an entry missing verifies', result);
      if (position !== 'middle') expect(result.reason.includes(`sequence gap: expected seq ${position === 'first' ? 0 : 1000}`), 'the sequence gap was not reported', result);
    } finally {
      await insertRow(sql, 'audit_log', row);
      for (const entry of linked) await query(sql, 'UPDATE audit_log SET related_seq = $1 WHERE seq = $2', [entry.related_seq, entry.seq]);
    }
  }));
  expect((await admin.api.audit.verify()).ok, 'the restored log did not verify');
  const which = { first: 'the first', batch: 'the first past a page of 1,000', middle: 'a heartbeat' }[position];
  return `entry ${seq}, ${which}, deleted: caught, then put back`;
}

/** Last: keep the head, delete its newest entries, and require verification to notice. */
export async function deletedTail(deployment: Deployment, { admin }: People): Promise<string> {
  const intact = await admin.api.audit.verify();
  expect(intact.ok && intact.checkpoint !== null, 'the log is not intact and checkpointed');
  const signed = intact.checkpoint.seq;
  await using(deployment.database(), (sql) => appendOnlyLifted(sql, async () => {
    await query(sql, 'UPDATE audit_log SET related_seq = NULL WHERE seq >= $1', [signed]);
    await query(sql, 'DELETE FROM audit_log WHERE seq >= $1', [signed]);
  }));
  const result = await admin.api.audit.verify();
  expect(!result.ok && result.author === 'app' && result.reason.includes('removed from the end'), 'the log verifies with its newest entries deleted', result);
  return 'the newest entries deleted, with the head left alone, were caught';
}

/** The whole log, detail included, newest first. */
export async function everyAuditEntry(api: CoffreClient): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: number | undefined; ; ) {
    const { entries } = await api.audit.list({ before, limit: 500, detail: '1' });
    all.push(...entries);
    if (entries.length < 500) return all;
    before = entries.at(-1)!.seq;
  }
}
