// What is written down: every value opened, by the vault that opened it;
// every version stored, naming the vault's wrap of its key; no value without
// its entry; and a log changed behind coffre's back is caught.
import { createHash, randomBytes } from 'node:crypto';

import type { AuditEntryView, CoffreClient } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { appendOnlyLifted, entryFields, insertRow, LOG_REFUSAL, logRefuses, query } from './storage.ts';
import { DEV, PROJECT, valuesIn, type Canaries, type People } from './people.ts';

/**
 * Every returned value read, committed by the vault under the response's
 * operation: one entry for the place, which lists each secret of a read of
 * several, and which a look for any one of them finds. With 0.15's log, each
 * value read is its use (`usesAudited`).
 */
export async function revealAudited(deployment: Deployment, { admin, reader }: People, canaries: Canaries, purpose: 'reveal' | 'run'): Promise<string> {
  const path = purpose === 'reveal' ? `${DEV}/API_KEY` : DEV;
  const asked = Date.now();
  const { operationId, values } = await reader.api.secrets.reveal(path);
  expect(typeof operationId === 'string' && operationId.length > 0, 'the read returned no operation id');
  const expected = purpose === 'reveal' ? { API_KEY: canaries[`${DEV}/API_KEY`] } : valuesIn(canaries, DEV);
  expect(JSON.stringify(Object.entries(values).sort()) === JSON.stringify(Object.entries(expected).sort()), 'the read returned different values', values);
  // With 0.15's log, each value read is its use, listed once the log has sealed it and the vault's projector has gone
  // that far (T166).
  if ((await admin.api.audit.verifyTrees()).kept) return usesAudited(deployment, { admin, reader }, Object.keys(expected), purpose, asked);
  const entries = await everyAuditEntry(admin.api);
  const bundle = entries.filter((entry) => entry.operationId === operationId);
  expect(bundle.length === 1, 'the read of one place is not logged as one entry', bundle);
  const [entry] = bundle as [AuditEntryView];
  const read = entry.secrets ?? [{ key: entry.key, version: entry.version }];
  expect(JSON.stringify(read.map((secret) => secret.key).sort()) === JSON.stringify(Object.keys(expected).sort()), 'the read does not list each value once', entry);
  expect(entry.author === 'vault' && entry.action === 'secret.read' && entry.decision === 'allow', "the read's entry is not the vault's allowed read", entry);
  expect(entry.metadata.purpose === purpose && entry.requestId !== null, 'the read does not name its request and its purpose', entry);
  const { keys: listed } = await admin.api.secrets.list(DEV);
  for (const secret of read) {
    expect(secret.version === listed.find((key) => key.key === secret.key)?.version, `the entry for ${String(secret.key)} names another version`, entry);
    // Who read this key: the entry of the place's read is among the key's own.
    const own = await admin.api.audit.list({ path: `${DEV}/${String(secret.key)}`, limit: 200 });
    expect(own.entries.some((found) => found.seq === entry.seq), `the read is not in ${String(secret.key)}'s log`, own.entries.slice(0, 5));
  }
  await using(deployment.database(), async (sql) => {
    const rows = await query<{ author: string; action: string; decision: string; request_id: string | null; secret_id: string | null; metadata: string }>(sql,
      'SELECT author, action, decision, request_id, secret_id, metadata FROM audit_log WHERE operation_id = $1', [operationId]);
    expect(rows.length === 1, 'the committed read is not one entry', rows);
    const [row] = rows as [(typeof rows)[number]];
    expect(row.author === 'vault' && row.action === 'secret.read' && row.decision === 'allow' && row.request_id !== null, 'the committed read is not the vault release', row);
    const metadata = JSON.parse(row.metadata) as { purpose: string; version?: number; secrets?: { secretId: string; version: number }[] };
    const committed = metadata.secrets ?? [{ secretId: row.secret_id!, version: metadata.version! }];
    expect(metadata.purpose === purpose && committed.length === Object.keys(expected).length, 'the committed read does not name its purpose and each secret', row);
    for (const secret of committed) {
      const [current] = await query<{ current_version: number }>(sql, 'SELECT current_version FROM secrets WHERE id = $1', [secret.secretId]);
      expect(current?.current_version === secret.version, 'the committed read names another version', row);
    }
  });
  return `${read.length} values read by the vault for ${purpose}, in one entry under ${operationId}`;
}

/**
 * How long before a read 0.15's log may hold the use it rode on: a repeat
 * within a minute rides on the first one's entry (a cover, R53), and the
 * deployment's clock may stand a little off the harness's.
 */
const COVERED_MS = 90_000;

/** How long a read may wait to be listed: the checkpointer's tick seals it, then the projector's lists it, each a tick or so. */
const LISTED_WITHIN_MS = 20_000;

/**
 * Whether `probe` holds within `LISTED_WITHIN_MS`, asked every quarter of a
 * second: what a check of 0.15's reads waits for, as a read is listed once
 * the log has sealed it and the vault's projector has gone that far (T166).
 */
export async function listed(probe: () => Promise<boolean>): Promise<boolean> {
  for (const deadline = Date.now() + LISTED_WITHIN_MS; ;) {
    if (await probe()) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

/**
 * Every value read, with 0.15's log, where a read is a use of each key,
 * which names no operation (R53, T166): the reader's newest read of each,
 * for the purpose, made by this read or by one within the minute before it
 * that this rode on, listed within `LISTED_WITHIN_MS`, the vault's and
 * vouched for, of the version the key holds, in the key's own log, and the
 * use the vault wrote, as its projector listed it.
 */
async function usesAudited(
  deployment: Deployment, { admin, reader }: Pick<People, 'admin' | 'reader'>, keys: string[], purpose: 'reveal' | 'run', asked: number,
): Promise<string> {
  const { keys: held } = await admin.api.secrets.list(DEV);
  // Of the key at dev itself: not a read of another place's key of that name, as through dev's reference into prod.
  const readOf = (entries: AuditEntryView[], key: string) => entries.find((found) => found.log === '0.15' && found.action === 'secret.read' && found.actorId === reader.email && found.key === key
    && `${found.project}/${found.environment}` === DEV && found.metadata.via === undefined && found.metadata.purpose === purpose && Date.parse(found.occurredAt) >= asked - COVERED_MS);
  let entries = await everyAuditEntry(admin.api);
  await listed(async () => keys.every((key) => readOf(entries, key) !== undefined) || ((entries = await everyAuditEntry(admin.api)), false));
  const read = keys.map((key) => {
    const entry = readOf(entries, key);
    expect(entry !== undefined, `the read of ${key} is not listed in 0.15's log within ${LISTED_WITHIN_MS / 1000} s`, entries.slice(0, 5));
    expect(entry.author === 'vault' && entry.decision === 'allow' && entry.forged !== true, `the read of ${key} is not the vault's allowed read`, entry);
    expect(entry.version === held.find((found) => found.key === key)?.version, `the entry for ${key} names another version`, entry);
    return entry;
  });
  for (const entry of read) {
    // Its whole log: the read may ride on a cover from the minute before, past a page of the key's newer reads.
    const own = await everyAuditEntry(admin.api, `${DEV}/${String(entry.key)}`);
    expect(own.some((found) => found.log === '0.15' && found.seq === entry.seq), `the read is not in ${String(entry.key)}'s log`, { read: entry, newest: own.slice(0, 5) });
  }
  await using(deployment.database(), async (sql) => {
    for (const entry of read) {
      const rows = await query<{ secret: string }>(sql, 'SELECT secret FROM log_uses WHERE number = $1', [entry.seq]);
      expect(rows.length === 1 && String(rows[0]!.secret) === entry.metadata.secretId, 'the read is not the use the vault wrote', { entry, rows });
      const projected = await query<{ secret: string; principal: string }>(sql, 'SELECT secret, principal FROM log_reads WHERE number = $1', [entry.seq]);
      expect(projected.length === 1 && String(projected[0]!.secret) === entry.metadata.secretId && projected[0]!.principal === `user:${reader.email}`, "the read is not the use as the vault's projector listed it", { entry, projected });
    }
  });
  return `${read.length} values read by the vault for ${purpose}, each its use in 0.15's log`;
}

/**
 * Verification must reach the stored head, not just some intact prefix:
 * the page's, from the newest checkpoint, and the walk from the first
 * entry, a stretch a request, which ends where it does. And the audit page
 * is sent with its verdict, rendered by the server, never a badge to come.
 */
export async function verification(deployment: Deployment, { admin }: People): Promise<string> {
  const anchored = await admin.api.audit.verify();
  expect(anchored.ok && anchored.remaining === 0, 'the log does not verify from its newest checkpoint', anchored);
  const result = await admin.api.audit.verifyWhole();
  expect(result.ok && result.remaining === 0, 'the full log does not verify to its end', result);
  expect(result.through !== null && anchored.through !== null && result.through >= anchored.through, 'the walk from the first entry stopped short', { anchored, result });
  await using(deployment.database(), async (sql) => {
    const [head] = await sql.query<{ next_seq: string | number; head_hash: Uint8Array }>('SELECT next_seq, head_hash FROM audit_chain_head');
    const [last] = await sql.query<{ seq: string | number; hash: Uint8Array }>('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1');
    expect(head !== undefined && last !== undefined, 'the head or newest entry is missing');
    expect(BigInt(head.next_seq) === BigInt(last.seq) + 1n, 'the head does not name the newest entry');
    expect(Buffer.from(head.head_hash).equals(Buffer.from(last.hash)), 'the head has another hash');
    expect(result.through !== null && BigInt(result.through) === BigInt(last.seq), 'verification stopped before the head', { result, head: head.next_seq });
    expect(BigInt(result.entries) === BigInt(head.next_seq), 'verification did not count every entry', result);
  });
  // 0.15's log, where the deployment keeps it (plan PR 8): its newest checkpoint and every entry since, as the audit
  // page checks it. A deployment of 0.14's log alone has none (`kept` false).
  const trees = await admin.api.audit.verifyTrees();
  expect(!trees.kept || trees.problems.length === 0, "0.15's log does not verify from its newest checkpoint", trees);
  // Not checked to its head, as 0.14's checkpoints catching up above: a checkpointer behind, no break of the log, and
  // no pass either (review r4 of W240).
  expect(!trees.kept || !trees.capped, "0.15's log is not checked to its head: more entries wait above its newest checkpoint than a check reads, the checkpointer behind", trees);
  // And the reads the pages list, held to the uses it sealed, from the first, as `coffre verify log` holds them (T166).
  const reads = await admin.api.audit.verifyReads();
  expect(!reads.kept || reads.ok, "the reads listed are not the uses 0.15's log sealed", reads);
  const page = await admin.browser.fetch('/audit');
  const html = await page.text();
  expect(page.status === 200 && html.includes('chain-seal') && !html.includes('Verifying'), 'the audit page was not sent with its verification result', { status: page.status });
  const sealed = !trees.kept ? '' : trees.checkpoint === null ? "; 0.15's log, nothing sealed yet" : `; 0.15's log from its checkpoint up to ${trees.checkpoint.upto}`;
  return `${result.entries} entries verified through the head at ${result.through}${sealed}, and the audit page sent with its result`;
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
 * it was sealed with, `key.wrap` for a write and `key.rewrap` for a restore,
 * a mark and a loosening:
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
      && (entry.action === 'secret.write' || entry.action === 'secret.restore' || entry.action === 'secret.loosen'));
    for (const entry of entries.filter((row) => row.author === 'app' && row.decision === 'allow')) {
      expect(entry.action !== 'secret.read', 'the app logged an allowed read of a value', entry);
    }
    for (const entry of writes) {
      // A write of a new value wraps a new key; a restore, a mark (which says the version it `kept`) and a loosening rewrap one.
      const seal = entry.action === 'secret.write' && JSON.parse(entry.metadata).kept === undefined ? 'key.wrap' : 'key.rewrap';
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
 * No value leaves without its entry: with 0.15's log refusing uses (a
 * trigger, as a full disk or a lost connection would), the vault's use,
 * which writes its row in the statement that decides it, fails, so a
 * reveal fails and carries nothing. Of a key no one has read yet: a key's
 * use within a minute of the last is that one's, its isolate's cover, and
 * writes nothing again.
 */
export async function noAuditNoValue(deployment: Deployment, { admin }: People, canaries: Canaries): Promise<string> {
  let status = 0;
  const key = `UNLOGGED_${randomBytes(4).toString('hex').toUpperCase()}`;
  const value = `coffre-canary-${randomBytes(10).toString('hex')}`;
  await admin.api.secrets.set(DEV, { [key]: value });
  await using(deployment.database(), (sql) => logRefuses(sql, async () => {
    const before = deployment.output().split(LOG_REFUSAL).length;
    const response = await admin.browser.send('POST', '/api/reveals', { path: `${DEV}/${key}` });
    const text = await response.text();
    status = response.status;
    const body = JSON.parse(text) as { error: string; message: string; reason?: string };
    expect(status === 500 && body.error === 'internal_error' && body.reason === undefined,
      'the unlogged reveal did not fail as internal_error', { status, body });
    expect(body.message === 'something went wrong; see the server log', 'the audit failure exposed another reason', body);
    expect(![value, ...Object.values(canaries)].some((canary) => text.includes(canary)), 'a reveal that could not be logged carried a value', text);
    // A lost vault gives the same public error; the trigger must be its cause.
    await until('the injected audit refusal in the processes\' output', async () => deployment.output().split(LOG_REFUSAL).length > before, 5);
  }, undefined, 'log_uses'));
  const after = await admin.api.secrets.reveal(`${DEV}/${key}`);
  expect(after.values[key] === value, 'reveals did not come back once the log took writes again');
  expect((await admin.api.secrets.reveal(DEV)).values.API_KEY === canaries[`${DEV}/API_KEY`], 'reveals did not come back once the log took writes again');
  return `a reveal the log would not take: ${status} internal_error, its injected cause in the log, and no value`;
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

/**
 * Rewrite either author's first entry in place and require a fault at that
 * exact sequence: from the walk from the first entry, since the page's
 * check goes on from the newest checkpoint and reads nothing before it.
 */
export async function rewrittenEntry(deployment: Deployment, { admin }: People, author: 'app' | 'vault'): Promise<string> {
  expect((await admin.api.audit.verifyWhole()).ok, 'the log does not verify before the rewrite');
  let seq = 0;
  await using(deployment.database(), (sql) => appendOnlyLifted(sql, async () => {
    const [row] = await query<{ seq: string | number; actor: string }>(sql,
      'SELECT seq, actor FROM audit_log WHERE author = $1 ORDER BY seq LIMIT 1', [author]);
    expect(row !== undefined, `no ${author} entry to rewrite`);
    seq = Number(row.seq);
    await query(sql, 'UPDATE audit_log SET actor = $1 WHERE seq = $2', ['user:nobody@conformance.example', row.seq]);
    try {
      const result = await admin.api.audit.verifyWhole();
      expect(!result.ok && result.failedAtSeq === Number(row.seq), 'a rewritten entry was not caught at its sequence', result);
    } finally {
      await query(sql, 'UPDATE audit_log SET actor = $1 WHERE seq = $2', [row.actor, row.seq]);
    }
  }));
  expect((await admin.api.audit.verifyWhole()).ok, 'the restored entry did not verify');
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

/** The whole log, detail included, newest first: 0.14's entries, and the sign-ins 0.15's records. */
export async function everyAuditEntry(api: CoffreClient, path?: string): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: string | undefined; ; ) {
    const { entries, next } = await api.audit.list({ before, limit: 500, detail: '1', sealed: '1', ...(path === undefined ? {} : { path }) });
    all.push(...entries);
    if (next === null) return all;
    before = next;
  }
}
