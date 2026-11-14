// What is written down: every value opened, by the vault that opened it;
// every version stored, naming the vault's wrap of its key; and no value
// without its entry; and each entry the audit page lists proven against the
// head the vault signed. 0.14's checks that a log changed behind coffre's
// back is caught asked `GET /audit/verification`, which 0.16 drops: the
// page's proofs and `coffre verify --full` read the log now
// (docs/design/0.16.md, "The server").
import type { AuditEntryView, CoffreClient } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { LOG_REFUSAL, logRefuses, query } from './storage.ts';
import { DEV, PROJECT, valuesIn, type Canaries, type People } from './people.ts';

/**
 * Every returned value read, committed by the vault under the response's
 * operation: one entry for the place, which lists each secret of a read of
 * several, and which a look for any one of them finds.
 */
export async function revealAudited(deployment: Deployment, { admin, reader }: People, canaries: Canaries, purpose: 'reveal' | 'run'): Promise<string> {
  const path = purpose === 'reveal' ? `${DEV}/API_KEY` : DEV;
  const { operationId, values } = await reader.api.secrets.reveal(path);
  expect(typeof operationId === 'string' && operationId.length > 0, 'the read returned no operation id');
  const expected = purpose === 'reveal' ? { API_KEY: canaries[`${DEV}/API_KEY`] } : valuesIn(canaries, DEV);
  expect(JSON.stringify(Object.entries(values).sort()) === JSON.stringify(Object.entries(expected).sort()), 'the read returned different values', values);
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
 * Each entry the audit page lists is held to the head the vault vouched for
 * in the page's own call (docs/design/0.16.md, "The log's head, when
 * asked"): every entry the head numbers proves against it, and only those
 * past it are not proven. What 0.14 asked of `GET /audit/verification`,
 * which 0.16 drops. The signer signs on its own, so a head stands within
 * its minute.
 */
export async function auditProven({ admin }: People): Promise<string> {
  type Page = Awaited<ReturnType<CoffreClient['audit']['list']>>;
  let page: Page | undefined;
  await until('a head the vault signed', async () => {
    page = await admin.api.audit.list({ detail: '1', limit: 200 });
    return page.head !== null;
  }, 90);
  const { entries, head } = page!;
  expect(head !== null && entries.length > 0, 'the audit page has no head or no entries', page);
  const failed = entries.filter((entry) => entry.proof === 'failed');
  expect(failed.length === 0, 'entries the head numbers do not prove against it', failed.slice(0, 5));
  // The signer signs the log in order, so the head numbers its first `size` entries.
  const misplaced = entries.filter((entry) => (entry.seq < head.size) !== (entry.proof === 'proven'));
  expect(misplaced.length === 0, 'an entry the head numbers is not proven, or one past it is', { head, misplaced: misplaced.slice(0, 5) });
  const proven = entries.filter((entry) => entry.proof === 'proven').length;
  expect(proven > 0, 'no entry on the page is proven', { head });
  return `${proven} of ${entries.length} entries proven against the head of ${head.size}, signed at ${head.signedAt}`;
}

/**
 * The audit page is sent with what its proofs found, rendered by the
 * server, never a verdict to come; and a log that proves is not shown as
 * one coffre could not check.
 */
export async function auditPageProofs({ admin }: People): Promise<string> {
  const page = await admin.browser.fetch('/audit');
  const html = await page.text();
  expect(page.status === 200 && !html.includes('Verifying'), 'the audit page was not sent with its proofs', { status: page.status });
  expect(!html.includes('could not check the log'), 'the audit page says coffre could not check the log', { status: page.status });
  return 'the audit page sent with its proofs, rendered by the server';
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

/** The whole log, detail included, newest first. */
export async function everyAuditEntry(api: CoffreClient): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: number | undefined; ; ) {
    const { entries, more } = await api.audit.list({ before, limit: 500, detail: '1' });
    all.push(...entries);
    if (!more || entries.length === 0) return all;
    before = entries.at(-1)!.seq;
  }
}
