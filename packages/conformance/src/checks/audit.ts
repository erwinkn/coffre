// What is written down: every value opened, by the vault that opened it;
// every version stored, naming the vault's wrap of its key; and no value
// without its entry; and each entry the audit page lists proven against the
// head the vault signed. 0.14's checks that a log changed behind coffre's
// back is caught asked `GET /audit/verification`, which 0.16 drops: the
// page's proofs and `coffre verify --full` read the log now
// (docs/design/0.16.md, "The server").
import { randomUUID } from 'node:crypto';

import { judgeProofs, type AuditEntryView, type CoffreClient, type ProofJudgment } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { LOG_REFUSAL, logBodies, logRefuses, query, type Body } from './storage.ts';
import { canary, DEV, PROJECT, valuesIn, type Canaries, type People } from './people.ts';

/**
 * Every returned value read, committed by the vault under the response's
 * operation: one entry for the place, which lists each secret of a read of
 * several, and which a look for any one of them finds.
 */
export async function revealAudited(deployment: Deployment, { admin, reader }: People, canaries: Canaries, purpose: 'reveal' | 'run'): Promise<string> {
  const path = purpose === 'reveal' ? `${DEV}/API_KEY` : DEV;
  // 0.16 logs the first use of a version in a minute, by credential and purpose (docs/design/0.16.md, "What it
  // promises"): a version the reader read a moment ago gets no new entry. Each value read is written afresh first.
  const fresh = Object.fromEntries(Object.keys(purpose === 'reveal' ? { API_KEY: '' } : valuesIn(canaries, DEV)).map((key) => [key, canary()]));
  await admin.api.secrets.set(DEV, fresh);
  for (const [key, value] of Object.entries(fresh)) canaries[`${DEV}/${key}`] = value;
  const { operationId, values } = await reader.api.secrets.reveal(path);
  expect(typeof operationId === 'string' && operationId.length > 0, 'the read returned no operation id');
  const expected = purpose === 'reveal' ? { API_KEY: canaries[`${DEV}/API_KEY`] } : valuesIn(canaries, DEV);
  expect(JSON.stringify(Object.entries(values).sort()) === JSON.stringify(Object.entries(expected).sort()), 'the read returned different values', values);
  // 0.16 answers a change or a read with its request's id as its operation, and its entry names that request. The page
  // lists what the signer has published, within its minute.
  let bundle: AuditEntryView[] = [];
  await until('the read on the audit page', async () => {
    bundle = (await everyAuditEntry(admin.api)).filter((entry) => entry.requestId === operationId);
    return bundle.length > 0;
  }, 90).catch(() => undefined);
  expect(bundle.length === 1, 'the read of one place is not logged as one entry', bundle);
  const [entry] = bundle as [AuditEntryView];
  const read = entry.secrets ?? [{ key: entry.key, version: entry.version }];
  expect(JSON.stringify(read.map((secret) => secret.key).sort()) === JSON.stringify(Object.keys(expected).sort()), 'the read does not list each value once', entry);
  expect(entry.author === 'vault' && entry.action === 'secret.read' && entry.decision === 'allow', "the read's entry is not the vault's allowed read", entry);
  expect(entry.metadata.purpose === purpose, 'the read does not name its purpose', entry);
  const { keys: listed } = await admin.api.secrets.list(DEV);
  for (const secret of read) {
    expect(secret.version === listed.find((key) => key.key === secret.key)?.version, `the entry for ${String(secret.key)} names another version`, entry);
    // Who read this key: the entry of the place's read is among the key's own.
    const own = await admin.api.audit.list({ path: `${DEV}/${String(secret.key)}`, limit: 200 });
    expect(own.entries.some((found) => found.seq === entry.seq), `the read is not in ${String(secret.key)}'s log`, own.entries.slice(0, 5));
  }
  await using(deployment.database(), async (sql) => {
    const rows = (await logBodies(sql)).filter((body) => body.request === operationId);
    expect(rows.length === 1, 'the committed read is not one entry', rows);
    const [row] = rows as [Body];
    const committed = (row.detail.keys ?? []) as { secret: string; version: number }[];
    expect(row.action === 'secret.read' && row.detail.refused === undefined, 'the committed read is not the vault release', row);
    expect(row.detail.purpose === purpose && committed.length === Object.keys(expected).length, 'the committed read does not name its purpose and each secret', row);
    for (const secret of committed) {
      const [current] = await query<{ current_version: number }>(sql, 'SELECT current_version FROM secrets WHERE id = $1', [secret.secret]);
      expect(current?.current_version === secret.version, 'the committed read names another version', row);
    }
  });
  return `${read.length} values read by the vault for ${purpose}, in one entry under ${operationId}`;
}

/**
 * Each entry the audit page lists is held to the head the vault vouched for
 * in the page's own call (docs/design/0.16.md, "The log's head, when
 * asked"): every entry the head numbers proves against it, only those
 * past it are not proven, and the page's stretch lacks none of either tree.
 * What 0.14 asked of `GET /audit/verification`, which 0.16 drops; judged as
 * `coffre verify instance` judges it (`judgeProofs`). The signer signs on
 * its own, so a head stands within its minute.
 */
export async function auditProven({ admin }: People): Promise<string> {
  let judged: ProofJudgment | undefined;
  // A batch the signer publishes, or a pruning committed, between the vault
  // reading its head and the app reading the log can leave a page honestly
  // racing (`judgeProofs`): asked again until it is not, and judged as it
  // last read if it still is.
  await until('a page past the race between its head and its log', async () => {
    judged = judgeProofs(await admin.api.audit.list({ detail: '1', limit: 200 }));
    return !judged.racing;
  }, 90).catch((error: unknown) => {
    if (judged === undefined) throw error;
  });
  const { head, proven, failed, misplaced, missing } = judged!;
  expect(head !== null, 'the audit page has no head');
  expect(failed.length === 0, 'entries the head numbers do not prove against it', failed.slice(0, 5));
  expect(misplaced.length === 0, 'an entry the head numbers is not proven, or one past it is', { head, misplaced: misplaced.slice(0, 5) });
  expect(missing !== null && missing.length === 0, "the page's stretch of the log lacks entries, or the page cannot say", { head, missing: missing?.slice(0, 5) });
  expect(proven > 0, 'no entry on the page is proven', { head });
  return `${proven} entries proven against the head of ${head.size}, signed at ${head.signedAt}, and none missing`;
}

/**
 * The audit page is sent with what its proofs found, rendered by the
 * server, never a verdict to come: each entry's row says its proof in
 * `data-proof` (`proven`, `unproven` or `failed`), which the page's port
 * writes; at least one row proves, none fails, and a log that proves is
 * not shown as one coffre could not check.
 */
export async function auditPageProofs({ admin }: People): Promise<string> {
  let status = 0;
  let html = '';
  let proofs: string[] = [];
  // The race `auditProven` waits out, in the page's own call: a batch signed
  // between its head and its rows can leave every row shown honestly
  // unproven. So a page of rows none of which proves is asked again; an
  // empty one, a failed proof or an error is final.
  await until('an audit page with a row its head numbers', async () => {
    const page = await admin.browser.fetch('/audit');
    status = page.status;
    html = await page.text();
    proofs = [...html.matchAll(/data-proof="([a-z]+)"/g)].map((match) => match[1]);
    return status !== 200 || proofs.length === 0 || proofs.some((proof) => proof !== 'unproven');
  }, 90);
  expect(status === 200 && !html.includes('Verifying'), 'the audit page was not sent with its proofs', { status });
  const proven = proofs.filter((proof) => proof === 'proven').length;
  expect(proven > 0, "the audit page's rows say no proof, or none proven", { status, proofs: proofs.slice(0, 10) });
  expect(!proofs.includes('failed'), 'the audit page shows an entry whose proof failed', { proofs: proofs.slice(0, 10) });
  expect(!html.includes('could not check the log'), 'the audit page says coffre could not check the log', { status });
  return `the audit page sent with its proofs, rendered by the server: ${proven} of ${proofs.length} rows proven`;
}

/**
 * Every version stored is the vault's write: one entry of the log names
 * it, its secret and its number, among the keys the change wrote: a
 * `secret.write` or `secret.loosen`, or the `environment.create` of a fork
 * that copied it. 0.14's app and vault each logged their
 * half of a write, the app's naming the vault's seal of its key; in 0.16
 * the vault writes the version and its one entry together, and the app
 * writes nothing (docs/design/0.16.md, "Four rules").
 */
const WRITES = new Set(['secret.write', 'secret.loosen', 'environment.create']);

export async function writesAgree(deployment: Deployment): Promise<string> {
  return using(deployment.database(), async (sql) => {
    const written = new Map<string, number>();
    for (const body of await logBodies(sql)) {
      if (!WRITES.has(body.action) || body.detail.refused !== undefined) continue;
      for (const line of (body.detail.keys ?? []) as { secret?: string; version?: number }[]) {
        if (line.version === undefined) continue;
        const name = `${line.secret} ${line.version}`;
        written.set(name, (written.get(name) ?? 0) + 1);
      }
    }
    const versions = await query<{ secret_id: string; version: number }>(sql,
      `SELECT v.secret_id, v.version FROM secret_versions v JOIN secrets s ON s.id = v.secret_id
       JOIN projects p ON p.id = s.project_id WHERE p.slug = $1`, [PROJECT]);
    expect(versions.length > 0, 'no stored versions were inspected');
    for (const version of versions) {
      const entries = written.get(`${version.secret_id} ${version.version}`) ?? 0;
      expect(entries === 1, 'a stored version has no unique write entry', { version, entries });
    }
    return `${versions.length} stored versions, each written by one entry of the vault's`;
  });
}

/**
 * No value leaves without its entry: with the audit log refusing writes (a
 * trigger, as a full disk or a lost connection would), the vault cannot log
 * the read, so a reveal fails and carries nothing. The vault logs a
 * credential's read of a version once a minute (docs/design/0.16.md, "What
 * it promises"), so the reveal asks for a key written just before, which no
 * entry has said yet; it is archived after.
 */
const UNLOGGED = 'NO_AUDIT_NO_VALUE';

export async function noAuditNoValue(deployment: Deployment, { admin }: People, canaries: Canaries): Promise<string> {
  let status = 0;
  await admin.api.secrets.set(DEV, { [UNLOGGED]: `unlogged-${randomUUID()}` });
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
  expect(after.values.API_KEY === canaries[`${DEV}/API_KEY`] && after.values[UNLOGGED] !== undefined, 'reveals did not come back once the log took writes again');
  await admin.api.secrets.set(DEV, { [UNLOGGED]: null });
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
