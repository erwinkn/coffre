// What is written down: every value opened, by the vault that opened it;
// every version stored, naming the vault's wrap of its key; and no value
// without its entry; and each entry the audit page lists proven against the
// head the vault signed. 0.14's checks that a log changed behind coffre's
// back is caught asked `GET /audit/verification`, which 0.16 drops: the
// page's proofs and `coffre verify --full` read the log now
// (docs/design/0.16.md, "The server").
import { judgeProofs, type AuditEntryView, type CoffreClient, type ProofJudgment } from '@coffre/client';

import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until, PUBLISHED_SECONDS } from '../report.ts';
import { LOG_REFUSAL, logBodies, logRefuses, query, type Body } from './storage.ts';
import { canary, DEV, PROJECT, replaced, valuesIn, type Canaries, type People } from './people.ts';

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
  for (const [key, value] of Object.entries(fresh)) replaced(canaries, `${DEV}/${key}`, value);
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
  }, PUBLISHED_SECONDS).catch(() => undefined);
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
  }, PUBLISHED_SECONDS).catch((error: unknown) => {
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
  }, PUBLISHED_SECONDS);
  expect(status === 200 && !html.includes('Verifying'), 'the audit page was not sent with its proofs', { status });
  const proven = proofs.filter((proof) => proof === 'proven').length;
  expect(proven > 0, "the audit page's rows say no proof, or none proven", { status, proofs: proofs.slice(0, 10) });
  expect(!proofs.includes('failed'), 'the audit page shows an entry whose proof failed', { proofs: proofs.slice(0, 10) });
  expect(!html.includes('could not check the log'), 'the audit page says coffre could not check the log', { status });
  return `the audit page sent with its proofs, rendered by the server: ${proven} of ${proofs.length} rows proven`;
}

/** A row of `log` as the database holds it: its bigints as text, put back as they were. */
type LogRow = { seq: string; kept: boolean; leaf: string; body: string };

/**
 * The newest signed entry of a tree cut out of the log, by the database's
 * owner (docs/design/0.16.md, "What the minute's run checks of the log"):
 * the signer's next check, within its minute, says `cut` of that tree in
 * its alert, in the processes' output, and the audit page proves the
 * entry nowhere, the gap a hole in its stretch. Put back, the page proves
 * it again, and the signer lets the finding go: the same cut is news to a
 * later check. The change cut first, then the use, whose finding says the
 * check after the change was put back has run; then the change again. An
 * entry cut further back, or the newest once another is signed after it,
 * is the re-check's, which reads the log a day after its last walk (D222):
 * not within a run (docs/conformance.md).
 */
export async function logCut(deployment: Deployment, { admin }: People): Promise<string> {
  // Each alert the signer sent, in order: one per check that found something, its findings one per line.
  const alerts = () => deployment.output().split("coffre's signer reports (").slice(1);
  const trees = ['kept', 'aging'] as const;
  const out: LogRow[] = [];
  const seqs = new Set<number>();
  await using(deployment.database(), async (sql) => {
    const cut = async (kept: boolean): Promise<LogRow> => {
      // Nothing waits: an entry signed after the cut would end its tree again, and leave the cut to the walk.
      await until('nothing waiting to be signed', async () => (await query(sql, 'SELECT 1 FROM log_pending LIMIT 1')).length === 0, PUBLISHED_SECONDS);
      const tree = kept ? 'kept' : 'aging';
      const before = alerts().length;
      const [row] = await query<LogRow>(sql, 'DELETE FROM log WHERE kept = $1 AND leaf = (SELECT max(leaf) FROM log WHERE kept = $1) RETURNING seq::text, kept, leaf::text, body', [kept]);
      expect(row !== undefined, `the log has no ${tree} entry to cut`);
      out.push(row);
      let alert: string | undefined;
      await until(`the signer's alert naming - cut ${tree}:`, async () => (alert = alerts().slice(before).find((text) => text.includes(`- cut ${tree}:`))) !== undefined, PUBLISHED_SECONDS);
      // Found afresh: the check that names it names no cut put back before, so a finding let go is not one said again.
      const again = trees.filter((other) => other !== tree && alert!.includes(`- cut ${other}:`));
      expect(again.length === 0, 'the signer names again a cut put back before', { tree, again, alert });
      // The page's stretch lacks it, by its tree's count, and lists it nowhere as proven.
      const page = await admin.api.audit.list({ detail: '1', limit: 200 });
      const seq = Number(row.seq);
      seqs.add(seq);
      const hole = page.holes?.some((gap) => (gap.above === null || gap.above > seq) && (gap.below === null || gap.below < seq) && gap[tree] > 0);
      expect(page.entries.every((entry) => entry.seq !== seq || entry.proof !== 'proven'), 'the audit page proves an entry cut out of the log', { seq });
      expect(hole === true, "the audit page's stretch does not lack the entry cut out of the log", { seq, holes: page.holes });
      return row;
    };
    const putBack = async (row: LogRow) => {
      await query(sql, 'INSERT INTO log (seq, kept, leaf, body) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING', [row.seq, row.kept, row.leaf, row.body]);
      out.splice(out.indexOf(row), 1);
    };
    try {
      await putBack(await cut(true));
      await putBack(await cut(false));
      await putBack(await cut(true));
    } finally {
      for (const row of [...out]) await putBack(row);
    }
  });
  // Every entry back, and proven against the head again.
  let judged: ProofJudgment | undefined;
  let listed: AuditEntryView[] = [];
  await until('a page past the race between its head and its log', async () => {
    const page = await admin.api.audit.list({ detail: '1', limit: 200 });
    [judged, listed] = [judgeProofs(page), page.entries];
    return !judged.racing;
  }, PUBLISHED_SECONDS).catch((error: unknown) => {
    if (judged === undefined) throw error;
  });
  const { failed, misplaced, missing } = judged!;
  const unproven = [...seqs].filter((seq) => !listed.some((entry) => entry.seq === seq && entry.proof === 'proven'));
  expect(unproven.length === 0 && failed.length === 0 && misplaced.length === 0 && missing !== null && missing.length === 0, 'the entries put back are not proven again', { unproven, failed: failed.slice(0, 5), misplaced: misplaced.slice(0, 5), missing });
  return "the newest change and use cut out of the log, each named in the signer's alert and proven nowhere on the audit page; put back, proven again, and a change cut again named again";
}

/**
 * Every version stored is the vault's write: one entry of the log names
 * it, its secret and its number, among the keys the change wrote: a
 * `secret.write` or `secret.loosen`, or the `environment.create` of a fork
 * that copied it, naming who wrote it and the request. 0.14's app and vault each logged their
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
      // Each is someone's, through one request the server passed the vault (docs/design/0.16.md, "The server").
      const named = (field: unknown) => typeof field === 'string' && field !== '';
      expect(named(body.actor) && named(body.request), `a committed ${body.action} names no actor or no request`, body);
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
    return `${versions.length} stored versions, each written by one entry of the vault's, naming its actor and request`;
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
  // Not a place's value for the checks after (it is gone at the end), but one for the scans to look for.
  const value = canary();
  canaries[`unlogged ${DEV}/${UNLOGGED}`] = value;
  await admin.api.secrets.set(DEV, { [UNLOGGED]: value });
  await using(deployment.database(), (sql) => logRefuses(sql, async () => {
    const before = deployment.output().split(LOG_REFUSAL).length;
    const response = await admin.browser.send('POST', '/api/reveals', { path: DEV });
    const text = await response.text();
    status = response.status;
    const body = JSON.parse(text) as { error: string; message: string; reason?: string };
    expect(status === 500 && body.error === 'internal_error' && body.reason === undefined,
      'the unlogged reveal did not fail as internal_error', { status, body });
    expect(body.message === 'something went wrong; see the server log', 'the audit failure exposed another reason', body);
    expect(!text.includes(value), 'a reveal that could not be logged carried the value it could not log', text);
    expect(!Object.values(canaries).some((known) => text.includes(known)), 'a reveal that could not be logged carried a value', text);
    // A lost vault gives the same public error; the trigger must be its cause.
    await until('the injected audit refusal in the processes\' output', async () => deployment.output().split(LOG_REFUSAL).length > before, 5);
  }, 'secret.read'));
  const after = await admin.api.secrets.reveal(DEV);
  expect(after.values.API_KEY === canaries[`${DEV}/API_KEY`] && after.values[UNLOGGED] === value, 'reveals did not come back once the log took writes again');
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
