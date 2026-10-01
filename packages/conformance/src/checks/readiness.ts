// Readiness needs both halves of the Cron's work: a recent heartbeat, and a
// checkpoint the vault signed over it. Either missing turns /readyz red.
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { appendOnlyLifted, insertRow, logRefuses, query, transaction } from './storage.ts';
import type { People } from './people.ts';

async function red(deployment: Deployment): Promise<void> {
  await until('readiness red', async () => (await fetch(`${deployment.origin}/readyz`)).status === 503, 10);
  const body = await (await fetch(`${deployment.origin}/readyz`)).json() as { ok: boolean; checkpointed: boolean };
  expect(body.ok === false && body.checkpointed === false, 'readiness did not report the missing checkpoint', body);
}

export async function refusedCheckpoint(deployment: Deployment): Promise<string> {
  expect((await fetch(`${deployment.origin}/readyz`)).ok, 'readiness is not green before the checkpoint refusal');
  await using(deployment.database(), (sql) => logRefuses(sql, async () => {
    const [before] = await sql.query<{ seq: number | string }>("SELECT seq FROM audit_log WHERE action = 'audit.heartbeat' ORDER BY seq DESC LIMIT 1");
    await deployment.scheduled({ allowFailure: true });
    await until('the new heartbeat', async () => {
      const [after] = await sql.query<{ seq: number | string }>("SELECT seq FROM audit_log WHERE action = 'audit.heartbeat' ORDER BY seq DESC LIMIT 1");
      return BigInt(after.seq) > BigInt(before.seq);
    }, 10);
    await red(deployment);
  }, 'audit.checkpoint'));
  await deployment.scheduled();
  await until('readiness recovered', async () => (await fetch(`${deployment.origin}/readyz`)).ok, 20);
  return 'a committed heartbeat with a refused checkpoint turns readiness red, then recovers';
}

export async function missingCheckpoint(deployment: Deployment): Promise<string> {
  expect((await fetch(`${deployment.origin}/readyz`)).ok, 'readiness is not green before removing checkpoints');
  await using(deployment.database(), (sql) => appendOnlyLifted(sql, async () => {
    const rows = await sql.query("SELECT * FROM audit_log WHERE action = 'audit.checkpoint' ORDER BY seq");
    expect(rows.length > 0, 'no checkpoints to remove');
    await sql.exec("DELETE FROM audit_log WHERE action = 'audit.checkpoint'");
    try {
      await red(deployment);
    } finally {
      for (const row of rows) await insertRow(sql, 'audit_log', row);
    }
  }));
  await until('readiness recovered', async () => (await fetch(`${deployment.origin}/readyz`)).ok, 20);
  return 'a recent heartbeat without a checkpoint is red; restoring the checkpoint recovers';
}

/** A hole before the latest signed prefix must stop the next scheduled checkpoint. */
export async function middleCut(deployment: Deployment, { admin }: People): Promise<string> {
  expect((await fetch(`${deployment.origin}/readyz`)).ok, 'readiness is not green before the middle cut');
  let seq = 0;
  await using(deployment.database(), async (sql) => {
    const [head] = await sql.query<{ next_seq: string | number }>('SELECT next_seq FROM audit_chain_head');
    const [latest] = await sql.query<{ seq: string | number; metadata: string }>(
      "SELECT seq, metadata FROM audit_log WHERE author = 'vault' AND action = 'audit.checkpoint' AND decision = 'allow' ORDER BY seq DESC LIMIT 1",
    );
    expect(latest !== undefined, 'no signed prefix to cut from');
    const signed = JSON.parse(latest.metadata) as { seq: number };
    // An old heartbeat and its checkpoint carry no access change or linked write.
    const [heartbeat] = await query<{ seq: string | number }>(sql, `SELECT h.seq FROM audit_log h JOIN audit_log c ON c.seq = h.seq + 1
      WHERE h.action = 'audit.heartbeat' AND h.seq > 0 AND c.author = 'vault' AND c.action = 'audit.checkpoint'
      AND c.decision = 'allow' AND c.seq < $1 AND NOT EXISTS
        (SELECT 1 FROM audit_log linked WHERE linked.related_seq IN (h.seq, c.seq)) ORDER BY h.seq LIMIT 1`, [signed.seq]);
    expect(heartbeat !== undefined, 'no older heartbeat and checkpoint to cut');
    seq = Number(heartbeat.seq);
    const kept = await query(sql, 'SELECT * FROM audit_log WHERE seq >= $1 AND seq <= $2 ORDER BY seq', [seq, seq + 1]);
    expect(kept.length === 2, 'the middle cut needs two adjacent entries');
    await appendOnlyLifted(sql, async () => {
      await query(sql, 'DELETE FROM audit_log WHERE seq >= $1 AND seq <= $2', [seq, seq + 1]);
      try {
        // Do not call full verification first: the scheduled job must find the hole itself.
        await deployment.scheduled({ allowFailure: true });
        let checkpoint: { decision: string; code: string | null; metadata: string } | undefined;
        await until('the checkpoint after the cut', async () => {
          [checkpoint] = await query(sql, `SELECT decision, code, metadata FROM audit_log
            WHERE author = 'vault' AND action = 'audit.checkpoint' AND seq >= $1 ORDER BY seq LIMIT 1`, [head.next_seq]);
          return checkpoint !== undefined;
        }, 10);
        expect(checkpoint?.decision === 'deny' && checkpoint.code === 'log_broken', 'the checkpoint signed over a middle cut', checkpoint);
        const detail = JSON.parse(checkpoint.metadata) as { reason: string };
        expect(detail.reason.includes(`sequence gap: expected seq ${seq}`), 'the checkpoint did not name the middle gap', detail);
        await red(deployment);
      } finally {
        await transaction(sql, async () => {
          for (const row of kept) await insertRow(sql, 'audit_log', row);
        });
      }
    });
  });
  await deployment.scheduled();
  await until('readiness recovered after the middle cut', async () => (await fetch(`${deployment.origin}/readyz`)).ok, 20);
  expect((await admin.api.audit.verify()).ok, 'the restored middle cut did not verify');
  return `entries ${seq} and ${seq + 1}, before the latest signed prefix, cut: checkpoint log_broken, readiness red; restored and recovered`;
}
