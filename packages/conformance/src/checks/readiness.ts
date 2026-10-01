// Readiness needs both halves of the Cron's work: a recent heartbeat, and a
// checkpoint the vault signed over it. Either missing turns /readyz red.
import { using } from '../database.ts';
import type { Deployment } from '../harness.ts';
import { expect, until } from '../report.ts';
import { appendOnlyLifted, insertRow, logRefuses } from './storage.ts';

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
