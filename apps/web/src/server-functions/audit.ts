import { z } from 'zod';

import { getRuntime } from '../server/runtime.ts';
import { registeredServerFn } from '../server/server-fn.ts';
import type { AuditRow } from '../shared/models.ts';
import { currentRequestContext } from './session.ts';
import { uiResult } from './result.ts';

export const listAudit = registeredServerFn({ method: 'GET' })
  .validator(z.object({ decision: z.literal('deny').optional(), actorId: z.string().optional() }))
  .handler(async ({ data }) => {
    const runtime = getRuntime();
    const ctx = currentRequestContext();
    return uiResult(async () => {
      const entries = await runtime.audit.list(ctx, {
        limit: 200,
        decision: data.decision,
        actorId: data.actorId,
      });
      const rows: AuditRow[] = entries.map((entry) => ({
        seq: entry.seq,
        occurredAt: entry.occurredAt,
        actorType: entry.actorType,
        actorId: entry.actorId,
        action: entry.action,
        decision: entry.decision,
        subject:
          (typeof entry.metadata.key === 'string' ? entry.metadata.key : null) ??
          (typeof entry.metadata.reason === 'string' ? entry.metadata.reason : null) ??
          '--',
      }));
      return { entries: rows };
    });
  });

export const verifyAuditChain = registeredServerFn({ method: 'GET' }).handler(async () => {
  const runtime = getRuntime();
  const ctx = currentRequestContext();
  return uiResult(async () => {
    const result = await runtime.audit.verify(ctx);
    if (!result.ok) {
      throw Object.assign(
        new Error(`Chain broken at seq ${result.failedAtSeq}: ${result.reason}`),
        { statusCode: 409 },
      );
    }
    return { rows: result.rows, head: result.head };
  });
});
