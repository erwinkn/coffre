import { z } from 'zod';

import { registeredServerFn } from '../server/server-fn.ts';
import type { AuditRow } from '../shared/models.ts';
import { api } from './session.ts';
import { uiFailure, uiResult } from './result.ts';

export const listAudit = registeredServerFn({ method: 'GET' })
  .validator(z.object({ decision: z.literal('deny').optional(), actorId: z.string().optional() }))
  .handler(async ({ data }) =>
    uiResult(async () => {
      const { entries } = await api().audit.list({
        limit: 200,
        decision: data.decision,
        actor: data.actorId,
      });
      const rows: AuditRow[] = entries.map((entry) => ({
        seq: entry.seq,
        occurredAt: entry.occurredAt,
        actorType: entry.actorType,
        actorId: entry.actorId,
        action: entry.action,
        decision: entry.decision,
        project: entry.project,
        environment: entry.environment,
        subject:
          (typeof entry.metadata.key === 'string' ? entry.metadata.key : null) ??
          (typeof entry.metadata.reason === 'string' ? entry.metadata.reason : null) ??
          '--',
      }));
      return { entries: rows };
    }),
  );

export const verifyAuditChain = registeredServerFn({ method: 'GET' }).handler(async () => {
  try {
    const result = await api().audit.verify();
    if (!result.ok) {
      return {
        ok: true as const,
        integrity: 'broken' as const,
        failedAtSeq: result.failedAtSeq,
        reason: result.reason,
      };
    }
    return {
      ok: true as const,
      integrity: 'intact' as const,
      rows: result.rows,
      head: result.head,
    };
  } catch (error) {
    return uiFailure(error);
  }
});
