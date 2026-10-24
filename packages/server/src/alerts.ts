// A workload's alerts (docs/design/workload-access.md, section 8.3): one
// `workload.alert` entry of the app's in the log, which is the record that
// counts and the audit page filters, then the deployment's own `alert`,
// called in the background after the response (`waitUntil` on Workers):
//
//   auth: signin({ workloads: { limits, alert: (alert) => fetch(env.SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text: alert.text }) }) } })
//
// Whoever learns of the event raises it: the gate's first refusal of a
// count in its window (`limit`, here), an enrollment's session (`enrolled`)
// and its tripwire (`contention`), a code near its end (`expiring`), and
// each freeze and lift (`frozen`).
import type { WorkloadAlert } from '@coffre/core/identity';

import { appendAudit } from './db/audit.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * Log `alert`, in a transaction of its own, then hand it to the
 * deployment's `alert` after the response. Never throws: an alert never
 * turns the answer it rides on into another. A log that refuses it, or a
 * delivery that fails, is said once in the process's log.
 *
 * `details` go in the entry beside the alert's own fields: a limit's count,
 * the credential it was for. `environmentId` is the place it concerns.
 */
export async function raiseAlert(
  runtime: Pick<CoffreRuntime, 'db' | 'chainKey' | 'auth' | 'waitUntil'>,
  alert: WorkloadAlert,
  details: Record<string, unknown> = {},
  environmentId: string | null = null,
): Promise<void> {
  try {
    await runtime.db.transaction((tx) =>
      appendAudit(tx, runtime.chainKey, [{
        actorType: 'service',
        actorId: alert.service.slice('token:'.length),
        action: 'workload.alert',
        decision: 'allow',
        environmentId,
        sourceIp: alert.ip,
        metadata: { ...details, kind: alert.kind, service: alert.service, binding: alert.binding, session: alert.session, ip: alert.ip, text: alert.text },
      }]),
    );
  } catch (error) {
    console.error('logging a workload alert failed', logged(error));
  }
  const deliver = runtime.auth.mode === 'signin' ? runtime.auth.signin.workloads?.alert ?? null : null;
  if (deliver === null) return;
  runtime.waitUntil(
    Promise.resolve()
      .then(() => deliver(alert))
      .then(() => undefined, (error: unknown) => console.error(`delivering a workload alert failed: ${alert.text}`, logged(error))),
  );
}

/**
 * A count's first refusal in its window (section 8.1), as one line for a
 * person: `api-prod is past its limit for stripe per minute, from
 * 203.0.113.9: refused for 42 s`.
 */
export function limitAlert(
  caller: { principal: string; bindingId: string; session: string | null; sourceIp: string | null },
  count: { key: string; retryAfterMs: number },
): WorkloadAlert {
  const name = caller.principal.slice('token:'.length);
  const from = caller.sourceIp === null ? '' : `, from ${caller.sourceIp}`;
  return {
    kind: 'limit',
    service: caller.principal,
    binding: caller.bindingId,
    session: caller.session,
    ip: caller.sourceIp,
    text: `${name} is past its limit for ${count.key}${from}: refused for ${Math.ceil(count.retryAfterMs / 1000)} s`,
  };
}
