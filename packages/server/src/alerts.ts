// A workload's alerts (docs/design/workload-access.md, section 8.3): one
// `workload.alert` entry of the app's in the log, which is the record that
// counts and the audit page filters, then the deployment's own `alert`,
// called in the background after the response (`waitUntil` on Workers):
//
//   auth: signin({ workloads: { limits, alert: (alert) => fetch(env.SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text: alert.text }) }) } })
//
// Whoever learns of the event raises it: the gate's first refusal of a
// count in its window (`limit`, here), an enrollment's session (`enrolled`)
// and its tripwire (`contention`), a code near its end (`expiring`), each
// freeze and lift (`frozen`), and a sign-in's token signed by a key its
// service's uploaded keys lack (`unknown_key`, here).
import type { WorkloadAlert } from '@coffre/core/identity';

import type { UnknownKey } from './api/workloads.ts';
import { appendAudit } from './db/audit.ts';
import { claimAlert } from './db/workloads.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';

/** How often a service's `unknown_key` alerts at most, whatever key its tokens name: anyone may send one. */
export const UNKNOWN_KEY_ALERT_MS = 60 * 60 * 1000;

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

/**
 * A sign-in refused for a key its service's uploaded keys lack
 * (`UnknownKey`): its issuer most likely rotated them, and none of the
 * service's workloads signs in until an Owner uploads them again. Raised
 * once an hour per service at most, whatever the token's `kid`, since
 * anyone who knows a service and its issuer can send one: a conditional
 * write outside any transaction decides (`claimAlert`), so a refusal capped
 * out never takes the log's head, whichever isolate it reaches. Never
 * throws.
 */
export async function unknownKeyAlert(runtime: Pick<CoffreRuntime, 'db' | 'chainKey' | 'auth' | 'waitUntil'>, refusal: UnknownKey, sourceIp: string | null): Promise<void> {
  try {
    if (!(await claimAlert(runtime.db, refusal.service, 'unknown_key', new Date(), UNKNOWN_KEY_ALERT_MS))) return;
  } catch (error) {
    console.error('capping a workload alert failed', logged(error));
    return;
  }
  await raiseAlert(runtime, keyAlert(refusal, sourceIp), { issuer: refusal.issuer, kid: refusal.kid });
}

/**
 * An unknown key's alert, as one line for a person, which says how to
 * upload the issuer's keys again: `api-prod's sign-in from 203.0.113.9 was
 * refused: its token names key "Ab3…", not one uploaded for https://….`
 */
export function keyAlert(refusal: UnknownKey, sourceIp: string | null): WorkloadAlert {
  const { service, binding, issuer, kid } = refusal;
  const name = service.slice('token:'.length);
  const from = sourceIp === null ? '' : ` from ${sourceIp}`;
  const named = kid === null ? 'names no key' : `names key "${kid}"`;
  const fetch = binding.profile === 'kubernetes' ? 'kubectl get --raw /openid/v1/jwks > keys.json' : 'save its JWKS as keys.json';
  return {
    kind: 'unknown_key',
    service,
    binding: binding.id,
    session: null,
    ip: sourceIp,
    text: `${name}'s sign-in${from} was refused: its token ${named}, not one uploaded for ${issuer}. `
      + `If that issuer rotated its keys, upload them again: ${fetch}, then coffre trust ${name} --issuer ${shellWord(issuer)} --replace-keys --jwks-file keys.json --apply. `
      + 'Said once an hour at most.',
  };
}

/** `word` as one shell word: as it is when it needs no quoting, as an issuer URL does not. */
function shellWord(word: string): string {
  return /^[A-Za-z0-9._~:/@%+=,-]+$/.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`;
}
