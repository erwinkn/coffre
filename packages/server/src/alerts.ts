// A workload's alerts the app raises (docs/design/0.16.md, "What the app
// reads of a workload, and decides nothing on"), handed to the function the
// deployment's configuration names, never logged as entries:
//
//   auth: signin({ workloads: { limits, alert: (alert) => fetch(env.SLACK_WEBHOOK, { method: 'POST', body: JSON.stringify({ text: alert.text }) }) } })
//
// Each is capped in its service's gate, a Durable Object on Workers, so once
// for the whole deployment, whichever isolate learns of it:
//
// - `limit`: a credential's limit, at its window's first refusal (the gate's
//   `first`), so once per workload, credential and window;
// - `unknown_key`: an exchange's token signed by a key its binding's keys
//   lack, once an hour per service, since anyone who knows the service and
//   its issuer can send one.
import type { GateCount, WorkloadAlert, WorkloadsConfig } from '@coffre/core/identity';
import { logged } from '@coffre/db/dialect';

import type { Gates } from './gate.ts';

/** How long a refusal waits on the deployment's alert: past it, it answers, and the alert goes on without it. */
const ALERT_WAIT_MS = 2_000;

/**
 * Hand `alert` to the deployment's function, if it names one, waited on
 * `ALERT_WAIT_MS` at most; a slower one still finishes, the platform
 * keeping the request alive for it (`track`). Never throws.
 */
export async function sendAlert(workloads: WorkloadsConfig, alert: WorkloadAlert, track: (work: Promise<unknown>) => void): Promise<void> {
  const deliver = workloads.alert;
  if (deliver === null) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const sent = (async () => deliver(alert))().catch((error: unknown) => console.error("the deployment's workload alert failed", logged(error)));
  track(sent);
  await Promise.race([sent, new Promise<void>((resolve) => (timer = setTimeout(resolve, ALERT_WAIT_MS)))]);
  clearTimeout(timer);
}

/**
 * A count's first refusal in its window, as one line for a person:
 * `api-prod is past its limit for stripe per minute, from 203.0.113.9:
 * refused for 42 s`. The app's row of a session names no binding.
 */
export function limitAlert(caller: { principal: string; session: string; sourceIp: string | null }, count: { key: string; retryAfterMs: number }): WorkloadAlert {
  const from = caller.sourceIp === null ? '' : `, from ${caller.sourceIp}`;
  return {
    kind: 'limit',
    service: caller.principal,
    binding: null,
    session: caller.session,
    ip: caller.sourceIp,
    text: `${caller.principal.slice('token:'.length)} is past its limit for ${count.key}${from}: refused for ${Math.ceil(count.retryAfterMs / 1000)} s`,
  };
}

/** How often a service's unknown key alerts at most, whatever key its tokens name. */
const UNKNOWN_KEY_ALERT_MS = 60 * 60 * 1000;
/** That cap as its service's gate counts it: an hour's window, which a Durable Object keeps through an eviction (`DURABLE_WINDOW_MS`). */
const UNKNOWN_KEY_COUNT: GateCount = { key: 'unknown_key alert', windowMs: UNKNOWN_KEY_ALERT_MS, most: 1 };
/** Per configuration, so per isolate or process: until when each service's unknown key is not said again. Settled values only. */
const quiet = new WeakMap<WorkloadsConfig, Map<string, number>>();
const MAX_QUIET = 1_000;

/**
 * Whether `service`'s unknown key is said now: its gate's count decides,
 * once in each hour of the clock (two may come a moment apart, either side
 * of the hour's turn). The isolate then keeps quiet until that hour ends,
 * so a flood asks the gate once an hour. With no gate, or one that failed,
 * the isolate's own hour from now caps it. A gate past its ceiling says nothing, and
 * the next refusal asks again.
 */
async function unknownKeyDue(workloads: WorkloadsConfig, gates: Gates | null, service: string): Promise<boolean> {
  let until = quiet.get(workloads);
  if (until === undefined) quiet.set(workloads, (until = new Map()));
  const now = Date.now();
  if (now < (until.get(service) ?? -Infinity)) return false;
  let due = true;
  let ends = now + UNKNOWN_KEY_ALERT_MS;
  if (gates !== null) {
    try {
      const admitted = await gates(service).admit({ counts: [UNKNOWN_KEY_COUNT] });
      if (!admitted.ok && admitted.reason !== 'limit') return false;
      // Quiet until the gate's window ends, the clock's hour: the same for every isolate.
      ends = admitted.ok ? (Math.floor(now / UNKNOWN_KEY_ALERT_MS) + 1) * UNKNOWN_KEY_ALERT_MS : now + admitted.retryAfterMs;
      due = admitted.ok;
    } catch (error) {
      console.error("the workload gate failed: an unknown key's alert is capped in this isolate alone", logged(error));
      // Another refusal that asked the gate at the same moment, failed too and spoke first: this one keeps quiet.
      if (Date.now() < (until.get(service) ?? -Infinity)) return false;
    }
  }
  until.delete(service);
  until.set(service, ends);
  while (until.size > MAX_QUIET) until.delete(until.keys().next().value!);
  return due;
}

/**
 * A token signed by a key its binding's own keys lack: its issuer most
 * likely rotated them, and none of the service's runs signs in until a
 * manager uploads them again. The deployment's alert, once an hour per
 * service at most (`unknownKeyDue`), said as `sendAlert` says. `kid`: the
 * key the token names, as an alert may show it, or null. Never throws.
 */
export async function unknownKeyAlert(
  workloads: WorkloadsConfig,
  gates: Gates | null,
  refusal: { service: string; binding: { id: string; profile: string }; issuer: string; kid: string | null },
  sourceIp: string | null,
  track: (work: Promise<unknown>) => void,
): Promise<void> {
  const { service, binding, issuer, kid } = refusal;
  if (workloads.alert === null || !(await unknownKeyDue(workloads, gates, service))) return;
  const name = service.slice('token:'.length);
  const fetch = binding.profile === 'kubernetes' ? 'kubectl get --raw /openid/v1/jwks > keys.json' : 'save its JWKS as keys.json';
  await sendAlert(workloads, {
    kind: 'unknown_key',
    service,
    binding: binding.id,
    session: null,
    ip: sourceIp,
    text: `${name}'s sign-in${sourceIp === null ? '' : ` from ${sourceIp}`} was refused: its token ${kid === null ? 'names no key' : `names key "${kid}"`}, not one uploaded for ${issuer}. `
      + `If that issuer rotated its keys, upload them again: ${fetch}, then coffre trust ${shellWord(`service:${name}`)} --issuer ${shellWord(issuer)} --replace-keys --jwks-file keys.json --apply. Said once an hour at most.`,
  }, track);
}

/** `word` as one shell word: as it is when it needs no quoting, as an issuer URL does not. */
function shellWord(word: string): string {
  return /^[A-Za-z0-9._~:/@%+=,-]+$/.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`;
}
