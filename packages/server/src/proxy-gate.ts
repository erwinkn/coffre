import { isDeploying, type Vault } from '@coffre/core/vault';

import { keeps015 } from './api/changes.ts';
import { ApiError } from './api/errors.ts';
import { askedOnce, askOnce, type AskedOnce } from './asked-once.ts';
import type { ProxyCode } from './proxy-code.ts';

/**
 * The gate (0.16, T186 PR C; docs/design/proxy-ui.md, section 6; formal/Routing.tla, CodeGate): before an isolate
 * serves its first proxy request, or the Proxy tab reads or writes, the names its code defines are reserved in the
 * vault's log (`reserveProxy`, a `proxy.code` change when it adds one, which deletes the UI items of those names,
 * audited). So no UI item a name code holds is served or shown by any isolate after one ran this code, and none
 * returns when a later deployment drops the name. `editable: false` included: `editable` decides what the tab may write,
 * never whether code's names are reserved.
 *
 * Per isolate, per vault, per code, asked once (asked-once.ts): the isolate's first requests make one call, the others
 * waiting for its settled answer, never its pending call. A call that fails keeps nothing: the requests that waited on
 * it answer 503 with it, and the next one asks again.
 *
 *   first proxy request of a deploy adding `maps`    1 call: `proxy.code`, the UI `maps` items deleted, answered once sealed
 *   the requests that come while it is under way     no call: each waits for its answer
 *   every request after                              no call
 */
let GATES = new WeakMap<Vault, Map<string, AskedOnce<void>>>();

/** Forget every gate passed: for tests, whose vault's log starts over between cases while the vault stays. */
export function forgetProxyGates(): void {
  GATES = new WeakMap();
}

export async function gateProxy(vault: Vault, code: ProxyCode | null): Promise<void> {
  if (code === null) return;
  const key = code.names.join('\n');
  let gates = GATES.get(vault);
  if (gates === undefined) GATES.set(vault, (gates = new Map()));
  let gate = gates.get(key);
  if (gate === undefined) gates.set(key, (gate = askedOnce()));
  await askOnce(gate, () => reserve(vault, code));
}

async function reserve(vault: Vault, code: ProxyCode): Promise<void> {
  let answer: Awaited<ReturnType<Vault['reserveProxy']>> | null;
  try {
    // A vault of 0.14's log holds no proxy definitions (0.15's log's objects), and makes none: nothing to reserve. Its
    // log is fixed when it is made, so the answer is kept with the vault.
    answer = (await keeps015(vault)) ? await vault.reserveProxy({ names: [...code.names] }) : null;
  } catch (error) {
    // A vault on another release (decision 8): 503 `deploying`, as every call answers it. An answer already the app's
    // own as well: 503 `starting`, from the vault's `about()` asked once (`keeps015`), when this request waited its
    // deadline for another's (review r2 of T201).
    if (isDeploying(error) || error instanceof ApiError) throw error;
    console.error("reserving the proxy code's names failed", { error: error instanceof Error ? error.message : String(error) });
    throw new ApiError('unavailable', "coffre cannot reserve its code's proxy names right now: ask again", 'proxy_gate', '1');
  }
  if (answer !== null && !answer.ok) throw new ApiError('unavailable', `coffre cannot reserve its code's proxy names: ${answer.refusal.message}`, 'proxy_gate', '1');
}
