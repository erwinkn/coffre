import { isDeploying, type Vault } from '@coffre/core/vault';

import { ApiError } from './api/errors.ts';
import type { ProxyCode } from './proxy-code.ts';

/**
 * The gate (0.16, T186 PR C; docs/design/proxy-ui.md, section 6; formal/Routing.tla, CodeGate): before an isolate
 * serves its first proxy request, or the Proxy tab reads or writes, the names its code defines are reserved in the
 * vault's log (`reserveProxy`, a `proxy.code` change when it adds one, which deletes the UI items of those names,
 * audited). So no UI item a name code holds is served or shown by any isolate after one ran this code, and none
 * returns when a later deployment drops the name. `editable: false` included: `editable` decides what the tab may write,
 * never whether code's names are reserved.
 *
 * Per isolate, per vault, per code: only the settled answer is kept, never the pending call (AGENTS.md, "What an
 * isolate keeps"), so that concurrent first requests each make the call, which is idempotent. A call that fails keeps
 * nothing: the request answers 503, and the next one asks again.
 *
 *   first proxy request of a deploy adding `maps`    1 call: `proxy.code`, the UI `maps` items deleted, answered once sealed
 *   every request after                              no call
 */
const GATED = new WeakMap<Vault, Set<string>>();

export async function gateProxy(vault: Vault, code: ProxyCode | null): Promise<void> {
  if (code === null) return;
  const key = code.names.join('\n');
  if (GATED.get(vault)?.has(key) === true) return;
  let answer: Awaited<ReturnType<Vault['reserveProxy']>>;
  try {
    answer = await vault.reserveProxy({ names: [...code.names] });
  } catch (error) {
    // A vault on another release (decision 8): 503 `deploying`, as every call answers it.
    if (isDeploying(error)) throw error;
    console.error("reserving the proxy code's names failed", { error: error instanceof Error ? error.message : String(error) });
    throw new ApiError('unavailable', "coffre cannot reserve its code's proxy names right now: ask again", 'proxy_gate', '1');
  }
  if (!answer.ok) throw new ApiError('unavailable', `coffre cannot reserve its code's proxy names: ${answer.refusal.message}`, 'proxy_gate', '1');
  let gated = GATED.get(vault);
  if (gated === undefined) GATED.set(vault, (gated = new Set()));
  gated.add(key);
}
