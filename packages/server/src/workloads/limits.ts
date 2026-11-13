import type { RateLimiter } from '@coffre/core/identity';

/**
 * The limit per source that counts in this process, what Node has where
 * Workers have a Cloudflare rate-limiting binding: requests one address
 * may make to an entry point that takes anyone, in fixed 10-second
 * windows, each entry point counted apart (the key names it). One value
 * serves `workloads.limits` and `mcp.limits` both. A deployment with
 * several processes allows each its own.
 *
 * `perSource`: 10,000 a window by default, 1,000 a second (the target CI
 * sign-in rate): a fleet behind one NAT, a cluster's egress
 * address or a CI provider's runner pool, is one address, so one address
 * may carry the whole target. The options `perConnection` and
 * `total` are taken and read no more, and the limiters of those names it
 * still returns, for a deployment that picks them out (`{ total:
 * processLimits().total }`), let every request through (deprecated; gone
 * in 0.17).
 */
export function processLimits(
  options: {
    perSource?: number;
    /** @deprecated Read no more. */
    perConnection?: number;
    /** @deprecated Read no more. */
    total?: number;
  } = {},
): {
  perSource: RateLimiter;
  /** @deprecated Lets every request through. */
  perConnection: RateLimiter;
  /** @deprecated Lets every request through. */
  total: RateLimiter;
} {
  return { perSource: windowed(options.perSource ?? PER_SOURCE), perConnection: UNLIMITED, total: UNLIMITED };
}

/** The deprecated limits, as `processLimits` still returns them for one release: no count. */
const UNLIMITED: RateLimiter = { limit: async () => ({ success: true }) };

/** CI sign-in at 1,000 a second, what the limits here and the spent tokens' pruning (`SPENT_TOKENS_PER_BEAT`) are sized for. */
export const SIGN_INS_PER_SECOND = 1_000;
/** Cloudflare's rate-limiting binding counts in 10 s or 60 s periods: the shorter, as the examples' binding does, so a burst is refused for 10 s, not a minute. */
const WINDOW_MS = 10 * 1000;
/** When a source refused by its limit asks again: once the window has moved on, here and in the examples' binding (`period: 10`). */
export const SOURCE_RETRY_AFTER = String(WINDOW_MS / 1000);
/** The default: the target, for one window. */
const PER_SOURCE = (SIGN_INS_PER_SECOND * WINDOW_MS) / 1000;
/**
 * Keys counted at once; past that, the oldest window goes, the one nearest
 * its end. Computed: the addresses the target's requests can come from in
 * one window, each one new, so a window evicted at that rate has ended
 * already. About 200 bytes a key (its string, its window, the map's
 * entry): 2 MB at most. A flood from more addresses than that evicts the
 * oldest windows, which then count from nothing: no address is refused for
 * another's requests.
 */
const MAX_KEYS = (SIGN_INS_PER_SECOND * WINDOW_MS) / 1000;

function windowed(limit: number): RateLimiter {
  if (!Number.isInteger(limit) || limit < 1) throw new Error('a limit is a whole number of requests a window (10 s), at least 1');
  const windows = new Map<string, { start: number; count: number }>();
  return {
    async limit({ key }) {
      const now = Date.now();
      let window = windows.get(key);
      if (window === undefined || now - window.start >= WINDOW_MS) {
        windows.delete(key);
        window = { start: now, count: 0 };
        windows.set(key, window);
        while (windows.size > MAX_KEYS) windows.delete(windows.keys().next().value!);
      }
      window.count++;
      return { success: window.count <= limit };
    },
  };
}
