import type { McpLimits, RateLimiter } from '@coffre/core/identity';

/**
 * Limits for exchanges that count in this process: what Node has, where
 * Workers have Cloudflare's rate-limiting bindings. Fixed one-minute
 * windows, per key: `perSource` keys by the caller's address, `total` by
 * one key for everyone, `perConnection` an MCP connection's tool calls by
 * its ID. A deployment with several processes allows each its own; size
 * them to that (docs/design/oidc.md, section 2). Workloads take the first
 * two, MCP all three.
 */
export function processLimits(options: { perSource?: number; perConnection?: number; total?: number } = {}): McpLimits {
  return {
    perSource: windowed(options.perSource ?? 30),
    perConnection: windowed(options.perConnection ?? 120),
    total: windowed(options.total ?? 300),
  };
}

const WINDOW_MS = 60 * 1000;
/** Keys counted at once; past that, the oldest window goes. */
const MAX_KEYS = 10_000;

function windowed(limit: number): RateLimiter {
  if (!Number.isInteger(limit) || limit < 1) throw new Error('a limit is a whole number of requests a minute, at least 1');
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
