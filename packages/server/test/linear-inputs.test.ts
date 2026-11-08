// The server's side of what a request's strings cost, now that no field has a length of its own: a sealed state
// counted before it is split.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { openState, sealState } from '../src/mcp/tokens.ts';

// The least CPU of five calls, which is what the code itself costs: a first call also compiles it, and the process's
// CPU counts V8's compiler threads and a collection's helpers, which only ever add to a call
// (packages/core/test/linear-inputs.test.ts). Splitting a million dots costs as much in every call.
const cpu = <T>(run: () => T) => {
  let least = Infinity;
  let result!: T | Error;
  for (let i = 0; i < 5; i++) {
    const started = process.cpuUsage();
    try {
      result = run();
    } catch (error) {
      result = error as Error;
    }
    const spent = process.cpuUsage(started);
    least = Math.min(least, (spent.user + spent.system) / 1000);
  }
  return { result, ms: least };
};

test("an MCP call's request state of a million dots is refused by its length, before it is split", () => {
  const key = randomBytes(32);
  const sealed = sealState(key, { approvalId: crypto.randomUUID(), connectionId: crypto.randomUUID(), digest: 'a'.repeat(64), expiresAt: new Date(Date.now() + 60_000) });
  assert.notEqual(openState(key, sealed), null);
  const { result, ms } = cpu(() => openState(key, '.'.repeat(1_000_000)));
  assert.equal(result, null);
  assert.ok(ms < 2, `took ${ms} ms`);
  assert.equal(openState(key, `${sealed}.x`), null);
});
