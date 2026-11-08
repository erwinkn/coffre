// The server's side of what a request's strings cost, now that no field has a length of its own: a sealed state
// counted before it is split.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { openState, sealState } from '../src/mcp/tokens.ts';

const cpu = <T>(run: () => T) => {
  const started = process.cpuUsage();
  let result: T | Error;
  try {
    result = run();
  } catch (error) {
    result = error as Error;
  }
  const spent = process.cpuUsage(started);
  return { result, ms: (spent.user + spent.system) / 1000 };
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
