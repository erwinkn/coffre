// The server's side of what a request's strings and rows cost, now that no field has a length of its own: a sealed
// state counted before it is split, and a sign-in's candidate bindings checked only while its budget lasts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { SIGN_IN_WORK_NS, SignInWorkSpent, signInWork } from '@coffre/core/identity';

import { authMac } from '../src/auth-rows.ts';
import { checkedCandidates, type BindingRow } from '../src/db/queries.ts';
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

test("a sign-in's candidate bindings are checked only while its budget lasts: sixteen of 900 KiB are refused, not all MAC'd", () => {
  const key = randomBytes(32);
  const claims = JSON.stringify(Object.fromEntries(Array.from({ length: 1500 }, (_, i) => [`c${i}`, 'v'.repeat(600)])));
  const row = (i: number) => {
    const fields = { id: crypto.randomUUID(), principal: 'token:api', generation: 0, profile: 'custom', issuer: 'https://idp.acme.example', jwksUri: `sha256:${i}`, claims, revokedAt: null };
    return { ...fields, authMac: authMac(key, 'service_bindings', fields as never) } as unknown as BindingRow;
  };
  const rows = Array.from({ length: 16 }, (_, i) => row(i));
  const work = signInWork();
  const { result, ms } = cpu(() => checkedCandidates(key, rows, work));
  assert.ok(result instanceof SignInWorkSpent, String(result));
  // R27's 20 ms: what the budget lets through, and no more (`SIGN_IN_WORK_NS`, 16 ms).
  assert.ok(ms < 20, `took ${ms} ms`);
  assert.ok(work.left < 0 && SIGN_IN_WORK_NS === 16_000_000);
  // A few small ones are all checked, a sliver of the budget spent.
  const small = signInWork();
  const fields = { id: crypto.randomUUID(), principal: 'token:api', generation: 0, profile: 'custom', issuer: 'https://idp.acme.example', jwksUri: 'sha256:x', claims: '{"sub":"x"}', revokedAt: null };
  const checked = checkedCandidates(key, [{ ...fields, authMac: authMac(key, 'service_bindings', fields as never) } as unknown as BindingRow], small);
  assert.equal(checked.length, 1);
  assert.ok(small.left > SIGN_IN_WORK_NS - 10_000);
});
