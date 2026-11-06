// A body nested deep, at every entry point that reads one: the API, sign-in,
// MCP. `JSON.parse` reads any depth, and the value count holds a body to
// `MAX_BODY_NODES` levels at most, but what walks a value by recursion runs
// out of stack at a few thousand levels on Node, and sooner on a smaller
// stack: that `RangeError` is the caller's input, answered 400, never 500.
// The vault's own socket is `packages/vault/test/node.test.ts`'s; the proxy's
// body, `credential-proxy-body.test.ts`'s.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';

import { isStackOverflow, STACK_OVERFLOW, STACK_OVERFLOW_CODE } from '@coffre/core/vault';
import { z } from 'zod';

import { NESTED_TOO_DEEPLY, toErrorBody } from '../src/api/errors.ts';
import { MAX_BODY_NODES } from '../src/http.ts';

/** A real stack overflow, as a walk of a value too deep for it throws one. */
function overflow(depth = 0): never {
  return overflow(depth + 1);
}
function overflowed(): RangeError {
  try {
    overflow();
  } catch (error) {
    return error as RangeError;
  }
}

test('a stack that ran out is known as V8 throws it, through causes and by the vault socket\'s code, and answered 400; never by words a caller wrote', () => {
  const thrown = overflowed();
  assert.ok(thrown instanceof RangeError);
  assert.equal(thrown.message, STACK_OVERFLOW);
  // As thrown; wrapped by what caught it; and as the vault's Node socket hands it back, its words in a plain Error.
  for (const error of [thrown, new Error('the policy could not be read', { cause: thrown }), Object.assign(new Error('vault policy: the call is nested too deeply to read'), { code: STACK_OVERFLOW_CODE })]) {
    assert.equal(isStackOverflow(error), true);
    assert.deepEqual(toErrorBody(error), { status: 400, body: { error: 'bad_request', message: NESTED_TOO_DEEPLY } });
  }
  assert.equal(isStackOverflow(new RangeError('Invalid array length')), false);
  // A caller's words that only say it: a key so named, in a validation's error, is that validation's 400, its own message.
  const named = z.record(z.string().regex(/^[A-Z_]+$/), z.string()).safeParse({ [STACK_OVERFLOW]: 'v' });
  assert.equal(named.success, false);
  assert.ok(named.error!.message.includes(STACK_OVERFLOW));
  assert.equal(isStackOverflow(named.error), false);
  assert.notEqual(toErrorBody(named.error).body.message, NESTED_TOO_DEEPLY);
  assert.equal(isStackOverflow(new Error(`vault policy: ${STACK_OVERFLOW}`)), false);
  assert.equal(toErrorBody(new RangeError('Invalid array length')).status, 500);
});

type Answer = { what: string; status: number; text: string };

test('at every entry point, a body nested as deep as its count allows is answered by its route, and a walk that runs out of stack 400, on a stack of half a megabyte', async () => {
  // Half a megabyte, an eighth of a worker's default: `JSON.stringify` runs out at about 1,350 levels there and
  // `structuredClone` at 500, under the 1,580 these bodies nest (`deep-bodies.worker.ts`).
  assert.ok(MAX_BODY_NODES > 1_400);
  const worker = new Worker(new URL('./deep-bodies.worker.ts', import.meta.url), { resourceLimits: { stackSizeMb: 0.5 }, execArgv: ['--conditions=coffre:source'] });
  try {
    const { deep, overflowed } = await new Promise<{ deep: Answer[]; overflowed: Answer[] }>((resolve, reject) => {
      worker.once('message', resolve);
      worker.once('error', reject);
    });
    assert.equal(deep.length, 6);
    for (const { what, status, text } of deep) {
      assert.ok(status < 500, `${what} answered ${status}: ${text}`);
      // Each its route's own answer: a field that must be a string is refused; one no one reads is left alone.
      if (/role|secret write|device login/.test(what)) assert.equal(status, 400, `${what}: ${text}`);
    }
    assert.deepEqual(overflowed.map(({ what }) => what), ['the API', 'sign-in', 'MCP']);
    for (const { what, status, text } of overflowed) {
      assert.equal(status, 400, `${what}: ${text}`);
      assert.ok(text.includes(NESTED_TOO_DEEPLY), `${what}: ${text}`);
    }
  } finally {
    await worker.terminate();
  }
});
