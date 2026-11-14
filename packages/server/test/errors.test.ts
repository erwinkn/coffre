// What a request is told of a key service that failed: an outage, 503
// `unavailable`, which the same request may get past; or a refusal of
// coffre's own, a 500 whose details only the log has. Read by the errors'
// names, as a Worker's RPC hands them back.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { KekCancelledError, KekRefusedError, KekUnavailableError } from '@coffre/core/kek';

import { toErrorBody } from '../src/api/errors.ts';
import { errorResponse } from '../src/http.ts';

test('a key service that does not answer is 503 unavailable, by its name across RPC; one that refuses coffre is a 500', (t) => {
  const logged: unknown[][] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => void logged.push(args));
  const UNAVAILABLE = { status: 503, body: { error: 'unavailable', message: 'coffre cannot reach what it depends on right now; try again in a moment' } };
  // As a Worker's RPC hands it back: an Error, with the thrown one's fields, its name among them.
  const crossed = (name: string, message: string) => Object.assign(new Error(message), { name });
  for (const error of [
    new KekUnavailableError('KMS Decrypt failed 3 times: ThrottlingException'),
    new KekCancelledError(true),
    crossed('KekUnavailableError', 'KMS Encrypt failed: KMSInternalException'),
    crossed('KekCancelledError', 'key operation was cancelled'),
    new Error('the vault failed the call', { cause: crossed('KekUnavailableError', 'the key service is down') }),
  ]) {
    assert.deepEqual(toErrorBody(error), UNAVAILABLE, error.message);
    assert.equal(errorResponse(error).headers.get('retry-after'), '5');
  }
  // Each logged as an outage: once by toErrorBody, once by the response.
  assert.deepEqual(logged.map(([label]) => label), Array(10).fill('a key service did not answer'));
  // Refused for good, its credentials or its key: asked again, the same. A bug's 500, which no client retries, and logged.
  logged.length = 0;
  for (const error of [new KekRefusedError('KMS Decrypt failed: AccessDeniedException'), crossed('KekRefusedError', 'KMS Encrypt failed: DisabledException'),
    new Error('the vault failed the call', { cause: new KekRefusedError('KMS decrypted under another key', true) })]) {
    assert.deepEqual(toErrorBody(error), { status: 500, body: { error: 'internal_error', message: 'something went wrong; see the server log' } }, error.message);
  }
  assert.deepEqual(logged.map(([label, line]) => [label, (line as { name: string }).name]), [['unhandled API error', 'KekRefusedError'], ['unhandled API error', 'KekRefusedError'], ['unhandled API error', 'Error']]);
  // Only its names: a message that says "Kek" is not one.
  assert.equal(toErrorBody(new Error('KekUnavailableError')).status, 500);
});
