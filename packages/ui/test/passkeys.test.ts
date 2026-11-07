import test from 'node:test';
import assert from 'node:assert/strict';

import { CoffreError } from '@coffre/client';

import { addOutcome, addsInPlace, readAddOptions, endsList, kindOf, nameProblem, promptsForPasskey, readsForPrompt, removable, removalSentence, resetSentence } from '../src/lib/passkeys.ts';

const none = { sessions: 0, tokens: 0, handles: 0, apps: 0 };
const optional = (enrolled: boolean) => ({ policy: 'optional' as const, enrolled, confirmedUntil: null });

test('what a removal or a reset ends, in words (docs/design/passkeys.md, sections 3.6 and 3.7)', () => {
  assert.equal(endsList({ sessions: 3, tokens: 1, handles: 2, apps: 1 }), '3 sessions, 1 personal token, 2 handles and 1 connected app');
  assert.equal(endsList({ ...none, tokens: 2 }), '2 personal tokens');
  assert.equal(endsList(none), '');
  assert.equal(removalSentence('YubiKey 5C', { ...none, sessions: 3, tokens: 1 }, false), 'Removing YubiKey 5C signs you out of 3 other sessions and ends 1 personal token.');
  assert.equal(removalSentence('iCloud Keychain', { ...none, sessions: 1 }, false), 'Removing iCloud Keychain signs you out of 1 other session.');
  assert.equal(removalSentence('Laptop', { ...none, apps: 2 }, false), 'Removing Laptop ends 2 connected apps.');
  assert.equal(removalSentence('Laptop', none, false), 'Removing Laptop signs you out nowhere else: this browser is the only place you are signed in.');
  // The last one, under `optional`: back to the provider alone.
  assert.match(removalSentence('Laptop', none, true), /your last passkey: you will sign in with your provider alone/);
  assert.equal(
    resetSentence('bob@acme.example', 2, { sessions: 3, tokens: 1, handles: 2, apps: 1 }),
    'Removes bob@acme.example’s 2 passkeys. Everything they are signed in with ends: 3 sessions, 1 personal token, 2 handles and 1 connected app.',
  );
  assert.equal(resetSentence('bob@acme.example', 1, none), 'Removes bob@acme.example’s 1 passkey. They are signed in nowhere right now.');
});

test('the prompt asks a person with none under optional, until Not now, and again after a reset since (sections 3.3, 3.7)', () => {
  const pressed = Date.parse('2026-11-01T10:00:00Z');
  assert.equal(promptsForPasskey(optional(false), null, null), true);
  assert.equal(promptsForPasskey(optional(false), pressed, null), false, 'Not now puts it off');
  assert.equal(promptsForPasskey(optional(false), pressed, { at: '2026-10-31T09:00:00Z' }), false, 'a reset Not now saw already');
  assert.equal(promptsForPasskey(optional(false), pressed, { at: '2026-11-02T09:00:00Z' }), true, 'a reset since: news, said whatever Not now said');
  assert.equal(promptsForPasskey(optional(true), null, null), false, 'one held already');
  assert.equal(promptsForPasskey({ policy: 'required', enrolled: false, confirmedUntil: null }, null, null), false, 'required asks at sign-in, not here');
  assert.equal(promptsForPasskey({ policy: 'off', enrolled: false, confirmedUntil: null }, null, null), false);
  assert.equal(promptsForPasskey(null, null, null), false, 'behind Cloudflare Access, coffre signs no one in');
  // Its passkeys are read, for the reset, whatever Not now said.
  assert.equal(readsForPrompt(optional(false)), true);
  assert.equal(readsForPrompt(optional(true)), false);
});

test('adding in place takes a passkey held, a policy that has them, and room; removing never takes the last under required', () => {
  assert.equal(addsInPlace(optional(true), 2, 10), true);
  assert.equal(addsInPlace(optional(true), 10, 10), false, 'at the cap');
  assert.equal(addsInPlace(optional(false), 0, 10), false, 'a first one is added at a sign-in');
  assert.equal(addsInPlace({ policy: 'off', enrolled: true, confirmedUntil: null }, 1, 10), false, 'none added under off');
  assert.equal(removable({ policy: 'required', enrolled: true, confirmedUntil: null }, 1), false);
  assert.equal(removable({ policy: 'required', enrolled: true, confirmedUntil: null }, 2), true);
  assert.equal(removable(optional(true), 1), true, 'under optional, the last one goes, with a touch of itself');
  assert.equal(removable({ policy: 'off', enrolled: true, confirmedUntil: null }, 1), true, 'under off, a lost one goes with no touch (section 3.7)');
  assert.equal(kindOf({ synced: true }), 'Synced');
  assert.equal(kindOf({ synced: false }), 'This device only');
});

test("a passkey's name, held to the server's rule", () => {
  assert.equal(nameProblem('  Work laptop '), null);
  assert.equal(nameProblem('   '), 'Give it a name.');
  assert.equal(nameProblem('x'.repeat(64)), null);
  assert.equal(nameProblem('x'.repeat(65)), 'At most 64 characters.');
  assert.equal(nameProblem('a\u0007b'), 'No control characters.');
  assert.equal(nameProblem('a\u0085b'), 'No control characters.', 'C1 too, as \\p{Cc} counts it');
});

test("what a failed add means: the same answer again, done, new options, or the server's words", () => {
  const error = (status: number, code: string, reason?: string) => new CoffreError(status, code, 'message', reason);
  assert.equal(addOutcome(new TypeError('fetch failed')), 'unavailable', 'the network');
  assert.equal(addOutcome(error(503, 'unavailable')), 'unavailable');
  assert.equal(addOutcome(error(429, 'rate_limited')), 'unavailable');
  assert.equal(addOutcome(error(409, 'conflict', 'changed')), 'unavailable', 'another change came between its tries');
  assert.equal(addOutcome(error(409, 'conflict', 'passkey_exists')), 'exists', 'the first send was taken, its answer lost');
  assert.equal(addOutcome(error(409, 'conflict', 'state_mismatch')), 'again');
  assert.equal(addOutcome(error(401, 'touch_failed')), 'again');
  assert.equal(addOutcome(error(409, 'tampered')), 'refused');
  assert.equal(addOutcome(error(403, 'fresh_check_required')), 'refused');
  // A body that did not arrive whole, as the client reads it (`http_error`): a 409 may be `passkey_exists`, so the
  // saved answer is sent again, never a new create() (review r2 of #539).
  assert.equal(addOutcome(error(409, 'http_error')), 'unavailable', 'a 409 unread');
  assert.equal(addOutcome(error(401, 'http_error')), 'unavailable', 'a 401 unread');
  assert.equal(addOutcome(error(403, 'http_error')), 'refused');
});

test('add options that did not arrive whole reject, so the dialog offers a retry (review r3 of #539)', () => {
  const read = { options: { challenge: 'c', timeout: 60_000 }, state: 's' } as unknown as Parameters<typeof readAddOptions>[0];
  assert.equal(readAddOptions(read), read);
  for (const unread of [null, {}, { state: 's' }, { options: null, state: 's' }, { options: {}, state: 1 }]) {
    assert.throws(() => readAddOptions(unread as Parameters<typeof readAddOptions>[0]), TypeError);
    try {
      readAddOptions(unread as Parameters<typeof readAddOptions>[0]);
    } catch (thrown) {
      assert.equal(addOutcome(thrown), 'unavailable');
    }
  }
});
