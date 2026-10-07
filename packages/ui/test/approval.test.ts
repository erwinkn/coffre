import test from 'node:test';
import assert from 'node:assert/strict';

import { settled } from '../src/lib/approval.ts';

test('an approved change never reads as nothing changed: being made, then unknown, as the server says', () => {
  assert.deepEqual(settled({ status: 'approved', outcome: null }), { title: 'You approved this', text: 'coffre is making the change. Refresh in a moment to see how it went.' });
  const unknown = settled({ status: 'failed', outcome: { text: 'The person approved this, but coffre does not know whether the change was made.', error: 'unknown_outcome' } });
  assert.equal(unknown.title, 'This change may not have been made');
  assert.match(unknown.text, /doesn't know whether it was made/);
  assert.equal(settled({ status: 'approved', outcome: { text: 'market/prod/OLD is archived.' } }).text, 'market/prod/OLD is archived.');
  assert.equal(settled({ status: 'expired', outcome: null }).text, 'Nothing changed. The app can ask again.');
  assert.equal(settled({ status: 'denied', outcome: null }).text, 'Nothing changed.');
});
