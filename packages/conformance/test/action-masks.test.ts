import assert from 'node:assert/strict';
import test from 'node:test';

import { maskProbes, verifyMasks } from '../scripts/action-fixtures.ts';

test('the Action log check requires every probe to be present and masked', () => {
  const masked = maskProbes().map(([marker]) => `2026-10-03T00:00:00Z ${marker}***`).join('\n');
  assert.doesNotThrow(() => verifyMasks(masked));
  assert.throws(() => verifyMasks(''), /missing masked probe/);
  const [marker, value] = maskProbes()[0]!;
  assert.throws(() => verifyMasks(masked.replace(`${marker}***`, marker + value)), /did not mask/);
  assert.throws(() => verifyMasks(masked + `\n${value}`), /did not mask/);
});
