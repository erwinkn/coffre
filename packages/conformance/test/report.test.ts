import assert from 'node:assert/strict';
import test from 'node:test';

import { Report } from '../src/report.ts';

test('a check of a route not served yet is skipped, saying why, and never run', async (t) => {
  const lines: string[] = [];
  t.mock.method(console, 'log', (line: string) => lines.push(line));
  t.mock.method(console, 'error', (line: string) => lines.push(line));
  const report = new Report(undefined, { waits: 'GET /later answers 501 until served' });
  let ran = false;
  const skipped = await report.check('waits', {}, async () => {
    ran = true;
    throw new Error('ran');
  });
  await report.check('runs', {}, async () => {
    throw new Error('a served route failed');
  });
  assert.equal(ran, false);
  assert.equal(skipped, undefined);
  assert.deepEqual(report.failed, ['runs']);
  assert.match(lines[0]!, /^ {2}skip +waits +not served in 0\.16 yet: GET \/later answers 501 until served$/);
});
