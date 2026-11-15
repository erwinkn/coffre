import assert from 'node:assert/strict';
import test from 'node:test';

import { alertsIn, cutFound } from '../src/checks/audit.ts';
import { lineReader } from '../src/harness.ts';

/** A finding's line, as the signer's `alertOf` writes it. */
const KEPT = '- cut kept: this tree of the log does not end with the entry signed last';
const AGING = '- cut aging: this tree of the log does not end with the entry signed last';
const header = (count: number) => `coffre's signer reports (${count}):`;
const NOTE = "(no alert is configured: the vault's `alert`)";

/** As wrangler prints a Worker's `console.error`: esbuild's error, colored, its other lines notes after a blank line. */
const wrangler = ([first, ...rest]: string[]) => [`\x1b[31m✘ \x1b[41;31m[\x1b[41;97mERROR\x1b[41;31m]\x1b[0m \x1b[1m${first}\x1b[0m`, '', ...rest.map((line) => `  ${line}`), ''];

test('an alert as wrangler prints it is read whole, and names its cut', () => {
  const lines = wrangler([header(1), KEPT, NOTE]);
  assert.deepEqual(alertsIn(lines), [{ count: 1, findings: [KEPT], complete: true }]);
  assert.deepEqual(cutFound([lines], [0], 'kept')?.failed, null);
});

test('r1: an alert said before the cut is not fresh, and one that names a cut put back again fails', () => {
  const old = [header(1), KEPT, NOTE];
  assert.equal(cutFound([old], [1], 'kept'), undefined);
  assert.equal(cutFound([[...old, ...old]], [1], 'aging'), undefined);
  assert.equal(cutFound([[...old, header(2), AGING, KEPT]], [1], 'aging')?.failed, 'the signer names again a cut put back before');
});

test('r2: a header with one of the two findings it counts is not whole', () => {
  assert.equal(cutFound([[header(2), KEPT]], [0], 'kept'), undefined);
  assert.equal(cutFound([[header(2), KEPT, NOTE]], [0], 'kept'), undefined);
  assert.equal(cutFound([[header(2), KEPT, AGING]], [0], 'kept')?.failed, 'the signer names again a cut put back before');
});

test('r3: a finding cut mid-line is no finding, and an alert counting more than it names fails', () => {
  assert.equal(cutFound([[header(2), KEPT, '- ']], [0], 'kept'), undefined);
  assert.equal(cutFound([[header(2), KEPT, '- cut ag']], [0], 'kept'), undefined);
  const ten = Array.from({ length: 10 }, (_, at) => `- row member:${at}: this row is not what the log says`);
  assert.equal(cutFound([[header(11), ...ten]], [0], 'kept'), undefined);
  assert.equal(cutFound([[header(11), ...ten, 'and 1 more']], [0], 'kept')?.failed, 'the signer names too few of its findings to tell what it found again');
  assert.equal(cutFound([[header(11), ...ten, 'and 2 more']], [0], 'kept'), undefined);
});

test('a foreign line among its findings leaves an alert incomplete', () => {
  assert.equal(cutFound([[header(2), KEPT, '[wrangler:info] GET /livez 200 OK', AGING]], [0], 'kept'), undefined);
  assert.deepEqual(alertsIn([header(Number.NaN), "coffre's signer reports (x):"]).map((alert) => alert.complete), [false, false]);
});

test('r4: a newline on stdout does not end a finding still arriving on stderr', () => {
  const [out, err]: string[][] = [[], []];
  const [stdout, stderr] = [lineReader(out), lineReader(err)];
  stderr.write(Buffer.from(`${header(2)}\n${KEPT}\n- `));
  stdout.write(Buffer.from('\n'));
  assert.equal(cutFound([out, err], [0, 0], 'kept'), undefined);
  stderr.write(Buffer.from(`${AGING.slice(2)}\n`));
  assert.equal(cutFound([out, err], [0, 0], 'kept')?.failed, 'the signer names again a cut put back before');
});

test('lines are whole across chunks split mid-line and mid-character, the last at the end', () => {
  const lines: string[] = [];
  const reader = lineReader(lines);
  const bytes = Buffer.from('✘ [ERROR] one\ntwo ✘\nthree');
  const split = bytes.indexOf('✘', 5) + 1;
  reader.write(bytes.subarray(0, 2));
  assert.deepEqual(lines, []);
  reader.write(bytes.subarray(2, split));
  assert.deepEqual(lines, ['✘ [ERROR] one']);
  reader.write(bytes.subarray(split));
  assert.deepEqual(lines, ['✘ [ERROR] one', 'two ✘']);
  reader.end();
  assert.deepEqual(lines, ['✘ [ERROR] one', 'two ✘', 'three']);
});
