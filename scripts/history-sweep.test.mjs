import assert from 'node:assert/strict';
import test from 'node:test';

import { growing, plansOf, statementsOf, vanished } from './history-sweep.mjs';

/** A server log as auto_explain writes it: each `[statement, pages]` a plan of backend 7, after its path's mark. */
function logOf(paths) {
  const plan = (text, pages) => [
    '2026-11-10 20:00:00.000 UTC [7] LOG:  duration: 0.100 ms  plan:',
    ...JSON.stringify({ 'Query Text': text, Plan: { 'Shared Hit Blocks': pages, 'Shared Read Blocks': 0 } }, null, 1).split('\n').map((line) => `\t${line}`),
  ];
  return Object.entries(paths).flatMap(([path, statements]) => [plan(`/* sweep:measured:${path} */ SELECT 1`, 0), ...statements.map(([text, pages]) => plan(text, pages))])
    .flat().join('\n');
}

const ACCESS = 'SELECT seq FROM audit_log WHERE subject_principal = $1 ORDER BY seq DESC LIMIT 1';

test("a statement two paths share grows in the one whose run of it grew, though the other's is larger and flat", () => {
  // Each run twice, the first of a backend's being its catalog's (statementsOf): the second is the one measured.
  const small = { 'GET /members': [[ACCESS, 900], [ACCESS, 900]], 'GET /members/ada': [[ACCESS, 20], [ACCESS, 20]] };
  const large = { 'GET /members': [[ACCESS, 900], [ACCESS, 900]], 'GET /members/ada': [[ACCESS, 400], [ACCESS, 400]] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  const grown = growing(before, after);
  assert.deepEqual(grown.map(({ why, before, after }) => [after.path, why, before.pages, after.pages]), [['GET /members/ada', 'pages', 20, 400]]);
});

test("a statement one path stopped running at the larger size is gone, though another path still runs it", () => {
  const small = { 'GET /members': [[ACCESS, 9], [ACCESS, 9]], 'GET /audit': [[ACCESS, 9], [ACCESS, 9]] };
  const large = { 'GET /members': [[ACCESS, 9], [ACCESS, 9]], 'GET /audit': [] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  assert.deepEqual(vanished(before, after).map(({ at }) => at.path), ['GET /audit']);
  assert.deepEqual(growing(before, after), []);
});

test('literals and spaces aside, a statement is the same at both sizes', () => {
  const small = { 'GET /audit': [["SELECT 1 FROM audit_log WHERE action = 'a.b' LIMIT 50", 5], ["SELECT 1 FROM audit_log WHERE action = 'a.b' LIMIT 50", 5]] };
  const large = { 'GET /audit': [["SELECT  1 FROM audit_log\n WHERE action = 'c.d' LIMIT 51", 6], ["SELECT 1 FROM audit_log WHERE action = 'c.d' LIMIT 51", 6]] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  assert.equal(after.size, 1);
  assert.deepEqual([growing(before, after), vanished(before, after)], [[], []]);
});
