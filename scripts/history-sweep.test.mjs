import assert from 'node:assert/strict';
import test from 'node:test';

import { growing, plansOf, shapeOf, statementsOf, unwarmed, vanished } from './history-sweep.mjs';

/** A server log as auto_explain writes it: each `[statement, pages, backend = 7]` a plan, after its path's mark. */
function logOf(paths) {
  const plan = (text, pages, backend = 7) => [
    `2026-11-10 20:00:00.000 UTC [${backend}] LOG:  duration: 0.100 ms  plan:`,
    ...JSON.stringify({ 'Query Text': text, Plan: { 'Shared Hit Blocks': pages, 'Shared Read Blocks': 0 } }, null, 1).split('\n').map((line) => `\t${line}`),
  ];
  return Object.entries(paths).flatMap(([path, statements]) => [plan(`/* sweep:measured:${path} */ SELECT 1`, 0), ...statements.map(([text, pages, backend]) => plan(text, pages, backend))])
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

test("a path whose run of a statement was a backend's first is not compared as grown, but reported unwarmed", () => {
  // At the smaller size, B warms backend 7 and A runs warm there; at the larger, A lands first on backend 8, which reads
  // the catalog, and B runs warm on 7 (review r3 of #559).
  const small = { 'GET /b': [[ACCESS, 1_295]], 'GET /a': [[ACCESS, 18]] };
  const large = { 'GET /a': [[ACCESS, 1_295, 8]], 'GET /b': [[ACCESS, 1_295], [ACCESS, 18]] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  assert.deepEqual(growing(before, after), []);
  assert.deepEqual(unwarmed(before, after).map(({ at, small, large }) => [at.path, small, large]), [['GET /a', true, false], ['GET /b', false, true]]);
});

test('a warm run grows though its first run on a backend read more', () => {
  const small = { 'GET /a': [[ACCESS, 1_295], [ACCESS, 18]] };
  const large = { 'GET /a': [[ACCESS, 1_295], [ACCESS, 400]] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  assert.deepEqual(growing(before, after).map(({ why, before, after }) => [why, before.pages, after.pages]), [['pages', 18, 400]]);
  assert.deepEqual(unwarmed(before, after), []);
});

test("an IN of parameters is one statement however long, so that a path's later runs of it are warm", () => {
  assert.equal(shapeOf('SELECT seq FROM audit_log WHERE seq IN ($1, $2, $3) AND actor = $4'), shapeOf('SELECT seq FROM audit_log WHERE seq IN ($1) AND actor = $2'));
  const small = { 'GET /audit': [['SELECT * FROM audit_log WHERE seq IN ($1, $2)', 5], ['SELECT * FROM audit_log WHERE seq IN ($1, $2, $3)', 5]] };
  const [before] = [small].map((paths) => statementsOf(plansOf(logOf(paths))));
  assert.deepEqual([...before.values()].map(({ warm, runs }) => [warm, runs]), [[true, 2]]);
});
