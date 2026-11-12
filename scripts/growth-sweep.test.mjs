import assert from 'node:assert/strict';
import test from 'node:test';

import { growing, idOf, knownOf, listOf, notesOf, plansOf, shapeOf, statementsOf, unknownOf, unparsed, unwarmed, vanished } from './growth-sweep.mjs';

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
  const rows = (n) => `SELECT a.i FROM (SELECT 0 AS i, CAST($1 AS uuid) AS object${Array.from({ length: n - 1 }, (_, k) => ` UNION ALL SELECT ${k + 1}, CAST($${k + 2} AS uuid)`).join('')}) AS a`;
  assert.equal(shapeOf(rows(3)), shapeOf(rows(40)));
  const small = { 'GET /audit': [['SELECT * FROM audit_log WHERE seq IN ($1, $2)', 5], ['SELECT * FROM audit_log WHERE seq IN ($1, $2, $3)', 5]] };
  const [before] = [small].map((paths) => statementsOf(plansOf(logOf(paths))));
  assert.deepEqual([...before.values()].map(({ warm, runs }) => [warm, runs]), [[true, 2]]);
});

test('a plan cut short is counted, not dropped unseen', () => {
  const whole = logOf({ 'GET /a': [[ACCESS, 5], [ACCESS, 5]] });
  // The last plan's body cut after its first line, as an interleaved or truncated log leaves it.
  const lines = whole.split('\n');
  const last = lines.findLastIndex((line) => line.includes('plan:'));
  const cut = [...lines.slice(0, last + 2)].join('\n');
  assert.equal(unparsed(whole), 0);
  assert.equal(unparsed(cut), 1);
  assert.equal(plansOf(cut).length, plansOf(whole).length - 1);
});

test('the list of known growers names each statement of each path that grew, and reads back as the same', () => {
  const small = { 'GET /members': [[ACCESS, 20], [ACCESS, 20]], 'GET /audit': [[ACCESS, 20], [ACCESS, 20]] };
  const large = { 'GET /members': [[ACCESS, 400], [ACCESS, 400]], 'GET /audit': [[ACCESS, 400], [ACCESS, 400]] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  const grown = growing(before, after);
  const id = idOf(shapeOf(ACCESS));
  const first = listOf(grown, new Map());
  assert.deepEqual([...knownOf(first)].sort(), [`${id} GET /audit`, `${id} GET /members`]);
  assert.match(first, /# {3}from \?/);
  // A source written in by hand stays when the list is written again.
  const written = first.replace('#   from ?', '#   from packages/server/src/db/members.ts:12');
  assert.equal(listOf(grown, notesOf(written)), written);
  // Deleting a path's line leaves the other, whatever the comments and spaces around it.
  assert.deepEqual([...knownOf(`# a comment\n\n${id}   GET /members   # fixed elsewhere\n`)], [`${id} GET /members`]);
});

test('a statement the larger size alone ran fails the sweep, however few its pages, until the list names it', () => {
  const PRUNE = 'SELECT min(at) FROM log_uses WHERE number > $1';
  const small = { tick: [[ACCESS, 3], [ACCESS, 3]] };
  const large = { tick: [[ACCESS, 3], [ACCESS, 3], [PRUNE, 3], [PRUNE, 3]] };
  const [before, after] = [small, large].map((paths) => statementsOf(plansOf(logOf(paths))));
  const grown = growing(before, after);
  assert.deepEqual(grown.map(({ why, after }) => [why, after.path, after.pages]), [['new', 'tick', 3]]);
  assert.deepEqual(unknownOf(grown, null), grown);
  assert.deepEqual(unknownOf(grown, knownOf('')), grown);
  const list = listOf(grown, new Map());
  assert.ok(list.includes(`${idOf(shapeOf(PRUNE))} tick`));
  assert.deepEqual(unknownOf(grown, knownOf(list)), []);
});
