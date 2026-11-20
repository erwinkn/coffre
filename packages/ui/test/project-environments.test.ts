import test from 'node:test';
import assert from 'node:assert/strict';

import { listedEnvironments, type ProjectEnvironment } from '../src/lib/project-environments.ts';

const env = (
  slug: string,
  details: { archivedAt: string | null; secretCount: number } | null,
): ProjectEnvironment => ({ slug, name: slug, accessible: details !== null, details }) as ProjectEnvironment;

test('the Projects list drops an environment with no secret and counts it apart', () => {
  const { listed, empty } = listedEnvironments([
    env('prod', { archivedAt: null, secretCount: 5 }),
    env('dev', { archivedAt: null, secretCount: 0 }),
  ]);
  assert.deepEqual(listed.map((e) => e.slug), ['prod']);
  assert.equal(empty, 1);
});

test('an environment the caller cannot open stays: its count is unknown', () => {
  const { listed, empty } = listedEnvironments([env('prod', null)]);
  assert.deepEqual(listed.map((e) => e.slug), ['prod']);
  assert.equal(empty, 0);
});

test('an archived environment is neither listed nor counted as empty', () => {
  const { listed, empty } = listedEnvironments([
    env('old', { archivedAt: '2026-01-01T00:00:00Z', secretCount: 0 }),
    env('older', { archivedAt: '2026-01-01T00:00:00Z', secretCount: 3 }),
  ]);
  assert.deepEqual(listed, []);
  assert.equal(empty, 0);
});

test('all-empty is told apart from no environment', () => {
  const allEmpty = listedEnvironments([
    env('dev', { archivedAt: null, secretCount: 0 }),
    env('qa', { archivedAt: null, secretCount: 0 }),
  ]);
  assert.deepEqual([allEmpty.listed.length, allEmpty.empty], [0, 2]);
  assert.deepEqual(listedEnvironments([]), { listed: [], empty: 0 });
});
