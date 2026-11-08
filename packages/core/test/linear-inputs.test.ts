// What a request's strings and lists cost, now that no field has a length of its own: a string a request turns into
// a list is counted before it is split, a list is read by its neighbours rather than every pair, and each answer is
// held to what the old, quadratic code answered.
import test from 'node:test';
import assert from 'node:assert/strict';

import { checkConstraints, ConstraintsInvalid, intersect } from '@coffre/core/identity';
import { parseScopes } from '@coffre/core/mcp';
import { MAX_BODY_NODES, splitAtMost } from '@coffre/core/schemas';

const cpu = <T>(run: () => T) => {
  const started = process.cpuUsage();
  const result = run();
  const spent = process.cpuUsage(started);
  return { result, ms: (spent.user + spent.system) / 1000 };
};

let seed = 3;
const random = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
const pick = <T>(items: readonly T[]) => items[Math.floor(random() * items.length)]!;

test('a string is split only once its parts are counted, and not past them', () => {
  assert.deepEqual(splitAtMost('a/b/c', '/', 3), ['a', 'b', 'c']);
  assert.equal(splitAtMost('a/b/c/d', '/', 3), null);
  assert.deepEqual(splitAtMost('', ' '), ['']);
  assert.deepEqual(splitAtMost('a::b::c', '::', 3), ['a', 'b', 'c']);
  assert.equal(splitAtMost('x'.repeat(10) + ' '.repeat(MAX_BODY_NODES), ' '), null);
  // A mebibyte of separators: counted to the cap, never split.
  const { result, ms } = cpu(() => splitAtMost('.'.repeat(1024 * 1024), '.'));
  assert.equal(result, null);
  assert.ok(ms < 5, `took ${ms} ms`);
});

test('scopes: past as many words as a body holds values, refused, never split into a set first', () => {
  const many = Array.from({ length: 120_000 }, (_, i) => `scope${i}`).join(' ');
  const { result, ms } = cpu(() => parseScopes(many));
  assert.deepEqual(result, { scopes: [], unknown: [`more than ${MAX_BODY_NODES} scopes`] });
  assert.ok(ms < 5, `took ${ms} ms`);
  assert.deepEqual(parseScopes('read write nope'), { scopes: ['read', 'write'], unknown: ['nope'] });
});

// What the constraints' paths were checked and reduced by before: every segment split, every pair compared.
const SEGMENT = /^[A-Za-z0-9\-_~!$&'()*+,=:@.]+$/;
const oldPrefix = (path: string) => path === '/' || (path.startsWith('/') && !path.endsWith('/') && path.slice(1).split('/').every((segment) => SEGMENT.test(segment) && segment !== '.' && segment !== '..'));
const under = (path: string, prefix: string) => prefix === '/' || path === prefix || path.startsWith(`${prefix}/`);
const oldOutermost = (paths: readonly string[]) => paths.filter((path) => !paths.some((other) => other !== path && under(path, other)));
const oldIntersect = (a: readonly string[], b: readonly string[]) => oldOutermost([...new Set([...b.filter((path) => a.some((prefix) => under(path, prefix))), ...a.filter((path) => b.some((prefix) => under(path, prefix)))])].sort());

const pieces = ['a', 'b', 'a-b', 'a.b', '.', '..', '...', '', '%', 'z~'];
const somePath = () => (random() < 0.08 ? '/' : `/${Array.from({ length: 1 + Math.floor(random() * 3) }, () => pick(pieces)).join('/')}${random() < 0.05 ? '/' : ''}`);

test("a constraint's path prefix is checked in one pass, as its segments one by one were", () => {
  for (let i = 0; i < 5000; i++) {
    const path = random() < 0.1 ? pick(['', 'a', '//a', '/a//b', '/./a', '/a/..', '/a/...']) : somePath();
    const valid = (() => {
      try {
        checkConstraints({ paths: [path] });
        return true;
      } catch (error) {
        assert.ok(error instanceof ConstraintsInvalid);
        return false;
      }
    })();
    assert.equal(valid, oldPrefix(path), path);
  }
});

test('the outermost of a list of paths, and two lists intersected, are what every pair compared made them, at a sort', () => {
  for (let i = 0; i < 3000; i++) {
    const a = [...new Set(Array.from({ length: Math.floor(random() * 6) }, somePath).filter(oldPrefix))].sort();
    const b = [...new Set(Array.from({ length: 1 + Math.floor(random() * 6) }, somePath).filter(oldPrefix))].sort();
    if (a.length > 0) assert.deepEqual(checkConstraints({ paths: a }).paths, oldOutermost(a), JSON.stringify(a));
    if (a.length > 0 && b.length > 0) {
      const parent = checkConstraints({ paths: a });
      const child = checkConstraints({ paths: b });
      assert.deepEqual(intersect(parent, child).paths, oldIntersect(parent.paths!, child.paths!), `${JSON.stringify(a)} ${JSON.stringify(b)}`);
    }
  }
  // Two lists as long as a body lets them be: a sort each, not every pair (which was 2.5 million comparisons).
  // Timed warm: the first call, not yet compiled, costs 17-22 ms on CI's runners and this host, about the wall
  // itself; warm it costs 6-8 ms, and every pair compared costs 165-200 ms.
  const wide = (tag: string) => Array.from({ length: 1500 }, (_, i) => `/${tag}${i % 40}/x${i}`);
  const both = () => intersect(checkConstraints({ paths: wide('a') }), checkConstraints({ paths: [...wide('a'), ...wide('b')].slice(0, 1500) }));
  both();
  const { ms } = cpu(both);
  assert.ok(ms < 20, `took ${ms} ms`);
});
