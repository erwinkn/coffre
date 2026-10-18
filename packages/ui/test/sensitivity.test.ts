import test from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient, SecretKey } from '@coffre/client';

import { saveSecrets } from '../src/lib/changes.ts';
import { markable, stricter, waitsForValue } from '../src/lib/sensitivity.ts';

function listed(key: string, sensitivity: SecretKey['sensitivity'], more: Partial<SecretKey> = {}): SecretKey {
  return {
    key, reference: null, folder: null, archived: false, version: 1, versionId: `${key}-v1`, updatedAt: null, updatedBy: null,
    generated: null, parent: null, value: sensitivity === 'plain' ? 'acct_42' : null, sensitivity, ...more,
  };
}

const mark = (key: string, sensitivity: SecretKey['sensitivity'] & {}) => ({ key, value: null, archived: false, sensitivity });

test('loosest first: plain, secret, sensitive', () => {
  assert.equal(stricter('sensitive', 'secret'), true);
  assert.equal(stricter('secret', 'plain'), true);
  assert.equal(stricter('plain', 'sensitive'), false);
  assert.equal(stricter('secret', 'secret'), false);
});

test("a mark takes only a key's own value: not a reference's, nor one a fork inherits", () => {
  assert.equal(markable(listed('STRIPE_KEY', 'secret')), true);
  assert.equal(markable(listed('STRIPE_KEY', 'secret', { parent: { from: 'prod', state: 'overridden', held: true, changed: false, reset: false } })), true);
  assert.equal(markable(listed('STRIPE_KEY', 'secret', { parent: { from: 'prod', state: 'inherited', held: true, changed: false, reset: false } })), false);
  assert.equal(markable(listed('STRIPE_KEY', null, { reference: { source: 'billing/prod/STRIPE_KEY' } as SecretKey['reference'] })), false);
  assert.equal(markable(listed('EMPTY', null, { version: null })), false);
});

test('a level changed alone waits for a value where it loosens, or where no value of its own is there to mark', () => {
  const key = listed('STRIPE_KEY', 'secret');
  assert.equal(waitsForValue(key, mark('STRIPE_KEY', 'sensitive')), false);
  assert.equal(waitsForValue(key, mark('STRIPE_KEY', 'plain')), true);
  assert.equal(waitsForValue(key, { ...mark('STRIPE_KEY', 'plain'), value: 'typed' }), false);
  const inherited = listed('STRIPE_KEY', 'secret', { parent: { from: 'prod', state: 'inherited', held: true, changed: false, reset: false } });
  assert.equal(waitsForValue(inherited, mark('STRIPE_KEY', 'sensitive')), true);
  assert.equal(waitsForValue(key, undefined), false);
});

test('a save shows at once who sees each value: a mark hides a plain one, a plain write shows it, a sensitive stays so', () => {
  const entries = [listed('ACCOUNT', 'plain'), listed('REGION', 'secret'), listed('STRIPE_KEY', 'sensitive')];
  const shown = saveSecrets({} as CoffreClient, { project: 'market', environment: 'prod' }, 'ada@acme.example').apply(entries, {
    active: entries,
    drafts: [{ id: 1, key: 'NEW', value: 'n', sensitivity: 'sensitive' }],
    changes: {
      ACCOUNT: mark('ACCOUNT', 'secret'),
      REGION: { key: 'REGION', value: 'eu', archived: false, sensitivity: 'plain' },
      STRIPE_KEY: { key: 'STRIPE_KEY', value: 'sk_2', archived: false, sensitivity: 'sensitive' },
    },
  });
  const by = Object.fromEntries(shown.map((entry) => [entry.key, [entry.sensitivity, entry.value, entry.version]]));
  assert.deepEqual(by, {
    NEW: ['sensitive', null, 1],
    ACCOUNT: ['secret', null, 2],
    REGION: ['plain', 'eu', 2],
    STRIPE_KEY: ['sensitive', null, 2],
  });
});
