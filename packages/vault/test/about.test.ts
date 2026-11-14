// `about` (src/vault.ts): the vault's configuration that is no secret, its
// vault keys and its signing keys' checks, from the configuration alone. The
// database under test throws on any use, so an answer that read it fails.
// workers.test.ts holds that, on Cloudflare, it opens no connection either.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

import { derivedSigningKey, keyCheckOf, type KekProvider } from '@coffre/core/kek';
import type { Database } from '@coffre/db';

import { resolveVaultConfig, type VaultConfig } from '../src/config.ts';
import { openLocalVault } from '../src/local.ts';
import { keyOf } from '../src/rows.ts';
import { openVault, prepareVault } from '../src/vault.ts';

const key = () => randomBytes(32);
const b64 = (bytes: Buffer) => bytes.toString('base64');

/** A database no call may touch. */
const untouchable = new Proxy({}, { get: (_, name) => { throw new Error(`about read the database (${String(name)})`); } }) as unknown as Database;

const owners = ['root@acme.example'];

function aboutOf(kek: VaultConfig['kek'], more: Pick<VaultConfig, 'previousKeks' | 'signingKey'> = {}) {
  return openLocalVault(untouchable, prepareVault(resolveVaultConfig({ kek, ...more, owners })), { wake: () => assert.fail('about wrote an entry') }).about();
}

/** A key service's KEK, as `awsKms(…)` makes one: its key never leaves it. */
const kms: KekProvider = {
  provider: 'aws-kms',
  keyId: 'arn:aws:kms:eu-west-3:111122223333:key/k7q2',
  keyVersion: '1',
  wrap: async () => assert.fail('about wraps nothing'),
  unwrap: async () => assert.fail('about unwraps nothing'),
};

test("a local vault key: its id, and the check of the signing key it stands for, the vault's only one", async () => {
  const current = key();
  assert.deepEqual(await aboutOf({ id: 'vault-2026-11', key: b64(current) }), {
    kek: { provider: 'local', id: 'vault-2026-11' },
    previous: [],
    checks: [keyCheckOf(derivedSigningKey(current))],
  });
});

test('after a rotation: the previous key by id, and its check after the current one, since the vault still verifies what it signed', async () => {
  const [current, old] = [key(), key()];
  const about = await aboutOf({ id: 'k2', key: b64(current) }, { previousKeks: [{ id: 'k1', key: b64(old) }] });
  assert.deepEqual(about, {
    kek: { provider: 'local', id: 'k2' },
    previous: [{ provider: 'local', id: 'k1' }],
    checks: [keyCheckOf(derivedSigningKey(current)), keyCheckOf(derivedSigningKey(old))],
  });
});

test('a key service and a signingKey: the check is of the signingKey, and no KEK has one, a previous local one but for its own', async () => {
  const [signing, old] = [key(), key()];
  assert.deepEqual(await aboutOf(kms, { signingKey: b64(signing) }), {
    kek: { provider: 'aws-kms', id: kms.keyId },
    previous: [],
    checks: [keyCheckOf(signing)],
  });
  // Moved from a local key to the key service: what the old key's signing key signed still verifies.
  const moved = await aboutOf(kms, { signingKey: b64(signing), previousKeks: [{ id: 'k1', key: b64(old) }] });
  assert.deepEqual(moved.checks, [keyCheckOf(signing), keyCheckOf(derivedSigningKey(old))]);
  assert.deepEqual(moved.previous, [{ provider: 'local', id: 'k1' }]);
});

test("a wrong key matches no check: another key, the vault key taken as its own signing key, or any other key derived from the seed", async () => {
  const current = key();
  const seed = derivedSigningKey(current);
  const { checks } = await aboutOf({ id: 'k', key: b64(current) });
  const { id, rows, entries } = keyOf(seed);
  for (const [what, wrong] of [['another key', key()], ['the vault key itself', current], ['the rows key', rows], ['the entries key', entries], ['the key id', id]] as const) {
    assert.ok(!checks.includes(keyCheckOf(wrong)), what);
  }
  // The check is none of the seed's other keys, nor the seed: it opens, signs and names nothing.
  for (const other of [seed, rows, entries, derivedSigningKey(seed)]) assert.notEqual(checks[0], other.toString('hex'));
  assert.match(checks[0]!, /^[0-9a-f]{64}$/);
});

test('each answer is a copy: a caller that changes one changes nothing the next is told', async () => {
  const prepared = prepareVault(resolveVaultConfig({ kek: { id: 'k', key: b64(key()) }, owners }));
  // In process, with no transport's JSON between: the vault's own answer.
  const vault = openVault(untouchable, prepared, { wake: () => {} });
  const first = await vault.about();
  first.checks.push('00');
  first.kek.id = 'other';
  assert.deepEqual(await vault.about(), prepared.about);
  assert.equal(prepared.about.checks.length, 1);
});
