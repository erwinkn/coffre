import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { seal, open, ENVELOPE_VERSION } from '../src/envelope.ts';
import { encodeAad, type SecretContext } from '../src/context.ts';
import { LocalKekProvider } from '../src/kek/local.ts';
import { KekRegistry } from '../src/kek/registry.ts';

/**
 * A project with two environments, standing in for dev and prod. The secret id
 * is the same in both, which is the realistic shape: the same logical key
 * ("DATABASE_URL") existing in more than one environment.
 */
function fixture() {
  const projectId = randomUUID();
  const secretId = randomUUID();

  const dev: SecretContext = { projectId, environmentId: randomUUID(), secretId };
  const prod: SecretContext = { projectId, environmentId: randomUUID(), secretId };

  const keks = new KekRegistry(LocalKekProvider.generate('kek-test-1'));
  return { dev, prod, keks, projectId, secretId };
}

test('seal then open round-trips the plaintext', async () => {
  const { dev, keks } = fixture();
  const plaintext = Buffer.from('postgres://user:pw@host/db', 'utf8');

  const envelope = await seal(plaintext, dev, keks);
  assert.equal(envelope.envelopeVersion, ENVELOPE_VERSION);

  const opened = await open(envelope, dev, keks);
  assert.deepEqual(opened, plaintext);
});

test('ciphertext is not the plaintext and a fresh DEK is used per seal', async () => {
  const { dev, keks } = fixture();
  const plaintext = Buffer.from('same value both times', 'utf8');

  const a = await seal(plaintext, dev, keks);
  const b = await seal(plaintext, dev, keks);

  assert.notDeepEqual(a.ciphertext, plaintext);
  // Identical plaintext under a fresh DEK and IV must not produce identical
  // ciphertext, or the store would leak which secrets share a value.
  assert.notDeepEqual(a.ciphertext, b.ciphertext);
  assert.notDeepEqual(a.wrappedDek, b.wrappedDek);
});

test('a ciphertext written for dev fails to decrypt as prod', async () => {
  const { dev, prod, keks } = fixture();

  const envelope = await seal(Buffer.from('dev-only-value', 'utf8'), dev, keks);

  // Simulate an attacker (or a bug) relocating the stored row from the dev
  // environment to the prod environment. Every stored byte is carried over
  // verbatim; only the context used to read it changes.
  await assert.rejects(
    () => open(envelope, prod, keks),
    /Unsupported state or unable to authenticate data|wrapped DEK/,
    'relocating a ciphertext across environments must fail closed',
  );
});

test('a ciphertext is bound to its project and its secret id, not just its environment', async () => {
  const { dev, keks } = fixture();
  const envelope = await seal(Buffer.from('bound', 'utf8'), dev, keks);

  const otherProject = { ...dev, projectId: randomUUID() };
  const otherSecret = { ...dev, secretId: randomUUID() };

  await assert.rejects(() => open(envelope, otherProject, keks));
  await assert.rejects(() => open(envelope, otherSecret, keks));
});

test('tampering with the ciphertext is detected', async () => {
  const { dev, keks } = fixture();
  const envelope = await seal(Buffer.from('do-not-modify', 'utf8'), dev, keks);

  envelope.ciphertext[0] ^= 0xff;

  await assert.rejects(() => open(envelope, dev, keks));
});

test('tampering with the wrapped DEK is detected', async () => {
  const { dev, keks } = fixture();
  const envelope = await seal(Buffer.from('do-not-modify', 'utf8'), dev, keks);

  envelope.wrappedDek[envelope.wrappedDek.length - 1] ^= 0xff;

  await assert.rejects(() => open(envelope, dev, keks));
});

test('a wrapped DEK cannot be lifted onto another environment row', async () => {
  const { dev, prod, keks } = fixture();

  const devEnvelope = await seal(Buffer.from('dev', 'utf8'), dev, keks);
  const prodEnvelope = await seal(Buffer.from('prod', 'utf8'), prod, keks);

  // Swap only the wrapped DEK across the two rows. This is the attack the
  // wrap-level AAD exists to stop: without it, the DEK would unwrap fine and
  // only the outer GCM tag would object.
  const spliced = { ...prodEnvelope, wrappedDek: devEnvelope.wrappedDek };

  await assert.rejects(() => open(spliced, prod, keks));
});

test('AAD encoding rejects anything that is not a UUID', () => {
  const valid = randomUUID();

  assert.throws(
    () => encodeAad({ projectId: 'prod', environmentId: valid, secretId: valid }),
    /projectId must be a lowercase UUID/,
  );
  assert.throws(
    () => encodeAad({ projectId: valid, environmentId: '', secretId: valid }),
    /environmentId must be a lowercase UUID/,
  );
});

test('AAD encoding is injective across the three fields', () => {
  const a = randomUUID();
  const b = randomUUID();
  const c = randomUUID();

  // Permuting the same three ids must produce different AAD, or a secret could
  // be confused with a project.
  const one = encodeAad({ projectId: a, environmentId: b, secretId: c });
  const two = encodeAad({ projectId: b, environmentId: a, secretId: c });

  assert.notDeepEqual(one, two);
});

test('rotation: a new primary KEK seals new rows while old rows still open', async () => {
  const { dev } = fixture();

  const oldKek = LocalKekProvider.generate('kek-2025');
  const newKek = LocalKekProvider.generate('kek-2026');

  const before = new KekRegistry(oldKek);
  const sealedUnderOld = await seal(Buffer.from('written-last-year', 'utf8'), dev, before);
  assert.equal(sealedUnderOld.kekId, 'kek-2025');

  // Rotate: the new KEK becomes primary, the old one stays readable.
  const after = new KekRegistry(newKek, [oldKek]);

  const sealedUnderNew = await seal(Buffer.from('written-today', 'utf8'), dev, after);
  assert.equal(sealedUnderNew.kekId, 'kek-2026');

  assert.deepEqual(
    await open(sealedUnderOld, dev, after),
    Buffer.from('written-last-year', 'utf8'),
  );
});

test('removing a KEK that rows still reference fails loudly', async () => {
  const { dev } = fixture();

  const retired = LocalKekProvider.generate('kek-retired');
  const sealed = await seal(Buffer.from('v', 'utf8'), dev, new KekRegistry(retired));

  const withoutIt = new KekRegistry(LocalKekProvider.generate('kek-current'));

  await assert.rejects(
    () => open(sealed, dev, withoutIt),
    /no vault key configured for local:kek-retired/,
  );
});
