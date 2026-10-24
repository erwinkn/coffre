import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { checkContext, encodeAad, ownerKey, type SecretContext } from '../src/context.ts';
import { decrypt, encrypt, ENVELOPE_VERSION, open, seal, type Envelope } from '../src/envelope.ts';
import { deriveKey, seal as sealValue, unseal } from '../src/identity/signin/sealed.ts';
import { awsKms } from '../src/kek/aws-kms.ts';
import { LocalKekProvider } from '../src/kek/local.ts';
import { KekRegistry } from '../src/kek/registry.ts';
import { KekBadClaimError } from '../src/kek/types.ts';
import { PEOPLE, uuid } from '../../../scripts/properties/domain.ts';
import { propertySettings } from './properties.ts';

// `seal` draws its data key and IVs from the host's generator, which no
// caller can inject. Vault keys, the data keys `encrypt` takes and the
// sign-in secrets are Hegel's.

const key = gs.binary({ minSize: 32, maxSize: 32 }).map((bytes) => Buffer.from(bytes));
const member = gs.oneOf(gs.sampledFrom(PEOPLE), gs.text({ codec: 'utf-8', maxSize: 16 }).map((name) => `user:${name}`));
const context = gs.composite((tc): SecretContext => {
  const ctx: SecretContext = { projectId: tc.draw(uuid), environmentId: tc.draw(uuid), secretId: tc.draw(uuid) };
  const owner = tc.draw(gs.optional(member));
  if (owner !== null) ctx.owner = ownerKey(owner);
  if (tc.draw(gs.booleans())) ctx.sensitive = true;
  return ctx;
});
/** Empty, short, or a repeated pattern up to 64 KiB: Hegel shrinks the pattern and the length, not 64 KiB of draws. */
const plaintext = gs.oneOf(
  gs.binary({ maxSize: 64 }).map((bytes) => Buffer.from(bytes)),
  gs.composite((tc) => Buffer.alloc(
    tc.draw(gs.integers({ minValue: 1024, maxValue: 65_536 })),
    Buffer.from(tc.draw(gs.binary({ minSize: 1, maxSize: 16 }))),
  )),
);

type Mutation = { kind: 'flip'; at: number; bit: number } | { kind: 'truncate'; keep: number } | { kind: 'extend'; extra: Uint8Array };
const mutation = gs.oneOf<Mutation>(
  gs.record({ kind: gs.just('flip' as const), at: gs.integers({ minValue: 0, maxValue: 1 << 20 }), bit: gs.integers({ minValue: 0, maxValue: 7 }) }),
  gs.record({ kind: gs.just('truncate' as const), keep: gs.integers({ minValue: 0, maxValue: 1 << 20 }) }),
  gs.record({ kind: gs.just('extend' as const), extra: gs.binary({ minSize: 1, maxSize: 16 }) }),
);
/** Always a different byte string: an empty one can only grow. */
function mutate(bytes: Buffer, change: Mutation): Buffer {
  if (change.kind === 'extend' || bytes.length === 0) return Buffer.concat([bytes, change.kind === 'extend' ? change.extra : Buffer.of(0)]);
  if (change.kind === 'truncate') return bytes.subarray(0, change.keep % bytes.length);
  const flipped = Buffer.from(bytes);
  flipped[change.at % flipped.length]! ^= 1 << change.bit;
  return flipped;
}

/** The context's three ids, as the value's own ciphertext binds them (context.ts). */
function sameIds(a: SecretContext, b: SecretContext): boolean {
  return a.projectId === b.projectId && a.environmentId === b.environmentId && a.secretId === b.secretId;
}
/** Everything the wrap of a data key binds: the ids, the owner and sensitivity, absent and undefined alike. */
function sameContext(a: SecretContext, b: SecretContext): boolean {
  return sameIds(a, b) && a.owner === b.owner && (a.sensitive === true) === (b.sensitive === true);
}

/** `ctx` moved: one to three fields changed, ids to fresh ones or to one of its other ids, an owner added, removed or changed, sensitivity toggled. */
function relocate(tc: hegel.TestCase, ctx: SecretContext): SecretContext {
  const fields = new Set(tc.draw(gs.arrays(gs.sampledFrom(['projectId', 'environmentId', 'secretId', 'owner', 'sensitive'] as const), { minSize: 1, maxSize: 3 })));
  const moved = { ...ctx };
  for (const field of fields) {
    if (field === 'sensitive') {
      if (moved.sensitive) delete moved.sensitive;
      else moved.sensitive = true;
    } else if (field === 'owner') {
      if (ctx.owner !== undefined && tc.draw(gs.booleans())) delete moved.owner;
      else moved.owner = tc.draw(member.map(ownerKey).filter((owner) => owner !== ctx.owner));
    } else {
      moved[field] = tc.draw(gs.oneOf(uuid, gs.sampledFrom([ctx.projectId, ctx.environmentId, ctx.secretId])).filter((id) => id !== ctx[field]));
    }
  }
  assert.equal(sameContext(ctx, moved), false);
  return moved;
}

function unwrapOf(envelope: Envelope, ctx: SecretContext, keks: KekRegistry): Promise<Buffer> {
  return keks.unwrap({ kekProvider: envelope.kekProvider, kekId: envelope.kekId, kekVersion: envelope.kekVersion, bytes: envelope.wrappedDek }, ctx);
}

const ARN = 'arn:aws:kms:eu-west-3:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const CREDENTIALS = { accessKeyId: 'AKIAEXAMPLE123', secretAccessKey: 'abc/def+ghi' };

/** KMS as its API documents it: a ciphertext opens only under the exact encryption context it was made with, whatever the order of its pairs. */
function fakeKms() {
  const blobs = new Map<string, { plaintext: string; context: string }>();
  const contexts: Record<string, string>[] = [];
  const canonical = (context: Record<string, string>) => JSON.stringify(Object.entries(context).sort(([a], [b]) => (a < b ? -1 : 1)));
  const fetch = async (_: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(String(init?.body)) as { CiphertextBlob?: string; Plaintext?: string; EncryptionContext: Record<string, string> };
    contexts.push(body.EncryptionContext);
    if (new Headers(init?.headers).get('x-amz-target') === 'TrentService.Encrypt') {
      const blob = Buffer.from(String(blobs.size)).toString('base64');
      blobs.set(blob, { plaintext: body.Plaintext!, context: canonical(body.EncryptionContext) });
      return Response.json({ CiphertextBlob: blob, KeyId: ARN });
    }
    const stored = blobs.get(body.CiphertextBlob!);
    if (stored === undefined || stored.context !== canonical(body.EncryptionContext)) {
      return Response.json({ __type: 'InvalidCiphertextException' }, { status: 400 });
    }
    return Response.json({ Plaintext: stored.plaintext, KeyId: ARN });
  };
  return { fetch: fetch as typeof globalThis.fetch, contexts, canonical };
}

const roundTrip = propertySettings(48);
test(`any value sealed under any context opens under it, and decrypts under its data key, seed ${roundTrip.seed}`, () => hegel.testAsync(async (tc) => {
  const keks = new KekRegistry(new LocalKekProvider(tc.draw(key), 'kek-a', tc.draw(gs.sampledFrom(['1', '2']))));
  const ctx = tc.draw(context);
  const value = tc.draw(plaintext);
  const envelope = await seal(value, ctx, keks);
  assert.deepEqual(
    [envelope.envelopeVersion, envelope.kekProvider, envelope.kekId, envelope.kekVersion],
    [ENVELOPE_VERSION, 'local', 'kek-a', keks.primary.keyVersion],
  );
  assert.deepEqual(await open(envelope, ctx, keks), value);
  assert.deepEqual(decrypt(envelope, ctx, await unwrapOf(envelope, ctx, keks)), value);
  const dek = tc.draw(key);
  const sealed = encrypt(value, ctx, dek);
  assert.equal(sealed.ciphertext.length, value.length);
  assert.deepEqual(decrypt(sealed, ctx, dek), value);
}, roundTrip));

const mutations = propertySettings(48);
test(`an envelope with any stored byte string or key claim changed fails to open, seed ${mutations.seed}`, () => hegel.testAsync(async (tc) => {
  const keks = new KekRegistry(new LocalKekProvider(tc.draw(key), 'kek-a'));
  const ctx = tc.draw(context);
  const value = tc.draw(plaintext);
  const envelope = await seal(value, ctx, keks);
  for (const field of ['iv', 'authTag', 'ciphertext', 'wrappedDek'] as const) {
    const changed = { ...envelope, [field]: mutate(envelope[field], tc.draw(mutation)) };
    assert.notDeepEqual(changed[field], envelope[field]);
    await assert.rejects(open(changed, ctx, keks), `${field} changed`);
  }
  for (const field of ['kekProvider', 'kekId', 'kekVersion'] as const) {
    const claimed = tc.draw(gs.text({ maxSize: 12 }));
    await assert.rejects(open({ ...envelope, [field]: claimed === envelope[field] ? `${claimed}\0` : claimed }, ctx, keks), `${field} claimed`);
  }
  const version = tc.draw(gs.integers({ minValue: -1, maxValue: 1_000 }));
  await assert.rejects(open({ ...envelope, envelopeVersion: version === ENVELOPE_VERSION ? version + 1 : version }, ctx, keks), /unsupported envelope version/);
  // Nothing above touched the original.
  assert.deepEqual(await open(envelope, ctx, keks), value);
}, mutations));

const relocation = propertySettings(64);
test(`an envelope opens under no other context, while its value decrypts under any context with the same ids, seed ${relocation.seed}`, () => hegel.testAsync(async (tc) => {
  const keks = new KekRegistry(new LocalKekProvider(tc.draw(key), 'kek-a'));
  const ctx = tc.draw(context);
  const value = Buffer.from(tc.draw(gs.binary({ maxSize: 64 })));
  const envelope = await seal(value, ctx, keks);
  const dek = await unwrapOf(envelope, ctx, keks);
  const moved = relocate(tc, ctx);
  tc.note(`moved to ${JSON.stringify(moved)}`);
  await assert.rejects(open(envelope, moved, keks));
  await assert.rejects(unwrapOf(envelope, moved, keks), KekBadClaimError);
  // The value's own ciphertext binds the ids alone, so a version made
  // sensitive keeps its ciphertext (context.ts): only the wrap refuses.
  if (sameIds(ctx, moved)) assert.deepEqual(decrypt(envelope, moved, dek), value);
  else assert.throws(() => decrypt(envelope, moved, dek));
}, relocation));

/** Two contexts from a few ids, owners and sensitivities, so they often agree on some fields and sometimes on all. */
const contextPair = gs.composite((tc) => {
  const ids = [tc.draw(uuid), tc.draw(uuid), tc.draw(uuid)];
  const owners = [ownerKey(tc.draw(member)), ownerKey(tc.draw(member))];
  const one = () => {
    const ctx: SecretContext = { projectId: tc.draw(gs.sampledFrom(ids)), environmentId: tc.draw(gs.sampledFrom(ids)), secretId: tc.draw(gs.sampledFrom(ids)) };
    const owner = tc.draw(gs.sampledFrom([undefined, 'absent', ...owners]));
    if (owner !== 'absent') ctx.owner = owner;
    if (tc.draw(gs.booleans())) ctx.sensitive = true;
    return ctx;
  };
  return [one(), one()] as const;
});

const injective = propertySettings(128);
test(`two contexts encode to the same AAD exactly when they are the same context, seed ${injective.seed}`, () => hegel.test((tc) => {
  const [a, b] = tc.draw(contextPair);
  assert.equal(encodeAad(a).equals(encodeAad(b)), sameContext(a, b));
  const ids = ({ projectId, environmentId, secretId }: SecretContext) => encodeAad({ projectId, environmentId, secretId });
  assert.equal(ids(a).equals(ids(b)), sameIds(a, b));
}, injective));

const HEX = '0123456789abcdef';
/** A lowercase UUID, as the AAD requires it: groups of 8, 4, 4, 4 and 12 lowercase hex digits. */
function isUuid(id: unknown): boolean {
  return typeof id === 'string' && id.split('-').map((group) => group.length).join() === '8,4,4,4,12' && [...id.replaceAll('-', '')].every((char) => HEX.includes(char));
}
function isOwner(owner: unknown): boolean {
  return typeof owner === 'string' && owner.length === 64 && [...owner].every((char) => HEX.includes(char));
}
const ODD = [' ', '\t', '\n', '\r', ' ', '﻿', '-', '|', '{', '}', 'g', 'G', 'A', 'F', '0', 'f', '\0', 'é'];
/** Strings one edit from `valid`: a character uppercased, replaced, inserted or removed, or the whole padded. */
const near = (valid: gs.Generator<string>) => gs.oneOf(
  valid,
  gs.composite((tc) => {
    const base = tc.draw(valid);
    const at = tc.draw(gs.integers({ minValue: 0, maxValue: base.length - 1 }));
    const char = tc.draw(gs.sampledFrom(ODD));
    switch (tc.draw(gs.sampledFrom(['upper', 'replace', 'insert', 'remove', 'pad-start', 'pad-end'] as const))) {
      case 'upper': return base.toUpperCase();
      case 'replace': return base.slice(0, at) + char + base.slice(at + 1);
      case 'insert': return base.slice(0, at) + char + base.slice(at);
      case 'remove': return base.slice(0, at) + base.slice(at + 1);
      case 'pad-start': return char + base;
      case 'pad-end': return base + char;
    }
  }),
  gs.text({ maxSize: 70 }),
);
const nearUuid = gs.oneOf<unknown>(near(uuid), gs.sampledFrom([undefined, null, 0, '']));
const nearOwner = gs.oneOf<unknown>(near(member.map(ownerKey)), member, gs.sampledFrom([undefined, null, 0, '']));

const validation = propertySettings(128);
test(`a context is refused unless its ids are lowercase UUIDs, its owner a lowercase SHA-256 and sensitive true or absent, seed ${validation.seed}`, () => hegel.testAsync(async (tc) => {
  const ctx = tc.draw(context) as Record<string, unknown>;
  const field = tc.draw(gs.sampledFrom(['projectId', 'environmentId', 'secretId', 'owner', 'sensitive'] as const));
  const candidate = tc.draw(field === 'owner' ? nearOwner : field === 'sensitive' ? gs.sampledFrom<unknown>([undefined, true, false, 'true', 1, null]) : nearUuid);
  if (candidate === undefined) delete ctx[field];
  else ctx[field] = candidate;
  tc.note(`${field} = ${JSON.stringify(candidate)}`);
  const valid = field === 'owner' ? candidate === undefined || isOwner(candidate)
    : field === 'sensitive' ? candidate === undefined || candidate === true
      : isUuid(candidate);
  const bad = ctx as SecretContext;
  if (valid) {
    checkContext(bad);
    encodeAad(bad);
    return;
  }
  assert.throws(() => checkContext(bad));
  assert.throws(() => encodeAad(bad));
  await assert.rejects(new LocalKekProvider(Buffer.alloc(32), 'kek-a').wrap(Buffer.alloc(32), bad));
  // A malformed context never reaches KMS.
  const kms = fakeKms();
  await assert.rejects(awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: kms.fetch }).wrap(Buffer.alloc(32), bad));
  assert.equal(kms.contexts.length, 0);
}, validation));

/** A seal; a new primary; a key dropped, unless primary; or a new primary and the old one dropped, as a rotation ends. */
type Step = { kind: 'seal'; context: number; value: Uint8Array } | { kind: 'rotate' | 'retire' | 'replace'; kek: number };
const KEKS = 4;
const step = gs.oneOf<Step>(
  gs.record({ kind: gs.just('seal' as const), context: gs.integers({ minValue: 0, maxValue: 1 }), value: gs.binary({ maxSize: 24 }) }),
  gs.record({ kind: gs.sampledFrom(['rotate', 'retire', 'replace'] as const), kek: gs.integers({ minValue: 0, maxValue: KEKS - 1 }) }),
);

const rotation = propertySettings(24);
test(`through any rotations, an envelope opens while its vault key is configured, fails loudly once it is not, and never opens claiming another, seed ${rotation.seed}`, () => hegel.testAsync(async (tc) => {
  // KEKs may share key material: the wrap binds each one's id and version too.
  const materials = tc.draw(gs.arrays(key, { minSize: 1, maxSize: KEKS }));
  const providers = Array.from({ length: KEKS }, (_, i) => new LocalKekProvider(
    materials[tc.draw(gs.integers({ minValue: 0, maxValue: materials.length - 1 }))]!,
    `kek-${i}`,
    tc.draw(gs.sampledFrom(['1', '2'])),
  ));
  const contexts = [tc.draw(context), tc.draw(context)];
  const steps = tc.draw(gs.arrays(step, { minSize: 1, maxSize: 12 }));
  let primary = 0;
  const configured = new Set([0]);
  const sealed: { envelope: Envelope; kek: number; ctx: SecretContext; value: Buffer }[] = [];
  for (const each of steps) {
    const keks = () => new KekRegistry(providers[primary]!, [...configured].filter((kek) => kek !== primary).map((kek) => providers[kek]!));
    if (each.kind === 'seal') {
      const value = Buffer.from(each.value);
      const ctx = contexts[each.context]!;
      const envelope = await seal(value, ctx, keks());
      assert.equal(envelope.kekId, `kek-${primary}`);
      sealed.push({ envelope, kek: primary, ctx, value });
    } else if (each.kind === 'rotate' || each.kind === 'replace') {
      if (each.kind === 'replace' && each.kek !== primary) configured.delete(primary);
      configured.add(each.kek);
      primary = each.kek;
    } else if (each.kek !== primary) {
      configured.delete(each.kek);
    }
    const registry = keks();
    for (const { envelope, kek, ctx, value } of sealed) {
      if (configured.has(kek)) assert.deepEqual(await open(envelope, ctx, registry), value);
      else await assert.rejects(open(envelope, ctx, registry), /no vault key configured for local:kek-\d/);
      for (const other of configured) {
        if (other === kek) continue;
        const claim = providers[other]!;
        await assert.rejects(open({ ...envelope, kekId: claim.keyId, kekVersion: claim.keyVersion }, ctx, registry), KekBadClaimError);
      }
    }
  }
}, rotation));

const kmsContext = propertySettings(32);
test(`the KMS encryption context names the secret's ids, owner and sensitivity, and binds exactly what the local wrap does, seed ${kmsContext.seed}`, () => hegel.testAsync(async (tc) => {
  const kms = fakeKms();
  const kek = awsKms({ keyArn: ARN, credentials: CREDENTIALS, fetch: kms.fetch });
  const local = new LocalKekProvider(tc.draw(key), 'kek-a');
  const [a, b] = tc.draw(contextPair);
  const dek = tc.draw(key);
  const wrapped = await kek.wrap(dek, a);
  // docs/keys.md and docs/design/credential-proxy.md, section 2.
  assert.deepEqual(kms.contexts[0], {
    'coffre:project': a.projectId,
    'coffre:environment': a.environmentId,
    'coffre:secret': a.secretId,
    ...(a.owner === undefined ? {} : { 'coffre:owner': a.owner }),
    ...(a.sensitive ? { 'coffre:sensitive': 'true' } : {}),
  });
  const locally = await local.wrap(dek, a);
  if (sameContext(a, b)) {
    assert.deepEqual(await kek.unwrap(wrapped, b), dek);
    assert.deepEqual(await local.unwrap(locally, b), dek);
  } else {
    await assert.rejects(kek.unwrap(wrapped, b), KekBadClaimError);
    await assert.rejects(local.unwrap(locally, b), KekBadClaimError);
  }
  assert.equal(kms.canonical(kms.contexts[1]!) === kms.canonical(kms.contexts[0]!), encodeAad(a).equals(encodeAad(b)));
}, kmsContext));

/** A small JSON value, as a sign-in cookie carries. Integers only: JSON writes -0 as 0. */
const scalar = gs.oneOf<unknown>(gs.just(null), gs.booleans(), gs.integers({ minValue: -(2 ** 53) + 1, maxValue: 2 ** 53 - 1 }), gs.text({ codec: 'utf-8', maxSize: 16 }));
const object = (inner: gs.Generator<unknown>) => gs.arrays(gs.tuples(gs.text({ codec: 'utf-8', maxSize: 8 }), inner), { maxSize: 4 }).map((pairs) => Object.fromEntries(pairs));
const json = gs.oneOf<unknown>(scalar, gs.arrays(scalar, { maxSize: 4 }), object(gs.oneOf<unknown>(scalar, gs.arrays(scalar, { maxSize: 3 }), object(scalar))));
const purpose = gs.text({ codec: 'utf-8', maxSize: 24 });

const sealedSettings = propertySettings(128);
test(`a sealed value opens under its key until its expiry, exclusive, and to null under another key or once its string is changed, seed ${sealedSettings.seed}`, () => hegel.test((tc) => {
  const secret = Buffer.from(tc.draw(gs.binary({ minSize: 1, maxSize: 64 })));
  const name = tc.draw(purpose);
  const value = tc.draw(json);
  const ttl = tc.draw(gs.integers({ minValue: -10, maxValue: 10_000_000 }));
  const issued = tc.draw(gs.integers({ minValue: 0, maxValue: 4_000_000_000_000 }));
  const sealed = sealValue(deriveKey(secret, name), value, ttl, issued);
  // `exp` is issued + ttl seconds, and a value is expired from `exp` on (`parsed.exp <= now`).
  const expiry = issued + ttl * 1000;
  const at = expiry + tc.draw(gs.oneOf(gs.sampledFrom([-1, 0, 1]), gs.integers({ minValue: -1e10, maxValue: 1e10 })));
  assert.deepEqual(unseal(deriveKey(secret, name), sealed, at), at < expiry ? value : null);

  const before = expiry - 1;
  const other = tc.draw(purpose.filter((each) => each !== name));
  assert.equal(unseal(deriveKey(secret, other), sealed, before), null, 'another purpose');
  const otherSecret = Buffer.from(tc.draw(gs.binary({ minSize: 1, maxSize: 64 }).filter((each) => !secret.equals(each))));
  assert.equal(unseal(deriveKey(otherSecret, name), sealed, before), null, 'another secret');

  const raw = Buffer.from(sealed.slice('v1.'.length), 'base64url');
  assert.equal(unseal(deriveKey(secret, name), `v1.${mutate(raw, tc.draw(mutation)).toString('base64url')}`, before), null, 'bytes changed');
  const at2 = tc.draw(gs.integers({ minValue: 0, maxValue: sealed.length }));
  const char = tc.draw(gs.oneOf(gs.sampledFrom([...'AQgw_-=. \n!+/']), gs.characters()));
  const spelled = tc.draw(gs.sampledFrom([
    sealed.slice(0, at2) + char + sealed.slice(at2),
    sealed.slice(0, at2) + char + sealed.slice(at2 + 1),
    sealed.slice(0, at2) + sealed.slice(at2 + 1),
  ]));
  if (spelled !== sealed) assert.equal(unseal(deriveKey(secret, name), spelled, before), null, `spelled ${JSON.stringify(spelled)}`);
}, sealedSettings));
