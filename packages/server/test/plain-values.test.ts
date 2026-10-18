// Plain values (docs/design/credential-proxy.md, section 2): a key marked
// not secret, an account's id, lists as it is to whoever reads its
// environment, reads with no `secret.read` and no vault call, and reaches a
// person's app as it is under stand-ins. A value is a secret unless its
// write says otherwise, so writing over a plain one without saying so makes
// it a secret again. Making a stored secret plain is a reveal of it, which
// stand-ins refuse a person, then a plain write of what it showed.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createClient, type CoffreClient } from '@coffre/client';
import { eq } from 'drizzle-orm';

import { clientFor } from './api-fixture.ts';
import { db, deps, DEV, entries, ORIGIN, ROOT, route, runtime, sessionFor, useMcp } from './mcp-fixture.ts';
import { environments, secrets, secretVersions } from './db/tables.ts';
import { coffreRoute } from '../src/app.ts';
import { checkPlugins } from '../src/plugins.ts';
import { basic, credentialProxy, header, sigv4 } from '../src/plugins/credential-proxy.ts';

const SID = 'AC0123456789abcdef';
const TOKEN = 'twilio_real_token_0123456789';
const FORKER = 'fork@acme.example';

/** A fake Twilio: it checks Basic, and quotes the account back, as Twilio's answers do. */
let upstream: Server;
let upstreamUrl: string;

before(async () => {
  upstream = createServer((request, response) => {
    const sent = Buffer.from((request.headers.authorization ?? '').replace(/^Basic /, ''), 'base64').toString();
    response.writeHead(sent === `${SID}:${TOKEN}` || !request.url!.startsWith('/twilio') ? 200 : 401, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ account_sid: SID, uri: request.url, echoed: sent, account: request.headers['x-account'] ?? null }));
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

let root: CoffreClient;

useMcp(
  async () => {
    runtime.plugins = checkPlugins([credentialProxy({
      credentials: {
        twilio: { upstream: `${upstreamUrl}/twilio`, inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}'), paths: ['/Accounts'] },
        account: { upstream: `${upstreamUrl}/account`, inject: header('x-account', '{ACCOUNT_ID}') },
        s3: { upstream: `${upstreamUrl}/s3`, inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
      },
      insecureUpstreams: true,
    })]);
    root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.members.add(`user:${FORKER}`);
    await root.members.add('token:ci');
    await root.projects.create('market');
    await root.environments.create('market/dev');
    await root.secrets.set('market/dev', { TWILIO_SID: { value: SID, plain: true }, TWILIO_TOKEN: TOKEN, REGION: { value: 'eu-west-3', plain: true } });
    await root.environments.create('market/other');
    await root.secrets.set('market/other', {
      ACCOUNT_ID: { value: 'acct_public_42', plain: true },
      AWS_ACCESS_KEY_ID: { value: 'AKIAPLAINBUTNEEDED', plain: true },
      AWS_SECRET_ACCESS_KEY: 'aws_secret_0123456789',
    });
    await root.access.set(`user:${DEV}`, { market: 'developer' });
    await root.access.set('token:ci', { 'market/dev': 'viewer' });
  },
  { people: 'stand-ins' },
);

function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => coffreRoute(request, runtime, '203.0.113.7').then((response) => response!) });
}

async function refusal(promise: Promise<unknown>): Promise<{ status: number; reason: string | null; message: string }> {
  try {
    await promise;
  } catch (error) {
    const { status, reason, message } = error as { status: number; reason?: string; message: string };
    return { status, reason: reason ?? null, message };
  }
  throw new Error('it was not refused');
}

const valuesIn = async (client: CoffreClient, path: string) => Object.fromEntries((await client.secrets.list(path)).keys.map((entry) => [entry.key, entry.value]));

test('a plain value lists as it is, and reads with no secret read, for a person under stand-ins too', async () => {
  assert.deepEqual(await valuesIn(root, 'market/dev'), { REGION: 'eu-west-3', TWILIO_SID: SID, TWILIO_TOKEN: null });
  const dev = clientFor(deps, DEV);
  const reads = (await entries('secret.read')).length;
  assert.deepEqual((await dev.secrets.reveal('market/dev/TWILIO_SID')).values, { TWILIO_SID: SID });
  // No vault call, so no secret.read of it, and none refused.
  assert.equal((await entries('secret.read')).length, reads);
  // A secret beside it is still refused, the whole read with it.
  assert.equal((await refusal(dev.secrets.reveal('market/dev/TWILIO_TOKEN'))).reason, 'stand_ins');
  assert.equal((await refusal(dev.secrets.reveal('market/dev'))).reason, 'stand_ins');
  // A service account reads both, as before.
  assert.deepEqual((await clientFor(deps, 'ci', 'service').secrets.reveal('market/dev')).values, { REGION: 'eu-west-3', TWILIO_SID: SID, TWILIO_TOKEN: TOKEN });
});

test('a write says it is plain, in its version and in the log; written again without, it is a secret', async () => {
  const [made] = (await entries('secret.write')).filter((entry) => entry.metadata.key === 'TWILIO_SID');
  assert.equal(made!.metadata.plain, true);
  await root.secrets.set('market/dev', { TWILIO_SID: 'AC_secret_now_0123' });
  assert.equal((await valuesIn(root, 'market/dev')).TWILIO_SID, null);
  assert.deepEqual((await root.secrets.history('market/dev/TWILIO_SID')).versions.map(({ version, plain }) => [version, plain]), [[2, false], [1, true]]);
  assert.equal((await refusal(clientFor(deps, DEV).secrets.reveal('market/dev/TWILIO_SID'))).reason, 'stand_ins');
  // Rolled back to the plain version, it is plain again: that value was shown already.
  await root.secrets.restore('market/dev/TWILIO_SID', 1);
  assert.equal((await valuesIn(root, 'market/dev')).TWILIO_SID, SID);
});

test('making a stored secret plain is a reveal first, which stand-ins refuse a person; a stale one is refused', async () => {
  // The client reveals the value, then writes it plain: a person has no reveal here, so no way to publish one.
  assert.equal((await refusal(root.secrets.reveal('market/dev/TWILIO_TOKEN'))).reason, 'stand_ins');
  // A service account may, saying the version it revealed; one written meanwhile stops it.
  const ci = clientFor(deps, 'ci', 'service');
  await root.access.set('token:ci', { 'market/dev': 'developer' });
  const listed = (await ci.secrets.list('market/dev')).keys.find((entry) => entry.key === 'TWILIO_TOKEN')!;
  const { values } = await ci.secrets.reveal('market/dev/TWILIO_TOKEN');
  await root.secrets.set('market/dev', { TWILIO_TOKEN: 'rotated_0123456789' });
  const stale = await refusal(ci.secrets.set('market/dev', { TWILIO_TOKEN: { value: values.TWILIO_TOKEN!, plain: true, replaces: listed.versionId! } }));
  assert.equal(stale.status, 409);
  assert.match(stale.message, /TWILIO_TOKEN changed since it was listed/);
  assert.equal((await valuesIn(root, 'market/dev')).TWILIO_TOKEN, null);
});

test('a personal config holds no plain value', async () => {
  const dev = clientFor(deps, DEV);
  const refused = await refusal(dev.secrets.set('market/dev@me', { MINE: { value: 'mine', plain: true } }));
  assert.equal(refused.status, 400);
  assert.match(refused.message, /personal config/);
  // Its owner sees dev's plain values through it, as dev's reader.
  await dev.secrets.set('market/dev@me', { MINE: 'mine-0123456789' });
  assert.equal((await valuesIn(dev, 'market/dev@me')).TWILIO_SID, SID);
});

test("a fork's inherited plain value shows only to a reader of the parent, and a copy keeps it plain", async () => {
  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.access.set(`user:${FORKER}`, { 'market/dev-eu': 'viewer' });
  assert.equal((await valuesIn(root, 'market/dev-eu')).TWILIO_SID, SID);
  // A fork lends nothing: its own reader is told the key, not the parent's value.
  assert.equal((await valuesIn(clientFor(deps, FORKER), 'market/dev-eu')).TWILIO_SID, null);
  assert.equal((await refusal(clientFor(deps, FORKER).secrets.reveal('market/dev-eu/TWILIO_SID'))).reason, 'parent_unreadable');

  await root.environments.create('market/copy', { from: 'dev' });
  assert.deepEqual(await valuesIn(root, 'market/copy'), { REGION: 'eu-west-3', TWILIO_SID: SID, TWILIO_TOKEN: null });
});

test('a dry run compares a plain value with no read, and plain against secret is a change', async () => {
  const reads = (await entries('secret.read')).length;
  const { keys } = await root.secrets.dryRun('market/dev', {
    REGION: { value: 'eu-west-3', plain: true },
    TWILIO_SID: SID,
    TWILIO_TOKEN: { value: TOKEN, plain: true },
  });
  assert.deepEqual({ ...keys }, { REGION: 'unchanged', TWILIO_SID: 'changed', TWILIO_TOKEN: 'changed' });
  assert.equal((await entries('secret.read')).length, reads);
});

test('deleting an environment erases its plain values too', async () => {
  await root.environments.create('market/gone');
  await root.secrets.set('market/gone', { ACCOUNT: { value: 'acct_42', plain: true } });
  await root.environments.update('market/gone', { archived: true });
  await root.environments.delete('market/gone');
  const [held] = await db.owner.select({ plaintext: secretVersions.plaintext, ciphertext: secretVersions.ciphertext })
    .from(secretVersions).innerJoin(secrets, eq(secrets.id, secretVersions.secretId)).where(eq(secrets.key, 'ACCOUNT'));
  assert.equal(held!.plaintext, null);
  assert.equal(held!.ciphertext.length, 0);
});

test("the proxy hands a credential's plain key to the app as it is, and leaves it in the answer", async () => {
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run market/dev', paths: ['market/dev'] })).token;
  const plan = (await (await route('/use/market/dev', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; left: string[] };
  // The account's id as it is, the token a stand-in: what `identifiers` said in configuration, said in the data.
  assert.equal(plan.env.TWILIO_SID, SID);
  assert.equal(plan.env.TWILIO_TOKEN, handle);
  assert.equal(plan.env.REGION, 'eu-west-3');
  assert.deepEqual(plan.left, []);

  const basicAuth = `Basic ${Buffer.from(`${SID}:${handle}`).toString('base64')}`;
  const answer = await route(`/use/market/dev/twilio/Accounts/${SID}/Messages.json`, { headers: { authorization: basicAuth } });
  assert.equal(answer.status, 200);
  const body = (await answer.json()) as { account_sid: string; uri: string; echoed: string };
  // Twilio quotes the account back: a plain value stays; the token it echoed is redacted.
  assert.equal(body.account_sid, SID);
  assert.equal(body.uri, `/twilio/Accounts/${SID}/Messages.json`);
  assert.equal(body.echoed, `${SID}:[redacted by coffre]`);
});

test("a credential's plain key stays a stand-in where the handle would go nowhere else: S3's access key id, a header's only key", async () => {
  const handle = (await bearer(await sessionFor(DEV)).handles.create({ label: 'coffre run market/other', paths: ['market/other'] })).token;
  const plan = (await (await route('/use/market/other', { headers: { authorization: `Bearer ${handle}` } })).json()) as { env: Record<string, string>; left: string[] };
  // The SDK sends its access key id as Credential=, the handle's one place: given as it is, the handle would be in a signature.
  assert.equal(plan.env.AWS_ACCESS_KEY_ID, handle);
  assert.equal(plan.env.AWS_SECRET_ACCESS_KEY, handle);
  assert.equal(plan.env.ACCOUNT_ID, handle);
  assert.deepEqual(plan.left, []);

  // The real plain value goes in, and comes back as it is: being no secret, it is not redacted, nor what the rule made of it.
  const answer = await route('/use/market/other/account/whoami', { headers: { 'x-account': handle } });
  assert.equal(answer.status, 200);
  assert.equal(((await answer.json()) as { account: string }).account, 'acct_public_42');
});

test("a listing shows no plain value from past a parent archived around coffre, as a read refuses there", async () => {
  await root.environments.create('market/middle', { from: 'dev', inherit: true });
  await root.environments.create('market/leaf', { from: 'middle', inherit: true });
  assert.equal((await valuesIn(root, 'market/leaf')).REGION, 'eu-west-3');
  const [middle] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'middle'));
  await db.owner.update(environments).set({ archivedAt: new Date() }).where(eq(environments.id, middle!.id));
  assert.equal((await refusal(root.secrets.reveal('market/leaf/REGION'))).status, 409);
  assert.equal((await valuesIn(root, 'market/leaf')).REGION, null);
});
