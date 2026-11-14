// Values through MCP on the 0.16 contract (docs/design/mcp.md, section 7;
// docs/design/0.16.md, "`/mcp`"): what the approval page tells a person
// whose connection holds Reveal values; a sensitive value, which no
// connection is handed; and a person's own config, `dev@me`, theirs alone.
// Cases from 0.14.7's mcp-values, credential-proxy and personal-overlay
// tests, against the real vault.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { beforeEach, test } from 'node:test';

import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';

import { approvalWait } from '../src/mcp/approvals.ts';
import { app, callRaw, connect, fromPage, type Result } from './mcp-fixture.ts';

const { world } = app;
const [root, dev, other] = [user('root'), user('dev'), user('other')];
/** Every value the suite holds, each unique, so a leak is found by searching for it. */
const [API_KEY, SEAL, REGION, MINE, MINE_PLAIN] = ['api', 'seal', 'region', 'mine', 'mine-plain'].map((name) => `${name}-${randomBytes(6).toString('hex')}`) as [string, string, string, string, string];
approvalWait.ms = 50;

/**
 * market/prod holds API_KEY, SEAL (sensitive) and REGION (plain);
 * market/prod-dev is Dev's personal config of prod: MINE, and MINE_PLAIN
 * (plain). Root owns the instance; Dev leads market; Other views it. Each
 * has a browser session, `<name>-web`, which connects apps.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  const prod = environment(market, 'prod');
  const mine = environment(market, 'prod-dev', { parentId: prod.id, owner: dev });
  const people = [root, dev, other].map((who) => [who, identity(who)] as const);
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('projects', market),
    ...rows('environments', prod, mine),
    ...rows('secrets',
      value(world, secret(prod, 'API_KEY'), API_KEY), value(world, secret(prod, 'SEAL'), SEAL, { sensitive: true }), value(world, secret(prod, 'REGION'), REGION, { plain: true }),
      value(world, secret(mine, 'MINE'), MINE), value(world, secret(mine, 'MINE_PLAIN'), MINE_PLAIN, { plain: true })),
    ...rows('roles',
      role(false, 'viewer', ['secret.read', 'secret.use'], []),
      role(false, 'lead', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage']),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(dev), principal(other)),
    ...rows('grants', grant(dev, 'lead', { project: market }), grant(other, 'viewer', { project: market })),
    ...rows('identities', ...people.map(([, id]) => id)),
    ...rows('credentials', ...people.map(([who, id]) => credential(`${who.slice(5, who.indexOf('@'))}-web`, who, { kind: 'browser', identityId: id.id }))),
  );
  app.calls.length = 0;
});

type View = { reveals: boolean; details: { label: string; value: string }[]; asks: { value: { note: string } } | null };
const idOf = (result: { body: { result?: Result } }) => (result.body.result!.structuredContent!.approval as { id: string }).id;
/** The approval as Dev's page shows it. */
async function view(id: string): Promise<View> {
  const response = await app.request(`/api/approvals/${id}`, { headers: fromPage('dev-web') });
  assert.equal(response.status, 200);
  return ((await response.json()) as { approval: View }).approval;
}
/** Every value of the suite's that `text` holds. */
const leaks = (text: string) => [API_KEY, SEAL, REGION, MINE, MINE_PLAIN].filter((held) => text.includes(held));

test('with Reveal values, the page never says the app cannot see a value: it says the app can read it, as any the person can (L1)', async () => {
  // Without it, a value made or typed on coffre is nobody's but coffre's.
  const writing = await connect('dev-web', 'read write');
  const made = await view(idOf(await callRaw(writing, 'generate_secret_value', { secret: 'market/prod/MADE' })));
  assert.equal(made.reveals, false);
  assert.ok(made.details.some((line) => line.label === 'New value' && /nobody sees it/.test(line.value)), JSON.stringify(made.details));
  const typed = await view(idOf(await callRaw(writing, 'request_secret_value', { secret: 'market/prod/TYPED' })));
  assert.equal(typed.asks!.value.note, 'It goes to coffre only: the app never sees it.');

  const revealing = await connect('dev-web', 'read write reveal');
  const shown = [
    await view(idOf(await callRaw(revealing, 'request_secret_value', { secret: 'market/prod/TYPED' }))),
    await view(idOf(await callRaw(revealing, 'generate_secret_value', { secret: 'market/prod/MADE' }))),
  ];
  for (const approval of shown) {
    assert.equal(approval.reveals, true);
    assert.ok(approval.details.some((line) => line.label === 'The app' && line.value === 'holds Reveal values: it can read values you can read, this one included'), JSON.stringify(approval.details));
    assert.doesNotMatch(JSON.stringify(approval), /never sees|nobody sees/);
  }
  assert.equal(shown[0]!.asks!.value.note, 'It goes to coffre, and the app can read it.');
});

test('reveal_secret_values leaves a sensitive value out of a whole environment, by name, and refuses it alone, saying why; the Owner too', async () => {
  for (const session of ['dev-web', 'root-web']) {
    const token = await connect(session, 'read reveal');
    const whole = await callRaw(token, 'reveal_secret_values', { path: 'market/prod' });
    const { values, sensitive } = whole.body.result!.structuredContent! as { values: Record<string, string>; sensitive: string[] };
    assert.deepEqual([values, sensitive], [{ API_KEY, REGION }, ['SEAL']], session);
    assert.match(whole.body.result!.content[0]!.text!, /Left out, sensitive, which nobody sees and apps use through the credential proxy: SEAL$/);
    const one = await callRaw(token, 'reveal_secret_values', { path: 'market/prod/SEAL' });
    assert.equal(one.body.result!.isError, true, session);
    assert.match(JSON.stringify(one.body), /sensitive/);
    assert.equal(JSON.stringify([whole.body, one.body]).includes(SEAL), false, session);
  }
});

test("on its owner's dev@me, MCP lists and reveals their own values, and dev's beneath; on another's config, an error that holds no value", async () => {
  const token = await connect('dev-web', 'read reveal');
  const listed = await callRaw(token, 'list_secrets', { environment: 'market/prod@me' });
  assert.equal(listed.body.result!.isError, undefined, JSON.stringify(listed.body));
  const keys = listed.body.result!.structuredContent!.keys as { key: string; value: string | null }[];
  assert.equal(keys.find((entry) => entry.key === 'MINE_PLAIN')!.value, MINE_PLAIN);
  assert.equal(keys.find((entry) => entry.key === 'REGION')!.value, REGION);
  const revealed = (await callRaw(token, 'reveal_secret_values', { path: 'market/prod@me' })).body.result!.structuredContent!;
  assert.deepEqual([revealed.values, revealed.sensitive], [{ API_KEY, MINE, MINE_PLAIN, REGION }, ['SEAL']]);

  // Whoever else asks for it, by its own name, the Owner included: their dev@me is prod, and Dev's is not theirs.
  for (const session of ['root-web', 'other-web']) {
    const theirs = await connect(session, 'read reveal');
    const own = (await callRaw(theirs, 'reveal_secret_values', { path: 'market/prod@me' })).body.result!.structuredContent!;
    assert.deepEqual(own.values, { API_KEY, REGION }, session);
    for (const [name, args] of [['list_secrets', { environment: 'market/prod-dev' }], ['reveal_secret_values', { path: 'market/prod-dev' }], ['reveal_secret_values', { path: 'market/prod-dev/MINE' }]] as const) {
      const answered = await callRaw(theirs, name, args);
      assert.equal(answered.body.result!.isError, true, `${session} ${name} ${JSON.stringify(args)}`);
      assert.deepEqual(leaks(JSON.stringify(answered.body)), [], `${session} ${name}`);
    }
  }
});
