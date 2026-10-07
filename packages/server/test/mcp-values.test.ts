// Values through MCP (docs/design/mcp.md, section 7): to the model only with
// Reveal values; to the person, on coffre's page, with Read; and made on the
// server when a client asks for a new one, which nobody sees.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { clientFor } from './api-fixture.ts';
import { auditLog, mcpApprovals } from './db/tables.ts';
import { ALPHABETS, randomValue } from '../src/mcp/changes.ts';
import { browserFor, callRaw, connect, db, deps, DEV, entries, fromPage, ROOT, route, useMcp } from './mcp-fixture.ts';

const VALUE = `value-${randomBytes(8).toString('hex')}`;

useMcp(
  async () => {
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.projects.create('market', { name: 'Market' });
    await root.environments.create('market/prod', { name: 'Production' });
    await root.secrets.set('market/prod', { API_KEY: VALUE });
    await root.access.set(`user:${DEV}`, { market: 'maintainer' });
  },
  { approvalWaitMs: 50 },
);

async function decide(id: string, value?: string) {
  const headers = fromPage(await browserFor(DEV), { 'content-type': 'application/json' });
  const { approval } = (await (await route(`/api/approvals/${id}`, { headers })).json()) as {
    approval: { digest: string; basis: string | null; kind: string; reveals: boolean; details: { label: string; value: string }[]; asks: { value: { note: string } } | null };
  };
  const response = await route(`/api/approvals/${id}`, { method: 'POST', headers, body: JSON.stringify({ approve: true, digest: approval.digest, basis: approval.basis, value }) });
  return { approval, decision: (await response.json()) as { status: string; shown: { label: string; value: string }[]; outcome: { text: string } } };
}

const idOf = (result: { body: { result?: { structuredContent?: Record<string, unknown> } } }) => (result.body.result!.structuredContent!.approval as { id: string }).id;

test('values reach the model only with Reveal values, with a warning first, and the reveal is logged under the connection', async () => {
  const reading = await connect(DEV);
  const refused = await callRaw(reading, 'reveal_secret_values', { path: 'market/prod' });
  assert.equal(refused.status, 403);
  assert.equal(JSON.stringify(refused.body).includes(VALUE), false);

  const revealing = await connect(DEV, 'read reveal');
  const revealed = await callRaw(revealing, 'reveal_secret_values', { path: 'market/prod' });
  assert.deepEqual(revealed.body.result!.structuredContent!.values, { API_KEY: VALUE });
  assert.match(revealed.body.result!.content[0]!.text!, /^These values are now part of this conversation and its history\./);
  // The vault's entry is the record of the read, under the connection, as the call's own entry names it.
  const reveals = (await entries('secret.read')).filter((entry) => entry.decision === 'allow');
  const [call] = await entries('mcp.read');
  assert.equal(reveals.length, 1);
  assert.equal(reveals[0]!.metadata.credentialId, (call!.metadata.via as { connectionId: string }).connectionId);
});

test('show_secret_value shows the value to the person on the page, with Read, and never to the client', async () => {
  const token = await connect(DEV);
  const asked = await callRaw(token, 'show_secret_value', { secret: 'market/prod/API_KEY' });
  assert.equal(asked.body.result!.structuredContent!.status, 'pending');
  const { approval, decision } = await decide(idOf(asked));
  assert.equal(approval.kind, 'reveal');
  assert.equal(decision.status, 'approved');
  assert.deepEqual(decision.shown, [{ label: 'API_KEY', value: VALUE, kind: 'mono' }], 'the page shows it');
  const reported = await callRaw(token, 'show_secret_value', { secret: 'market/prod/API_KEY' });
  assert.equal(reported.body.result!.structuredContent!.status, 'approved');
  assert.match(reported.body.result!.content[0]!.text!, /shown to the person/);
  assert.equal(JSON.stringify([asked.body, reported.body]).includes(VALUE), false, 'never to the client');
  assert.equal(JSON.stringify(await db.owner.select().from(mcpApprovals)).includes(VALUE), false);
  // The reveal is the person's, logged by the vault under the connection; nothing else is read with Read.
  const reveal = (await entries('secret.read')).find((entry) => entry.decision === 'allow')!;
  const [row] = await db.owner.select().from(mcpApprovals);
  assert.equal(reveal.actor, `user:${DEV}`);
  assert.equal(reveal.metadata.credentialId, row!.connectionId);
  assert.equal((await callRaw(token, 'reveal_secret_values', { path: 'market/prod' })).status, 403);
});

test('generate_secret_value makes the value on the server when the person approves, and nobody sees it', async () => {
  const token = await connect(DEV, 'read write');
  const asked = await callRaw(token, 'generate_secret_value', { secret: 'market/prod/SESSION_SECRET', alphabet: 'hex' });
  const { approval, decision } = await decide(idOf(asked));
  assert.ok(approval.details.some((line) => line.label === 'New value' && /64 random hex characters/.test(line.value)));
  assert.equal(decision.status, 'approved');
  assert.deepEqual(decision.shown, [], 'not even the person');
  const made = (await clientFor(deps, ROOT).secrets.reveal('market/prod/SESSION_SECRET')).values.SESSION_SECRET!;
  assert.match(made, /^[0-9a-f]{64}$/);
  const reported = await callRaw(token, 'generate_secret_value', { secret: 'market/prod/SESSION_SECRET', alphabet: 'hex' });
  assert.equal((reported.body.result!.structuredContent!.result as { version: number }).version, 1);
  const seen = JSON.stringify([asked.body, reported.body, decision, await db.owner.select().from(mcpApprovals), await db.owner.select({ metadata: auditLog.metadata }).from(auditLog)]);
  assert.equal(seen.includes(made), false);
});

test('with Reveal values, the page never says the app cannot see a value: it says the app can read it, as any the person can (L1)', async () => {
  const plain = await decide(idOf(await callRaw(await connect(DEV, 'read write'), 'generate_secret_value', { secret: 'market/prod/PLAIN' })));
  assert.equal(plain.approval.reveals, false);
  assert.ok(plain.approval.details.some((line) => line.label === 'New value' && /nobody sees it/.test(line.value)));

  const token = await connect(DEV, 'read write reveal');
  const typed = await decide(idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/TYPED' })), 'typed');
  const generated = await decide(idOf(await callRaw(token, 'generate_secret_value', { secret: 'market/prod/MADE' })));
  for (const { approval } of [typed, generated]) {
    assert.equal(approval.reveals, true);
    assert.ok(approval.details.some((line) => line.label === 'The app' && line.value === 'holds Reveal values: it can read values you can read, this one included'));
    assert.doesNotMatch(JSON.stringify(approval), /never sees|nobody sees/);
  }
  assert.equal(typed.approval.asks!.value.note, 'It goes to coffre, and the app can read it.');
});

test('a random value is as long as asked, from its alphabet only', () => {
  for (const [alphabet, { characters, length }] of Object.entries(ALPHABETS) as [keyof typeof ALPHABETS, (typeof ALPHABETS)[keyof typeof ALPHABETS]][]) {
    const value = randomValue(alphabet);
    assert.equal(value.length, length);
    assert.ok([...value].every((character) => characters.includes(character)), alphabet);
    assert.equal(randomValue(alphabet, 16).length, 16);
    assert.notEqual(randomValue(alphabet), randomValue(alphabet));
  }
});
