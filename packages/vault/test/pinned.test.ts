// The encodings 0.16's vault, app and audit page share: an event's id, object and payload,
// the seal inputs of a `settings` row and a `log_keys` row, their changes after the upgrade, each change of the vault's
// upgrade step, and the check's tail bound. Each is a fixed
// vector, so that a later change that moves a field fails here, not in a neighbour's build.
import test from 'node:test';
import assert from 'node:assert/strict';

import { CHECK_TAIL_ENTRIES } from '../src/audit-check.ts';
import { loggedChange, payloadOf } from '../src/changes.ts';
import { applyOp, canonical, logObject, objectKey, refOf, sealOf, type Kind, type Op } from '../src/inputs.ts';
import { logMacKey } from '../src/log-entry.ts';
import { replay } from '../src/log-replay.ts';
import { eventObject, eventRow, findingEventId, notePayload } from '../src/note.ts';
import { logKeyObject, settingsObject } from '../src/objects.ts';
import { ANCHOR_OBJECT, anchorPayload, donePayload, firstChangePayload, parseAnchor, UPGRADE_ACTOR, UPGRADE_OBJECT, UPGRADE_REQUESTS } from '../src/upgrade.ts';

/** A seal key of fixed bytes: the vectors pin what is sealed, not how a key is derived. */
const KEY = Buffer.alloc(32, 0x5a);
const REQUEST = '6f9619ff-8b86-4011-b42d-00c04fc964ff';
/** An event's id, as its writer draws it. */
const EVENT = '0b6a7c9e-1f2d-4e3a-8b5c-6d7e8f901a2b';

/** Every kind of object a change is of: a new kind joins it, or this fails to compile. */
const KINDS = ['principal', 'credential', 'connection', 'binding', 'secret', 'environment', 'roles', 'role', 'policy', 'proxy', 'proxy-reserved', 'settings', 'log-key'] as const satisfies readonly Kind[];
const _everyKind: Exclude<Kind, (typeof KINDS)[number]> extends never ? true : never = true;

test("the beat's finding's id: one per checkpoint and state, so a beat that runs twice writes it once", () => {
  assert.equal(findingEventId(4410n, 'late'), 'system:vault/finding:4410:late');
  assert.equal(findingEventId(4410n, 'broken'), 'system:vault/finding:4410:broken');
  assert.equal(findingEventId(null, 'behind'), 'system:vault/finding:none:behind');
});

test("an event's object is log_object('event', its id), no object of any kind's", () => {
  const id = EVENT;
  assert.equal(eventObject(id), 'ae0a382b-81d9-d6f2-4351-d5540a9267ae');
  // The projector and the replay tell an event from a change by its object too: no kind files an object under it.
  for (const kind of KINDS) assert.notEqual(objectKey({ kind, id }), eventObject(id), kind);
  // Nor the log's own, an event whose id is one of theirs included.
  for (const own of ['anchor', 'upgrade-0.16', 'retention', 'cutover']) assert.notEqual(eventObject(own), logObject('log', own), own);
});

test("an event's payload is the input but its actor and id, as canonical JSON", () => {
  const payload = notePayload({
    id: EVENT, requestId: REQUEST, action: 'settings.change', allowed: false, code: 'requires_instance_admin',
    actor: 'user:ada@acme.example', subject: null, places: { projectId: null, environmentId: null, secretId: null, versionId: null },
    credential: '00000000-0000-4000-8002-000000000001', operationId: null, sourceIp: '203.0.113.7', detail: {},
  }, 'app');
  assert.equal(payload, '{"action":"settings.change","allowed":false,"author":"app","code":"requires_instance_admin","credential":"00000000-0000-4000-8002-000000000001","detail":{},"op":"event","operationId":null,"places":{"environmentId":null,"projectId":null,"secretId":null,"versionId":null},"ref":{"id":"0b6a7c9e-1f2d-4e3a-8b5c-6d7e8f901a2b","kind":"event"},"requestId":"6f9619ff-8b86-4011-b42d-00c04fc964ff","sourceIp":"203.0.113.7","subject":null}');
});

test("an event as prepare signs it for the app's transaction: its id, object and MAC; who decided is under the MAC", () => {
  const input = {
    id: EVENT, requestId: REQUEST, action: 'passkey.add', allowed: true, code: null, actor: 'user:ada@acme.example',
    subject: 'user:ada@acme.example', places: { projectId: null, environmentId: null, secretId: null, versionId: null },
    credential: '00000000-0000-4000-8002-000000000001', operationId: null, sourceIp: null, detail: {},
  };
  const row = eventRow(logMacKey(Buffer.alloc(32, 0x11)), 1794500000000, input, 'app');
  assert.equal(row.requestId, EVENT);
  assert.equal(row.object, eventObject(EVENT));
  assert.equal(row.seal, null);
  assert.equal(row.mac.toString('hex'), '4dc59a4590c719272c7bf5b419d842d4');
  // The same event the vault decided: another payload, another MAC.
  const vaults = eventRow(logMacKey(Buffer.alloc(32, 0x11)), 1794500000000, input, 'vault');
  assert.ok(vaults.payload.includes('"author":"vault"'));
  assert.equal(vaults.mac.toString('hex'), '4dc59a45a170153d4271cb5a8e60624f');
});

test("a settings row's object, its key in the log and its seal", () => {
  const object = settingsObject({ serviceAccountsProjects: 'except', serviceAccountsProjectIds: ['00000000-0000-4000-8000-0000000000b1'], serviceAccountsEnvironments: 'only', serviceAccountsEnvironmentSlugs: ['dev', 'staging'] });
  assert.equal(canonical(object), '{"kind":"settings","serviceAccounts":{"environments":{"only":["dev","staging"]},"projects":{"except":["00000000-0000-4000-8000-0000000000b1"]}}}');
  assert.deepEqual(refOf(object), { kind: 'settings', id: 'instance' });
  assert.equal(objectKey(refOf(object)), '002185e2-2135-9b9d-44bb-41d12b0f4356');
  assert.equal(sealOf(KEY, refOf(object), object).toString('hex'), '6d5ef10e4abb9dfd5cd95d6ea552383e');
  // `all` holds no list: the row's CHECK keeps it empty, and the object says `all`.
  assert.deepEqual(settingsObject({ serviceAccountsProjects: 'all', serviceAccountsProjectIds: [], serviceAccountsEnvironments: 'all', serviceAccountsEnvironmentSlugs: [] }), { kind: 'settings', serviceAccounts: { projects: 'all', environments: 'all' } });
  // A filter of no kind the row's CHECK allows is read as letting no one, never as everyone.
  assert.deepEqual(settingsObject({ serviceAccountsProjects: 'some', serviceAccountsProjectIds: [], serviceAccountsEnvironments: 'all', serviceAccountsEnvironmentSlugs: [] }), { kind: 'settings', serviceAccounts: { projects: { only: [] }, environments: 'all' } });
});

test("a log key row's object, its key in the log and its seal", () => {
  const object = logKeyObject({ holder: 'app', keyId: 'app:3f0c9a1e5b7d2468', retired: true });
  assert.ok(object !== null);
  assert.equal(canonical(object), '{"holder":"app","id":"app:3f0c9a1e5b7d2468","kind":"log-key","retired":true}');
  assert.deepEqual(refOf(object), { kind: 'log-key', id: 'app:3f0c9a1e5b7d2468' });
  assert.equal(objectKey(refOf(object)), '89fa5347-0c6d-5344-f90c-d525b2dcc98a');
  assert.equal(sealOf(KEY, refOf(object), object).toString('hex'), 'fad7d7efdafe9947813c4cb8734bb021');
  assert.equal(logKeyObject({ holder: 'witness', keyId: 'witness:3f0c9a1e5b7d2468', retired: false }), null);
});

test("the upgrade's changes: request ids, objects, actor", () => {
  assert.deepEqual([UPGRADE_REQUESTS.anchor, UPGRADE_REQUESTS.settings, UPGRADE_REQUESTS.key('app:3f0c9a1e5b7d2468'), UPGRADE_REQUESTS.done], [
    'upgrade-0.16:anchor', 'upgrade-0.16:settings', 'upgrade-0.16:log-key:app:3f0c9a1e5b7d2468', 'upgrade-0.16:done',
  ]);
  assert.equal(ANCHOR_OBJECT, '5a934dd2-9938-1790-accb-fcc1d92344d1');
  assert.equal(UPGRADE_OBJECT, '00e06232-1663-2f1d-ef30-061e0486ed3c');
  assert.equal(UPGRADE_ACTOR, 'system:vault');
});

test("the anchor's payload: the old chain's final entry, and the checkpoint its tail was checked from", () => {
  assert.equal(
    anchorPayload({ seq: 440213n, hash: Buffer.alloc(32, 0xab) }, { seq: 440190n, hash: Buffer.alloc(32, 0xcd) }, 'outside'),
    `{"anchor":{"hash":"${'ab'.repeat(32)}","seq":"440213"},"from":{"hash":"${'cd'.repeat(32)}","seq":"440190"},"held":"outside","op":"upgrade.anchor"}`,
  );
});

test("the anchor's payload read back: exactly an anchor's, or nothing", () => {
  const payload = anchorPayload({ seq: 440213n, hash: Buffer.alloc(32, 0xab) }, { seq: 440190n, hash: Buffer.alloc(32, 0xcd) }, 'log');
  assert.deepEqual(parseAnchor(payload), { anchor: { seq: 440213n, hash: Buffer.alloc(32, 0xab) }, from: { seq: 440190n, hash: Buffer.alloc(32, 0xcd) }, held: 'log' });
  for (const bad of [
    'not json', 'null', donePayload(),
    payload.replace('"upgrade.anchor"', '"upgrade.done"'),
    payload.replace('"440213"', '440213'),
    payload.replace('"440213"', '"0440213"'),
    payload.replace('ab'.repeat(32), 'AB'.repeat(32)),
    payload.replace('ab'.repeat(32), 'ab'.repeat(31)),
    payload.replace('{"anchor"', '{"extra":1,"anchor"'),
    payload.replace('"held":"log"', '"held":"store"'),
    payload.replace('"held":"log",', ''),
    ` ${payload}`,
  ]) assert.equal(parseAnchor(bad), null, bad);
});

test('the replay passes over an event: its op changes no object a decision reads', () => {
  const row = eventRow(logMacKey(Buffer.alloc(32, 0x11)), 1_700_000_000_000, {
    id: EVENT, requestId: REQUEST, action: 'project.create', allowed: true, code: null, actor: 'user:ada@acme.example', subject: null,
    places: { projectId: null, environmentId: null, secretId: null, versionId: null }, credential: null, operationId: null, sourceIp: null, detail: {},
  }, 'app');
  const logged = loggedChange({ number: 1n, at: row.at, object: row.object, payload: row.payload, seal: null });
  assert.ok(logged !== null);
  const replayed = replay([KEY], [logged]);
  assert.deepEqual(replayed.faults, []);
  assert.equal(replayed.rows.size, 0);
});

test("the settings' and a key's first change: a genesis of the row's object, citing its old entry", () => {
  const settings = settingsObject({ serviceAccountsProjects: 'all', serviceAccountsProjectIds: [], serviceAccountsEnvironments: 'except', serviceAccountsEnvironmentSlugs: ['prod'] });
  assert.equal(firstChangePayload(settings, 1207n), '{"old":"1207","op":"genesis","ref":{"id":"instance","kind":"settings"},"value":{"kind":"settings","serviceAccounts":{"environments":{"except":["prod"]},"projects":"all"}}}');
  // Settings nobody changed: the default, citing nothing.
  const fresh = settingsObject({ serviceAccountsProjects: 'all', serviceAccountsProjectIds: [], serviceAccountsEnvironments: 'all', serviceAccountsEnvironmentSlugs: [] });
  assert.equal(firstChangePayload(fresh, null), '{"op":"genesis","ref":{"id":"instance","kind":"settings"},"value":{"kind":"settings","serviceAccounts":{"environments":"all","projects":"all"}}}');
  const key = logKeyObject({ holder: 'vault', keyId: 'vault:0123456789abcdef', retired: false })!;
  assert.equal(firstChangePayload(key, 2048n), '{"old":"2048","op":"genesis","ref":{"id":"vault:0123456789abcdef","kind":"log-key"},"value":{"holder":"vault","id":"vault:0123456789abcdef","kind":"log-key","retired":false}}');
});

test("the done marker's payload", () => {
  assert.equal(donePayload(), '{"op":"upgrade.done","release":"0.16"}');
});

test("the settings changed after the upgrade: the whole scope, applied to the row's object", () => {
  const before = settingsObject({ serviceAccountsProjects: 'all', serviceAccountsProjectIds: [], serviceAccountsEnvironments: 'all', serviceAccountsEnvironmentSlugs: [] });
  const op: Op = { op: 'settings.change', serviceAccounts: { projects: 'all', environments: { except: ['prod'] } } };
  assert.equal(payloadOf(refOf(before), op), '{"op":"settings.change","ref":{"id":"instance","kind":"settings"},"serviceAccounts":{"environments":{"except":["prod"]},"projects":"all"}}');
  assert.deepEqual(applyOp(before, refOf(before), op), { kind: 'settings', serviceAccounts: { projects: 'all', environments: { except: ['prod'] } } });
  assert.equal(applyOp(null, refOf(before), op), undefined);
});

test("a key rotated to and from: the new key's add, naming the one it replaces, and the old one's retire", () => {
  const ref = { kind: 'log-key', id: 'app:fedcba9876543210' } as const;
  const add: Op = { op: 'log-key.add', holder: 'app', from: 'app:3f0c9a1e5b7d2468' };
  assert.equal(payloadOf(ref, add), '{"from":"app:3f0c9a1e5b7d2468","holder":"app","op":"log-key.add","ref":{"id":"app:fedcba9876543210","kind":"log-key"}}');
  assert.deepEqual(applyOp(null, ref, add), { kind: 'log-key', id: 'app:fedcba9876543210', holder: 'app', retired: false });
  // A key of another holder's, or replacing another holder's, or one that exists, is no add.
  assert.equal(applyOp(null, ref, { op: 'log-key.add', holder: 'vault', from: null }), undefined);
  assert.equal(applyOp(null, ref, { op: 'log-key.add', holder: 'app', from: 'vault:3f0c9a1e5b7d2468' }), undefined);
  assert.equal(applyOp({ kind: 'log-key', id: ref.id, holder: 'app', retired: false }, ref, add), undefined);
  const old = logKeyObject({ holder: 'app', keyId: 'app:3f0c9a1e5b7d2468', retired: false })!;
  assert.equal(payloadOf(refOf(old), { op: 'log-key.retire' }), '{"op":"log-key.retire","ref":{"id":"app:3f0c9a1e5b7d2468","kind":"log-key"}}');
  assert.deepEqual(applyOp(old, refOf(old), { op: 'log-key.retire' }), { ...old, retired: true });
  assert.equal(applyOp({ ...old, retired: true }, refOf(old), { op: 'log-key.retire' }), undefined);
});

test("check's tail bound: the uses an isolate holds in flight", () => {
  assert.equal(CHECK_TAIL_ENTRIES, 1250);
});
