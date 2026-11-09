import test from 'node:test';
import assert from 'node:assert/strict';

import { defineDeployment, resolveDeployment } from '../src/deployment.ts';
import { signin } from '../src/identity/auth.ts';
import { github } from '../src/identity/signin/config.ts';

const providers = [github({ clientId: 'id', clientSecret: 'secret' })];
const limits = { perSource: { limit: async () => ({ success: true }) } };

test('defineDeployment() is every default: what a deployment that sets nothing runs on', () => {
  assert.deepEqual(defineDeployment(), {
    people: { browserSessionHours: 12, cliSessionDays: 30 },
    services: { tokenMaxDays: 365, signInsPerAddress: 10_000, useOnly: false, noReads: false },
    reads: { bulkLimit: { count: 1_000, windowMinutes: 15 } },
    values: { rotateAfterDays: 365 },
    proxy: { revokedWithinSeconds: 60, cacheValues: true, editable: false },
    audit: { keepUsesDays: null, repeatsWithinSeconds: 60 },
  });
});

test('a field set replaces its default alone, and the object is frozen through', () => {
  const deployment = defineDeployment({ services: { tokenMaxDays: 90 }, audit: { keepUsesDays: 400 }, values: { rotateAfterDays: null } });
  assert.equal(deployment.services.tokenMaxDays, 90);
  assert.equal(deployment.services.signInsPerAddress, 10_000);
  assert.equal(deployment.audit.keepUsesDays, 400);
  assert.equal(deployment.audit.repeatsWithinSeconds, 60);
  assert.equal(deployment.values.rotateAfterDays, null);
  assert.ok(Object.isFrozen(deployment) && Object.isFrozen(deployment.services) && Object.isFrozen(deployment.reads.bulkLimit));
  // Checked again, as the app and the vault each do with what they are passed, it is the same.
  assert.deepEqual(defineDeployment(deployment), deployment);
});

test('each field refuses what is out of its range, by name', () => {
  const refused: [object, RegExp][] = [
    [{ people: { browserSessionHours: 0 } }, /people\.browserSessionHours is a number above 0, at most 168/],
    [{ people: { cliSessionDays: 366 } }, /people\.cliSessionDays/],
    [{ services: { tokenMaxDays: 366 } }, /services\.tokenMaxDays is a whole number, at least 1, at most 365/],
    [{ services: { tokenMaxDays: 1.5 } }, /services\.tokenMaxDays/],
    [{ services: { signInsPerAddress: 0 } }, /services\.signInsPerAddress/],
    [{ services: { useOnly: 'yes' } }, /services\.useOnly is true or false/],
    [{ reads: { bulkLimit: { count: 10, windowMinutes: 24 * 60 + 1 } } }, /reads\.bulkLimit/],
    [{ values: { rotateAfterDays: 0 } }, /values\.rotateAfterDays .* or null for no flag/],
    // R's floor is a use's own deadline, 3 s: below it, a cold request sends after the promise.
    [{ proxy: { revokedWithinSeconds: 2 } }, /proxy\.revokedWithinSeconds is a number of seconds, 3 to 3,600/],
    [{ proxy: { revokedWithinSeconds: 3_601 } }, /proxy\.revokedWithinSeconds/],
    [{ audit: { keepUsesDays: 0 } }, /audit\.keepUsesDays .* or null to keep every day/],
    [{ audit: { repeatsWithinSeconds: -1 } }, /audit\.repeatsWithinSeconds is a number of seconds, 0 to 3,600/],
    // A typo is no default: it fails, naming the fields there are.
    [{ proxy: { revokedWithin: 30 } }, /proxy\.revokedWithin is not a field; proxy's are revokedWithinSeconds, cacheValues, editable/],
    [{ people: { passkeys: 'required' } }, /people\.passkeys is not a field/],
    [{ limits: {} }, /limits is not a group/],
  ];
  for (const [options, message] of refused) assert.throws(() => defineDeployment(options as never), message, JSON.stringify(options));
  assert.equal(defineDeployment({ proxy: { revokedWithinSeconds: 3 } }).proxy.revokedWithinSeconds, 3);
  assert.equal(defineDeployment({ audit: { repeatsWithinSeconds: 0 } }).audit.repeatsWithinSeconds, 0);
});

test('a setting in its 0.15 place is read in 0.16, once warned of; beside the object, it is refused', () => {
  const warned: string[] = [];
  const moved = [{ old: 'signin({ cliSessionDays })', options: { people: { cliSessionDays: 7 } } }, { old: 'vault({ bulkLimit })', options: { reads: { bulkLimit: { count: 50, windowMinutes: 5 } } } }];
  const read = resolveDeployment(undefined, moved, (message) => warned.push(message));
  assert.equal(read.people.cliSessionDays, 7);
  assert.deepEqual(read.reads.bulkLimit, { count: 50, windowMinutes: 5 });
  assert.equal(read.people.browserSessionHours, 12);
  assert.match(warned[0]!, /signin\(\{ cliSessionDays \}\), vault\(\{ bulkLimit \}\) moved to deployment\.ts in 0\.16/);
  resolveDeployment(undefined, moved, (message) => warned.push(message));
  assert.equal(warned.length, 1, 'once per isolate or process');
  assert.throws(() => resolveDeployment({}, moved), /signin\(\{ cliSessionDays \}\), vault\(\{ bulkLimit \}\): in deployment\.ts now, which this deployment passes too/);
  assert.deepEqual(resolveDeployment(undefined, []), defineDeployment());
});

test("sign-in takes its lifetimes and the services' switches from the object", () => {
  const deployment = defineDeployment({ people: { browserSessionHours: 8, cliSessionDays: 7 }, services: { tokenMaxDays: 30, useOnly: true, noReads: true } });
  const auth = signin({ providers, workloads: { limits } });
  assert.deepEqual(auth.moved, []);
  const resolved = auth.resolve('https://secrets.acme.example', deployment);
  assert.equal(resolved.mode, 'signin');
  if (resolved.mode !== 'signin') return;
  assert.equal(resolved.signin.browserSessionHours, 8);
  assert.equal(resolved.signin.cliSessionDays, 7);
  assert.equal(resolved.signin.serviceTokenMaxDays, 30);
  assert.equal(resolved.signin.useOnly, true);
  assert.equal(resolved.signin.workloads?.noReads, true);
  // `useOnly` holds with workloads off too: no service token is issued or taken, whatever else signs services in.
  const off = signin({ providers }).resolve('https://secrets.acme.example', deployment);
  assert.deepEqual(off.mode === 'signin' && [off.signin.useOnly, off.signin.workloads], [true, null]);
  // 0.15's place, still read, with workloads on.
  const legacy = signin({ providers, workloads: { limits, useOnly: true } }).resolve('https://secrets.acme.example');
  assert.equal(legacy.mode === 'signin' && legacy.signin.useOnly, true);
  // What the deployment still writes in signin is named, for the object it moved to.
  const old = signin({ providers, serviceTokenMaxDays: 90, workloads: { limits, useOnly: true } });
  assert.deepEqual(old.moved, [
    { old: 'signin({ serviceTokenMaxDays })', options: { services: { tokenMaxDays: 90 } } },
    { old: 'signin({ workloads: { useOnly } })', options: { services: { useOnly: true } } },
  ]);
});
