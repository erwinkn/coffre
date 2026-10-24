import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import type { ScopeGrant } from '@coffre/core/access';
import type { BindingPolicy } from '@coffre/core/identity';

import { placesOf, sessionScope, signedUrl } from '../src/workload-sessions.ts';
import { propertySettings } from '../../../scripts/property-settings.ts';

// Properties of a workload session's pure parts (docs/design/workload-access.md,
// sections 5.3 and 6.1): the scope a session holds, and the URL its proof is
// checked against. Each is held to what it must be, not to how it is computed.

const ORIGIN = 'https://secrets.acme.example';
const settings = propertySettings(64);

const uuid = gs.fromRegex('[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', { fullmatch: true });

const grant = gs.composite((tc): ScopeGrant => ({
  projectId: tc.draw(gs.sampledFrom(['10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002'])),
  environmentId: tc.draw(gs.optional(gs.sampledFrom(['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000003']))),
  role: tc.draw(gs.sampledFrom(['viewer', 'developer'])),
  permissions: { normal: ['secret.read', 'secret.use'], protected: ['secret.use'] },
  sensitive: tc.draw(gs.booleans()),
}));

const reads = gs.composite((tc): NonNullable<BindingPolicy['reads']> => {
  const places = tc.draw(gs.arrays(gs.sampledFrom(['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000004']), { maxSize: 3 }));
  return Object.fromEntries([...new Set(places)].map((place) => [place, tc.draw(gs.booleans()) ? { keys: '*' as const } : { keys: tc.draw(gs.arrays(uuid, { minSize: 1, maxSize: 3 })) }]));
});

test(`a session's scope is its stored scope, no grant added or widened, and a grant reads exactly what its own environment lists, seed ${settings.seed}`, () => hegel.test((tc) => {
  // A stored scope names each place once.
  const stored = [...new Map(tc.draw(gs.arrays(grant, { maxSize: 5 })).map((one) => [`${one.projectId}/${one.environmentId}`, one])).values()];
  const listed = tc.draw(reads);
  const ownScope = tc.draw(gs.booleans());
  const scope = sessionScope({ scope: ownScope ? JSON.stringify(stored) : null }, { scope: ownScope ? '[]' : JSON.stringify(stored) }, { reads: listed });
  assert.equal(scope.length, stored.length);
  scope.forEach((held, i) => {
    const { reads: attached, ...rest } = held;
    assert.deepEqual(rest, stored[i], 'the same place, role, permissions and sensitivity');
    const own = held.environmentId === null ? undefined : listed[held.environmentId]?.keys;
    assert.deepEqual(attached, own, 'its own environment\'s list, and none on a project\'s grant');
  });
}, settings));

test(`a proof is checked against the request's path and query as received, on publicUrl's origin, whatever the path, seed ${settings.seed}`, () => hegel.test((tc) => {
  const segments = tc.draw(gs.arrays(gs.fromRegex('[A-Za-z0-9._~%-]{0,6}', { fullmatch: true }), { minSize: 1, maxSize: 4 }));
  const path = `/${segments.join('/')}`;
  const query = tc.draw(gs.optional(gs.fromRegex('[a-z]{1,3}=[a-z0-9]{0,4}(&[a-z]{1,3}=[a-z0-9]{0,4}){0,2}', { fullmatch: true })));
  // The request as the platform hands it over: another host, a port, a path that starts like a host.
  const host = tc.draw(gs.sampledFrom(['http://10.0.0.7:8080', 'https://coffre.internal', ORIGIN]));
  const received = new URL(`${host}${path}${query === null ? '' : `?${query}`}`);
  const url = new URL(signedUrl(new Request(received), ORIGIN));
  assert.equal(url.origin, ORIGIN);
  assert.equal(url.pathname, received.pathname);
  assert.equal(url.search, received.search);
}, settings));

test(`a session's places are the environment IDs its row lists, and nothing from a row that lists none, seed ${settings.seed}`, () => hegel.test((tc) => {
  const ids = tc.draw(gs.arrays(uuid, { maxSize: 4 }));
  assert.deepEqual(placesOf(JSON.stringify(ids.map((environmentId) => ({ environmentId, personal: false })))), ids);
  assert.deepEqual(placesOf(null), []);
  assert.deepEqual(placesOf(tc.draw(gs.sampledFrom(['', '{', '{}', '"x"', '[1]']))), []);
}, settings));
