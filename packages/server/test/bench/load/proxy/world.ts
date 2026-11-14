// The proxy run's instance, as the Workers test seeds it
// (test/app-workers.test.ts): project `market`, environment `apis` with
// `API_KEY`, a handle of ada's for market/apis, and for each of `--services`
// services `token:deploy-<n>` (a trust binding with a policy, viewer on
// market) one workload session bound to a key of its own. Writes
// <dir>/callers.json: the handle, and each session's token and key (the
// private one as a JWK) for load.ts to sign its proofs with. The log is
// grown by world.ts grow, as for the reveal run.
//
//   node --conditions=coffre:source proxy/world.ts <dir> [services]
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { thumbprint, type PublicJwk } from '@coffre/client/dpop';
import { generateToken } from '@coffre/core/identity';
import { binding, credential, emptyDatabase, environment, grant, instance, openConfiguredVault, principal, project, role, rows, secret, session, user, value, write } from '@coffre/vault/testing';

const [dir, services = '1'] = process.argv.slice(2);
const { world } = await openConfiguredVault({ kek: { id: 'bench', key: process.env.BENCH_VAULT_KEY! }, owners: ['root@acme.example'] });
try {
  await emptyDatabase(world.owner);
  const ada = user('ada');
  const market = project('market');
  const apis = environment(market, 'apis');
  const apiKey = await value(world, secret(apis, 'API_KEY'), 'sk_workers_0123456789');
  const handle = generateToken('handle');
  const sessions = await Promise.all(Array.from({ length: Number(services) }, async (_, n) => {
    const service = `token:deploy-${n}`;
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const jwk: PublicJwk = { kty: kty as 'EC', crv: crv as 'P-256', x: x!, y: y! };
    const bound = binding(service, { policy: '{}', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]) });
    const token = generateToken('workload');
    return { service, bound, token, jwk, privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey), row: session(token, bound, { jkt: await thumbprint(jwk), places: JSON.stringify([{ environmentId: apis.id }]) }) };
  }));
  await write(
    world,
    ...rows('projects', market),
    ...rows('environments', apis),
    ...rows('secrets', apiKey),
    ...rows('roles', role(false, 'viewer', ['secret.read', 'secret.use'], []), role(true, 'member', [])),
    ...rows('policy', instance()),
    ...rows('principals', principal(ada), ...sessions.map((s) => principal(s.service))),
    ...rows('grants', grant(ada, 'viewer', { project: market }), ...sessions.map((s) => grant(s.service, 'viewer', { project: market }))),
    ...rows('bindings', ...sessions.map((s) => s.bound)),
    ...rows('credentials',
      credential(handle, ada, { kind: 'handle', scope: JSON.stringify([{ projectId: market.id, environmentId: apis.id, role: 'viewer' }]), places: JSON.stringify([{ environmentId: apis.id, personal: false }]) }),
      ...sessions.map((s) => s.row)),
  );
  writeFileSync(join(dir!, 'callers.json'), JSON.stringify({ handle, sessions: sessions.map(({ service, token, jwk, privateJwk }) => ({ service, token, jwk, privateJwk })) }));
  console.log(JSON.stringify({ setup: true, services: sessions.length }));
} finally {
  await world.close();
}
