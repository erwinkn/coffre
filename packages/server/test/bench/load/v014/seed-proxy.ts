// 0.14.7's side of the load rig: the same instance as world.ts writes for
// 0.16 (project `bench`, environment `prod`, KEY_0…KEY_99, a service
// account `token:bench-ci` reading them as viewer), made through 0.14.7's
// own API, by its conformance harness (`wrangler dev`, the dev IdP). It
// prints the database the harness made and the service token, and leaves
// the database for run.ts --version 0.14.7 to serve: the harness's own
// `stop` would drop it.
//
// Copied into a v0.14.7 export's packages/conformance/scripts/ (run-014.sh), then
//   node --conditions=coffre:source seed.ts <examples/workers> --postgres <owner url> --runtime <url> --vault-runtime <url>
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { signInAdmin } from '../src/checks/people.ts';
import { boot } from '../src/harness.ts';

const { values, positionals } = parseArgs({ allowPositionals: true, options: { postgres: { type: 'string' }, runtime: { type: 'string' }, 'vault-runtime': { type: 'string' }, port: { type: 'string', default: '3382' } } });
const deployment = await boot('workers', resolve(positionals[0]!), { port: Number(values.port), postgres: values.postgres, runtime: values.runtime, vaultRuntime: values['vault-runtime'] });
const { value: admin } = await signInAdmin(deployment);
await admin.api.projects.create('bench', { name: 'Bench' });
await admin.api.environments.create('bench/prod', { name: 'prod' });
await admin.api.secrets.set('bench/prod', Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`KEY_${i}`, `value of KEY_${i}, ${'x'.repeat(40)}`])));
await admin.api.members.add('token:bench-ci');
await admin.api.access.set('token:bench-ci', { 'bench/prod': 'viewer' });
const { token } = await admin.api.tokens.issue('token:bench-ci', { label: 'bench', expiresInDays: 7 });
// The proxy run (W424 vs W422's #731): market/apis's API_KEY, and the admin's handle for it, as W422's proxy/world.ts has.
await admin.api.projects.create('market', { name: 'Market' });
await admin.api.environments.create('market/apis', { name: 'apis' });
await admin.api.secrets.set('market/apis', { API_KEY: 'sk_workers_9876543210' });
const { token: handle } = await admin.api.handles.create({ label: 'bench', paths: ['market/apis'], expiresInMinutes: 7 * 24 * 60 });
const check = await fetch(`${deployment.origin}/api/reveals`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ path: 'bench/prod/KEY_0' }) });
const sql = await deployment.database();
const [{ name }] = await sql.query<{ name: string }>('SELECT current_database() AS name');
await sql.close();
console.log(JSON.stringify({ database: name, token, handle, reveal: check.status }));
// Its processes, not its database.
process.kill(-deployment.serving().wrangler!, 'SIGTERM');
process.exit(0);
