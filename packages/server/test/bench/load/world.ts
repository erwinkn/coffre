// The load rig's instance, and its log grown to size.
//
//   node --conditions=coffre:source world.ts setup            empty the database, write the instance
//   node --conditions=coffre:source world.ts grow <entries>   grow the log to <entries>, through the signer
//
// The instance: project `bench`, environment `prod`, 100 keys KEY_0…KEY_99,
// and a service account `token:bench-ci` that reads them (viewer), whose
// token is `bench-ci-token`. Written as a vault of the rig's key writes it
// (`@coffre/vault/testing`), so the Worker's vault reads it as its own.
//
// The log grows the way requests grow it: entries appended to `log_pending`,
// each under the vault's MAC, dated now, and the signer told of them. The
// signer, the vault Worker's Durable Object, numbers them, writes `log`,
// `log_index` and the tiles, and signs the head, 256 a run. So the indexes
// and the signer's own state are what a real log of that size leaves. The
// entries are uses (`secret.read`, the tree that ages out) and one in ten a
// change (`secret.write`, kept), each naming a secret, a principal and a
// credential; one in ten names the bench's own secrets and service account,
// so the rows the bench's reads could touch grow with the log too.
import { randomUUID } from 'node:crypto';

import { rowsOf } from '@coffre/db/dialect';
import { logPending } from '@coffre/db/schema';
import { credential, emptyDatabase, environment, grant, openConfiguredVault, pending, principal, project, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

const VAULT_KEY = process.env.BENCH_VAULT_KEY!;
const CONTROL = process.env.BENCH_CONTROL_URL ?? '';
export const KEYS = Array.from({ length: 100 }, (_, i) => `KEY_${i}`);
const SERVICE = 'token:bench-ci';

const { world } = await openConfiguredVault({ kek: { id: 'bench', key: VAULT_KEY }, owners: ['root@acme.example'] });
const count = async (table: string) => (await rowsOf<{ n: number }>(world.owner, sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`))[0]!.n;

async function setup(): Promise<void> {
  await emptyDatabase(world.owner);
  const bench = project('bench');
  const prod = environment(bench, 'prod');
  const secrets = KEYS.map((key) => value(world, secret(prod, key), `value of ${key}, ${'x'.repeat(40)}`));
  await write(
    world,
    ...rows('projects', bench),
    ...rows('environments', prod),
    ...rows('secrets', ...secrets),
    ...rows('roles', role(false, 'viewer', ['secret.read'], []), role(true, 'member', [])),
    ...rows('principals', principal(SERVICE), principal('user:root@acme.example')),
    ...rows('grants', grant(SERVICE, 'viewer', { project: bench })),
    // A service token's scope caps it: here, viewer on the project, as `coffre tokens issue` would.
    ...rows('credentials', credential('bench-ci-token', SERVICE, { scope: JSON.stringify([{ projectId: bench.id, environmentId: null, role: 'viewer' }]) })),
  );
  console.log(JSON.stringify({ setup: true, secrets: secrets.map((s) => s.id).slice(0, 3) }));
}

async function grow(target: number): Promise<void> {
  const ids = await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM secrets ORDER BY key`);
  const own = ids.map((row) => row.id);
  const [key] = world.keys;
  const started = Date.now();
  let written = 0;
  let last = '';
  const logged = async () => (await count('log')) + (await count('log_pending'));
  let have = await logged();
  const BATCH = 2048;
  while (have < target) {
    const waiting = await count('log_pending');
    if (waiting < 4 * BATCH) {
      const n = Math.min(BATCH, target - have);
      const batch = Array.from({ length: n }, (_, i) => {
        const mine = (written + i) % 10 === 0;
        const kept = (written + i) % 10 === 5;
        const secretId = mine ? own[(written + i) % own.length]! : randomUUID();
        const actor = mine ? SERVICE : `user:person-${(written + i) % 5000}@acme.example`;
        const credentialId = mine ? 'bench' : randomUUID();
        return pending(key!, {
          kept, action: kept ? 'secret.write' : 'secret.read', actor, credential: credentialId, request: randomUUID(), ip: '192.0.2.7',
          objects: [`secret:${secretId}`, `principal:${actor}`, `credential:${credentialId}`],
          detail: { keys: [{ key: `KEY_${(written + i) % 100}`, version: 1 }], purpose: 'reveal' },
        }, Date.now(), []);
      });
      await world.owner.insert(logPending).values(batch.map(({ kept, body, mac }) => ({ kept, body, mac })));
      written += n;
      have += n;
      last = batch.at(-1)!.hash.toString('hex');
      // The signer, told of the newest: it runs a second on, and again at once while entries wait.
      await fetch(`${CONTROL}/wake?hash=${last}`);
    } else {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (written % (BATCH * 25) === 0) console.log(JSON.stringify({ written, waiting, rate: Math.round(written / ((Date.now() - started) / 1000)) }));
  }
  for (;;) {
    const waiting = await count('log_pending');
    if (waiting === 0) break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  console.log(JSON.stringify({ grown: await count('log'), index: await count('log_index'), seconds: Math.round((Date.now() - started) / 1000) }));
}

try {
  const [what, n] = process.argv.slice(2);
  if (what === 'setup') await setup();
  else if (what === 'grow') await grow(Number(n));
  else throw new Error('usage: world.ts setup | grow <entries>');
} finally {
  await world.close();
}
