// 0.14.7's log grown to size the way its own appends write it:
// `appendEntries` (@coffre/db/log), under the app's key, in transactions of
// 2,000, each locking the head, chaining and MACing each entry, and
// inserting through every index of `audit_log`. Reveals of the bench's keys
// by many actors, one in ten naming the bench's project, environment and a
// secret of it, so the indexes the bench's reads could touch grow too.
//
// Copied into a v0.14.7 export's packages/db/scripts/ (run-014.sh), then
//   node --conditions=coffre:source grow.ts <owner url> <entries> <APP_KEY base64>
import { randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';

import { openDatabase } from '../src/connect.ts';
import { appendEntries } from '../src/log.ts';
import { sql } from 'drizzle-orm';

const [url, target, appKey] = process.argv.slice(2);
const { db, close } = await openDatabase(url!);
const key = deriveLogKey('app', Buffer.from(appKey!, 'base64'));
const rows = async <T>(query: ReturnType<typeof sql>) => ((await db.execute(query)) as unknown as { rows?: T[] }).rows ?? ((await db.execute(query)) as unknown as T[]);
const [place] = await rows<{ project: string; environment: string }>(sql`SELECT e.project_id AS project, e.id AS environment FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.slug = 'bench' AND e.slug = 'prod'`);
const secrets = (await rows<{ id: string }>(sql`SELECT s.id FROM secrets s WHERE s.environment_id = ${place!.environment}`)).map((row) => row.id);
const count = async () => Number((await rows<{ n: string }>(sql`SELECT next_seq AS n FROM audit_chain_head`))[0]?.n ?? 0);
const started = Date.now();
let have = await count();
let i = 0;
while (have < Number(target)) {
  const n = Math.min(2000, Number(target) - have);
  await db.transaction(async (tx) => {
    await appendEntries(tx, key, Array.from({ length: n }, () => {
      i += 1;
      const mine = i % 10 === 0;
      return {
        actor: mine ? 'token:bench-ci' : `user:person-${i % 5000}@acme.example`, action: 'secret.reveal', decision: 'allow',
        projectId: mine ? place!.project : null, environmentId: mine ? place!.environment : null, secretId: mine ? secrets[i % secrets.length]! : null,
        operationId: randomUUID(), requestId: randomUUID(), sourceIp: '192.0.2.7', metadata: JSON.stringify({ keys: [`KEY_${i % 100}`] }),
      };
    }));
  });
  have += n;
  if (i % 100_000 < 2000) console.log(JSON.stringify({ have, rate: Math.round(i / ((Date.now() - started) / 1000)) }));
}
console.log(JSON.stringify({ grown: await count(), seconds: Math.round((Date.now() - started) / 1000) }));
await close();
