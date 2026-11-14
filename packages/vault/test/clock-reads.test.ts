// The vault's reads of who is asking, as Hyperdrive gets them: each selects
// the database's clock, `clock_timestamp()`, and Hyperdrive caches no
// statement that does. Its caching is off in every deployment (`coffre
// setup` makes both configs with `--caching-disabled`); this holds if one
// forgets. A credential revoked, a grant ended or a member removed is then
// never read as it was. 0.14.7's `db/hyperdrive-cache.test.ts` held the
// app's credential lookup to it; on 0.16 that lookup is the vault's.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { openDatabase } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';
import { principals } from '@coffre/db/schema';

import { caller } from '../src/caller.ts';
import { change, part, put } from '../src/change.ts';
import { memoryOf, use } from '../src/use.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';
import { emptyDatabase, openTestVault, VAULT_URL } from './database.ts';
import { ask, credential, environment, grant, principal, project, role, rows, tokenOf, user, write } from './world.ts';

const vault = await openTestVault();
after(() => vault.close());

const ada = user('ada');

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  const market = project('market');
  const prod = environment(market, 'prod');
  await write(
    vault,
    ...rows('roles', role(false, 'viewer', ['secret.read'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(ada)),
    ...rows('grants', grant(ada, 'viewer', { project: market })),
    ...rows('credentials', credential('ada', ada)),
  );
});

/**
 * What `run` sent through a proxy like Hyperdrive, one array a round trip,
 * with the vault's memory off so every call reads: the statements alone,
 * without the transaction's own (`begin`, its bounds, `commit`).
 */
async function sentBy(run: (through: typeof vault) => Promise<unknown>): Promise<string[][]> {
  const sent: string[][] = [];
  const proxy = await postgresProxy(VAULT_URL, { onSync: (statements) => sent.push(statements.map((text) => text.trim())) });
  const through = await openDatabase(proxy.url);
  try {
    await run({ ...vault, db: through.db, memory: memoryOf(0) });
    return sent.map((trip) => trip.filter((text) => !/^(begin|commit|rollback|SELECT set_config)/i.test(text))).filter((trip) => trip.length > 0);
  } finally {
    await through.close();
    await proxy.close();
  }
}

test("a use's read selects the database's clock with the credential it looks up", async () => {
  const sent = await sentBy(async (through) => assert.ok('values' in (await use(through, ask('ada', 'market/prod', null)))));
  const lookups = sent.flat().filter((text) => /\bcredentials\b/i.test(text) && /\btoken_hash\b/i.test(text));
  assert.equal(lookups.length, 1, JSON.stringify(sent));
  assert.match(lookups[0]!, /clock_timestamp\(\)/);
});

test("who is asking, the read every API request starts with, selects the database's clock", async () => {
  const sent = await sentBy(async (through) => {
    const answer = await caller(through, { token: tokenOf('ada'), proof: null, ip: null });
    assert.ok(!('refused' in answer), JSON.stringify(answer));
  });
  const [read] = sent;
  assert.equal(read!.length, 1, JSON.stringify(sent));
  assert.match(read![0]!, /token_hash/);
  assert.match(read![0]!, /clock_timestamp\(\)/);
});

test("a change's read selects the database's clock, as its write is held to it", async () => {
  const sent = await sentBy(async (through) => {
    const result = await change(through, {
      read: { asking: part(principals, sql`${principals.id} = ${ada}`) },
      decide: ({ asking }) => ({ writes: asking.length === 1 ? [put(principals, principal(user('bo')))] : [], entry: { kept: true, action: 'test.write' as never, actor: ada, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }),
    });
    assert.ok(!('refused' in result), JSON.stringify(result));
  });
  // Its read, then its write.
  assert.equal(sent.length, 2, JSON.stringify(sent));
  assert.equal(sent[0]!.length, 1, JSON.stringify(sent));
  assert.match(sent[0]![0]!, /^select\b/i);
  assert.match(sent[0]![0]!, /clock_timestamp\(\)/);
});
