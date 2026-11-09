// The lookups behind a standing refusal (`#standingRefusal`, at each checkpoint and verification, bounded or not)
// cost the same however many refused checkpoints came since the last signed (T245, R48): a vault whose KEK is wrong,
// or whose log is broken, is refused one a beat for as long as it lasts. The newest signed checkpoint
// (`latestVaultEntry`) and the newest refusal for a broken log since (`newestRefusal`), each one step of an index of
// its own, where the walk back by `(author, action, seq)` read every refusal: 327 pages at 10,000, 3,252 at 100,000.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { latestVaultEntry, newestRefusal } from '../src/store.ts';
import { CHECKPOINT } from '../src/tally.ts';
import { openTestDatabase, postgresOnly, rows, VAULT_URL, withLogUnlocked, type TestDatabase } from './database.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());

type Statement = { text: string; values: unknown[] };
type Node = { 'Shared Hit Blocks': number; 'Shared Read Blocks': number; 'Index Name'?: string; Plans?: Node[] };

const ZERO = Buffer.alloc(32);

/** `count` of the vault's checkpoint entries after the newest, `decision` for `code`. */
async function checkpoints(count: number, decision: 'allow' | 'deny', code: string | null): Promise<void> {
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => tx.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, prev_hash, mac, hash, metadata)
      SELECT coalesce((SELECT max(seq) FROM audit_log), 0) + g, 'vault', 'vault:k', ${Date.now()}::bigint + g, 'system:coffre', ${CHECKPOINT}, ${decision}, ${code},
        ${ZERO}, ${ZERO}, ${ZERO}, '{}'
      FROM generate_series(1, ${Math.min(20_000, left)}) g`));
  }
  await db.owner.execute(sql`VACUUM (ANALYZE, PARALLEL 0) audit_log`);
}

/** Each statement `work` sends, through a client of the vault's login. */
async function sent(work: (vault: ReturnType<typeof createDatabase>) => Promise<unknown>): Promise<Statement[]> {
  const client = postgresClient(VAULT_URL, { max: 1 });
  const seen: Statement[] = [];
  const unsafe = client.unsafe;
  (client as { unsafe: unknown }).unsafe = (text: string, values: unknown[] = [], ...rest: unknown[]) => {
    seen.push({ text, values });
    return (unsafe as (...args: unknown[]) => unknown)(text, values, ...rest);
  };
  try {
    await work(createDatabase(client));
    return seen;
  } finally {
    await client.end();
  }
}

/** The pages a statement reads, run again under EXPLAIN as the vault's login, and the indexes it reads them by. */
async function pages(statement: Statement): Promise<{ pages: number; indexes: string[] }> {
  const one = postgresClient(VAULT_URL, { max: 1 });
  try {
    await one.unsafe(`EXPLAIN ${statement.text}`, statement.values as never[]);
    const [row] = await one.unsafe(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`, statement.values as never[]);
    const plan = (row as unknown as { 'QUERY PLAN': [{ Plan: Node }] })['QUERY PLAN'][0].Plan;
    const indexes = (node: Node): string[] => [...(node['Index Name'] === undefined ? [] : [node['Index Name']]), ...(node.Plans ?? []).flatMap(indexes)];
    return { pages: plan['Shared Hit Blocks'] + plan['Shared Read Blocks'], indexes: indexes(plan) };
  } finally {
    await one.end();
  }
}

test("the newest signed checkpoint and a broken log's refusal since are one step each, however many checkpoints were refused since (T245, R48)", { ...postgresOnly('it reads Postgres query plans'), timeout: 300_000 }, async () => {
  await checkpoints(1, 'allow', null);
  const [signed] = await rows<{ seq: string }>(db.owner, sql`SELECT max(seq)::text AS seq FROM audit_log`);
  const measured = async () => {
    const statements = await sent(async (vault) => {
      const found = await latestVaultEntry(vault, [CHECKPOINT]);
      assert.equal(found?.seq, BigInt(signed!.seq), 'the signed checkpoint, past every refusal');
      assert.equal(await newestRefusal(vault, CHECKPOINT, 'log_broken', found!.seq), undefined, 'no refusal for a broken log');
    });
    return Promise.all(statements.filter(({ text }) => /^\s*select\b/i.test(text)).map(pages));
  };
  // Refused for a wrong KEK, one a beat: 10,000 is a week's, 100,000 two months'.
  await checkpoints(10_000, 'deny', 'wrong_kek');
  const small = await measured();
  await checkpoints(90_000, 'deny', 'wrong_kek');
  const grown = await measured();
  const said = JSON.stringify({ small, grown });
  assert.equal(grown.length, 2, said);
  for (const { pages: read } of [...small, ...grown]) assert.ok(read <= 8, said);
  assert.deepEqual(grown.map(({ indexes }) => indexes), [['audit_log_vault_allowed_idx'], ['audit_log_vault_refused_idx']], said);
});
