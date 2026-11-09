// The lookups behind a standing refusal (`#standingRefusal`, at each checkpoint and verification, bounded or not)
// cost the same however many refused checkpoints came since the last signed (T245, R48): a vault whose KEK is wrong,
// or whose log is broken, is refused one a beat for as long as it lasts. The newest signed checkpoint
// (`latestSigned`) and the newest refusal for a broken log since (`newestRefusal`), each one step of an index of
// its own, where the walk back by `(author, action, seq)` read every refusal: 327 pages at 10,000, 3,252 at 100,000.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { createDatabase } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { latestSigned, latestTallied, newestRefusal } from '../src/store.ts';
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

/** `count` of the vault's checkpoint entries after the newest, `decision` for `code`: each one allowed signs the log through the entry before it. */
async function checkpoints(count: number, decision: 'allow' | 'deny', code: string | null): Promise<void> {
  for (let left = count; left > 0; left -= 20_000) {
    await withLogUnlocked(db.owner, (tx) => tx.execute(sql`
      INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, code, related_seq, prev_hash, mac, hash, metadata)
      SELECT newest + g, 'vault', 'vault:k', ${Date.now()}::bigint + g, 'system:coffre', ${CHECKPOINT}, ${decision}, ${code},
        CASE WHEN ${decision} = 'allow' THEN nullif(newest + g - 1, 0) END, ${ZERO}, ${ZERO}, ${ZERO}, '{}'
      FROM (SELECT coalesce(max(seq), 0) AS newest FROM audit_log) head, generate_series(1, ${Math.min(20_000, left)}) g`));
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

/**
 * The pages a statement reads, run again under EXPLAIN as the vault's login, and the indexes it reads them by:
 * planned for its values, as coffre's unnamed statements are, or, `generic`, for any values, as a named
 * statement is from its sixth run, which proves a partial index's condition only from constants.
 */
async function pages(statement: Statement, generic = false): Promise<{ pages: number; indexes: string[] }> {
  const one = postgresClient(VAULT_URL, { max: 1, connection: generic ? { plan_cache_mode: 'force_generic_plan' } : {} });
  try {
    // EXPLAIN of a statement given its values plans for them whatever plan_cache_mode says; EXPLAIN EXECUTE of a named one takes its generic plan.
    // Its values as literals there: a parameter in a utility statement has no type Postgres can infer.
    const literals = statement.values.map((value) => `'${String(value).replaceAll("'", "''")}'`).join(', ');
    const explained = generic
      ? `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE measured${statement.values.length === 0 ? '' : `(${literals})`}`
      : `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${statement.text}`;
    const bound = (generic ? [] : statement.values) as never[];
    if (generic) await one.unsafe(`PREPARE measured AS ${statement.text}`);
    await one.unsafe(explained, bound);
    const [row] = await one.unsafe(explained, bound);
    const plan = (row as unknown as { 'QUERY PLAN': [{ Plan: Node }] })['QUERY PLAN'][0].Plan;
    const indexes = (node: Node): string[] => [...(node['Index Name'] === undefined ? [] : [node['Index Name']]), ...(node.Plans ?? []).flatMap(indexes)];
    return { pages: plan['Shared Hit Blocks'] + plan['Shared Read Blocks'], indexes: indexes(plan) };
  } finally {
    await one.end();
  }
}

test("the newest signed checkpoint and a broken log's refusal since are one step each, however many checkpoints were refused since (T245, R48)", { ...postgresOnly('it reads Postgres query plans'), timeout: 300_000 }, async () => {
  // A history of signed checkpoints first, so that Postgres's statistics hold allowed ones common, as a deployment's do.
  await checkpoints(30_000, 'allow', null);
  const [signed] = await rows<{ seq: string }>(db.owner, sql`SELECT max(seq)::text AS seq FROM audit_log`);
  const measured = async () => {
    const statements = await sent(async (vault) => {
      const found = await latestSigned(vault);
      assert.equal(found?.seq, BigInt(signed!.seq), 'the signed checkpoint, past every refusal');
      assert.equal(await newestRefusal(vault, CHECKPOINT, 'log_broken', found!.seq), undefined, 'no refusal for a broken log');
      assert.equal((await latestTallied(vault))?.seq, found!.seq, 'the newest checkpoint that keeps a tally');
    });
    const selects = statements.filter(({ text }) => /^\s*select\b/i.test(text));
    // A generic plan for the two allowed lookups too, whose conditions are constants (`signedCheckpoints`). Not for the refusal's:
    // coffre plans each statement for its values, and a plan for any `code` takes a refusal of another for one of it.
    const allowed = [selects[0]!, selects[2]!];
    return [...await Promise.all(selects.map((statement) => pages(statement))), ...await Promise.all(allowed.map((statement) => pages(statement, true)))];
  };
  // Refused for a wrong KEK, one a beat: 10,000 is a week's, 100,000 two months'.
  await checkpoints(10_000, 'deny', 'wrong_kek');
  const small = await measured();
  await checkpoints(90_000, 'deny', 'wrong_kek');
  const grown = await measured();
  const said = JSON.stringify({ small, grown });
  // The signed checkpoint, the refusal since and the tally, each planned for its values, then the two allowed for any values.
  const by = ['audit_log_signed_idx', 'audit_log_vault_refused_idx', 'audit_log_signed_idx', 'audit_log_signed_idx', 'audit_log_signed_idx'];
  for (const measured of [small, grown]) {
    assert.equal(measured.length, by.length, said);
    measured.forEach(({ pages: read, indexes }, i) => assert.ok(read <= 8 && indexes.includes(by[i]!), said));
  }
});
