// Holds the signer to its model: replays runs of formal/quint/log.qnt, as
// Quint's simulator writes them, against src/signer.ts on Postgres, with the
// vault's change and a database writer beside it.
//
//   quint run log.qnt --main logSound --mbt --n-traces 1000 --max-samples 1000 --max-steps 30 --out-itf 'l{seq}.itf.json'
//   node --conditions=coffre:source test/replay-log.ts l*.itf.json
//
// and `--main logTwo`, with two rows, where a change to one is decided on the
// other too. The model's row is a member's: MAC 0 is no row, 1 a Member, 2 an Owner. Its
// clock ticks the signer's window, a minute. After each step the log and the
// signer's mirror must be the model's; what waits must be what waits in the
// model, less what the signer refused, which it removes and the model
// leaves; and:
//
// - once the model alerts, the signer has found something;
// - the signer finds nothing unless the writer acted, or a wake-up came late.
//
// So each run holds the signer to finding the first tampering in it, and to
// silence before it. It does not compare what is found after: the model's
// alert stays on, and it says again each run what the signer says once. The
// signer may also find something a step before the model does: it says an
// entry is lost when it moves, and the model, if that was the last one
// signed, at the next full check.
import assert from 'node:assert/strict';

import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { change, drop, part, put } from '../src/change.ts';
import { pending } from '../src/entry.ts';
import { Signer, type Finding, type Snapshot } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { statesOf } from './itf.ts';
import { principal, user } from './world.ts';

type State = {
  actionTaken: string;
  nondetPicks: { row?: string; v?: number; read?: string; sent?: boolean; n?: number; full?: boolean };
  db: { rows: Record<string, number>; pending: number[]; log: number[] };
  signer: { mirror: Record<string, number>; expected: number[]; moving: number[]; alert: boolean };
  world: { attacks: number; slow: boolean };
};
/** An entry the vault made, as it waited: what the writer puts back, and the hash the signer is told. */
type Made = { id: string; kept: boolean; body: string; mac: string; hash: Buffer };

const ROLES = [null, 'member', 'owner'] as const;
const named = (row: string) => JSON.stringify(['principals', user(row)]);
const sorted = (numbers: Iterable<number>) => [...numbers].sort((a, b) => a - b);

const vault = await openTestVault();
let [steps, attacks, found, early] = [0, 0, 0, 0];
try {
  for (const file of process.argv.slice(2)) {
    const states = statesOf<State>(file);
    await emptyDatabase(vault.owner);
    vault.woken.length = 0;
    const store = memoryStore();
    const signer = await Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store, keepUsesDays: 90 });
    const made: Made[] = [];
    /** Each row the vault wrote, by the model's name for its MAC: what the writer puts back. */
    const sealed = new Map<string, typeof principals.$inferSelect>();
    const findings: Finding[] = [];
    /** The entries the signer refused, and so removes: put back, each is one more to refuse. */
    const refused = new Set<number>();
    let snapshot: Snapshot | undefined;

    for (const [i, state] of states.entries()) {
      const { row, v, read, n, full } = state.nondetPicks;
      const before = states[i - 1];
      const where = `${file} step ${i}: ${state.actionTaken || 'the writer'}`;
      if (state.actionTaken === 'commit') {
        const [id, was] = [user(row!), before!.db.rows[row!]!];
        let hash: Buffer;
        if (v === was) {
          // A use: an entry, and no row.
          const entry = pending(vault.keys[0]!, { kept: false, action: 'secret.read', actor: id, credential: null, request: null, ip: null, objects: [], detail: {} }, vault.now(), []);
          await vault.db.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (false, ${entry.body}, decode(${entry.mac.toString('hex')}, 'hex'))`);
          ({ hash } = entry);
        } else {
          const result = await change(vault, {
            // Decided on the row the model read, too: found, its entry names it; missing, it cannot.
            read: { found: part(principals, eq(principals.id, id)), beside: part(principals, read === row ? sql`false` : eq(principals.id, user(read!))) },
            decide: ({ found: [row] }) => ({
              writes: [v === 0 ? drop(principals, row!) : put(principals, principal(id, { role: ROLES[v!]! }), row ?? null)],
              entry: { kept: true, action: 'member.role', actor: null, credential: null, request: null, ip: null, objects: [`principal:${id}`], detail: {} },
              answer: null,
            }),
          });
          assert.ok('answer' in result, where);
          hash = vault.woken.pop()!;
          const [written] = await vault.owner.select().from(principals).where(eq(principals.id, id));
          if (written !== undefined) sealed.set(`${row} ${v}`, written);
        }
        const [waits] = await rowsOf<Omit<Made, 'hash'>>(vault.owner, sql`SELECT id::text, kept, body, encode(mac, 'hex') AS mac FROM log_pending ORDER BY id DESC LIMIT 1`);
        // Its wake-up is on its way until `deliver`, or never left: the vault died first.
        made.push({ ...waits!, hash });
      } else if (state.actionTaken === 'deliver') await signer.wake(made[n!]!.hash);
      else if (state.actionTaken === 'runRead') snapshot = await signer.read(full!);
      else if (state.actionTaken === 'runSign') {
        await signer.sign(snapshot!);
        // The model moves only what was taken. The signer's move also removes what it refused.
        if (state.signer.moving.length === 0) await signer.move();
      } else if (state.actionTaken === 'runMove') await signer.move();
      else if (state.actionTaken === 'tick') vault.tick(60_000);
      else if (state.actionTaken === '') {
        // The writer: whatever differs from the step before, written around the vault.
        attacks += 1;
        for (const [name, mac] of Object.entries(state.db.rows)) {
          if (mac === before!.db.rows[name]) continue;
          if (mac === 0) await vault.owner.delete(principals).where(eq(principals.id, user(name)));
          else await vault.owner.insert(principals).values(sealed.get(`${name} ${mac}`)!).onConflictDoUpdate({ target: principals.id, set: sealed.get(`${name} ${mac}`)! });
        }
        for (const [index, entry] of made.entries()) {
          const [waited, waits] = [before!.db.pending.includes(index), state.db.pending.includes(index)];
          if (waited && !waits) await vault.owner.execute(sql`DELETE FROM log_pending WHERE id = ${entry.id}::bigint`);
          // Back under the id it had, so that it waits in the order it was written, as the model has it.
          if (!waited && waits) refused.delete(index);
          if (!waited && waits) await vault.owner.execute(sql`INSERT INTO log_pending (id, kept, body, mac) OVERRIDING SYSTEM VALUE VALUES (${entry.id}::bigint, ${entry.kept}, ${entry.body}, decode(${entry.mac}, 'hex'))`);
          if (before!.db.log.includes(index) && !state.db.log.includes(index)) await vault.owner.execute(sql`DELETE FROM log WHERE body = ${entry.body}`);
        }
      }

      const numbered = new Map(made.map((entry, index) => [entry.hash.toString('hex'), index]));
      for (const finding of await signer.take()) {
        findings.push(finding);
        if (finding.found === 'replayed' || finding.found === 'stale') refused.add(numbered.get(finding.of)!);
      }
      const said = `${where}: ${JSON.stringify(findings)}`;
      if (state.signer.alert) assert.ok(findings.length > 0, `the model alerts and the signer found nothing, ${said}`);
      if (findings.length > 0) assert.ok(state.world.attacks < states[0]!.world.attacks || state.world.slow, `the signer found something with nobody writing, ${said}`);
      early += findings.length > 0 && !state.signer.alert ? 1 : 0;

      const written = new Map(made.map((entry, index) => [entry.body, index]));
      const bodies = async (table: 'log' | 'log_pending') => (await rowsOf<{ body: string }>(vault.owner, sql`SELECT body FROM ${sql.identifier(table)}`)).map((entry) => written.get(entry.body)!);
      assert.deepEqual(sorted(await bodies('log')), sorted(state.db.log), `the log, ${said}`);
      // What the signer refused it removes, at its move, and nothing else: in the model it waits on.
      const waiting = await bodies('log_pending');
      assert.ok(waiting.every((index) => state.db.pending.includes(index)) && state.db.pending.every((index) => refused.has(index) || waiting.includes(index)), `what waits is ${JSON.stringify(waiting)}, ${said}`);
      for (const [name, mac] of Object.entries(state.signer.mirror)) assert.equal(store.kept.get(`row ${named(name)}`), mac === 0 ? undefined : sealed.get(`${name} ${mac}`)!.mac.toString('hex'), `the mirror, ${said}`);
      steps += 1;
    }
    found += findings.length > 0 ? 1 : 0;
  }
} finally {
  await vault.close();
}
console.log(`replayed ${process.argv.length - 2} runs, ${steps} steps, ${attacks} moves by the writer; the signer found something in ${found} runs, ${early} steps before the model: the signer agrees with the model`);
