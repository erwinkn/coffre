// Holds the vault's change to its model: replays runs of formal/quint/change.qnt,
// as Quint's simulator writes them, against src/change.ts on Postgres. Each
// step names the action the model took and what it picked; after each one,
// the rows in the database must be the model's.
//
//   quint run change.qnt --main sound --mbt --n-traces 500 --max-samples 500 --max-steps 40 --out-itf 't{seq}.itf.json'
//   node --conditions=coffre:source test/replay-change.ts t*.itf.json
//
// A use is the model's two steps too, src/use.ts on the same database: at
// `useStart` the vault's memory must hold the read exactly when the model's
// does, and at `useAnswer` the answer must be the model's. The model's clock
// is the vault's, a second a tick, and its TTL the memory's two seconds.
import assert from 'node:assert/strict';

import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { and, eq, sql } from 'drizzle-orm';

import { change, commit, part, prepare, put, type Operation, type Prepared, type Seen } from '../src/change.ts';
import type { Fresh, Row } from '../src/rows.ts';
import { answer, memoryOf, read, recall, type Read } from '../src/use.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { statesOf } from './itf.ts';
import { amend, ask, credential, environment, grant, project, role, rows, secret, value, write } from './world.ts';

type Role = 'Out' | 'Member' | 'Owner';
type Op = 'Promote' | 'Demote' | 'Remove';
type State = {
  actionTaken: string; nondetPicks: { p?: string; t?: string; op?: Op }; role: Record<string, Role>; gen: Record<string, number>; chg: Record<string, { decided: boolean }>;
  use: Record<string, { reading: boolean; ok: boolean }>;
};

const id = (person: string) => `user:${person}@acme.example`;
const at = new Date(Date.UTC(2026, 10, 13));
const after: Record<Op, Role> = { Promote: 'Owner', Demote: 'Member', Remove: 'Out' };
const roleOf = (row: Pick<Row<typeof principals>, 'status' | 'role'>): Role => (row.status === 'removed' ? 'Out' : row.role === 'owner' ? 'Owner' : 'Member');

/** The model's `may`, over rows: an Owner promotes, demotes or removes, and never the last Owner. A removal moves the generation on. */
function act(p: string, op: Op, t: string) {
  const read = {
    caller: part(principals, eq(principals.id, id(p))),
    target: part(principals, eq(principals.id, id(t))),
    owners: part(principals, and(eq(principals.role, 'owner'), eq(principals.status, 'active'))),
  };
  return {
    read,
    decide({ caller: [by], target: [who], owners }: Seen<typeof read>) {
      const was = roleOf(who!);
      if (roleOf(by!) !== 'Owner' || after[op] === was || (op === 'Demote' && was !== 'Owner') || (op !== 'Promote' && was === 'Owner' && owners.length <= 1)) return { refused: 'no' };
      const { mac: _, ...kept } = who!;
      const row = op === 'Remove' ? { ...kept, status: 'removed', role: 'member', generation: kept.generation + 1 } : { ...kept, status: 'active', role: op === 'Promote' ? 'owner' : 'member' };
      return { writes: [put(principals, row, who!)], entry: { kept: true, action: 'member.role', actor: id(p), credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null };
    },
  } satisfies Operation<typeof read, null>;
}

const vault = await openTestVault();
let [steps, refusals, lost, uses, remembered] = [0, 0, 0, 0, 0];
try {
  for (const file of process.argv.slice(2)) {
    const states = statesOf<State>(file);
    await emptyDatabase(vault.owner);
    const people = Object.keys(states[0]!.role);
    const admitted = people.map((person): Fresh<typeof principals> => ({
      id: id(person), status: 'active', role: 'owner', scope: null, generation: 0, createdAt: at, createdBy: id(person), statusChangedAt: at, statusChangedBy: id(person), frozenAt: null,
    }));
    await change(vault, { read: { none: part(principals, sql`false`) }, decide: () => ({ writes: admitted.map((row) => put(principals, row)), entry: { kept: true, action: 'test.admit', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }) });
    // What a use reads: one key of one environment, which every member views, whatever their role on the instance.
    const market = project('market');
    const prod = environment(market, 'prod');
    await write(
      vault,
      ...rows('projects', market), ...rows('environments', prod), ...rows('secrets', await value(vault, secret(prod, 'FLAG'), 'on')),
      ...rows('roles', role(true, 'owner', []), role(true, 'member', []), role(false, 'viewer', ['secret.read'])),
      ...rows('grants', ...people.map((person) => grant(id(person), 'viewer', { project: market }))),
    );
    Object.assign(vault, { memory: memoryOf(2) });
    // Each person's newest credential, and the generation it was issued in: someone let back in signs in again.
    const session = new Map<string, { label: string; generation: number }>();
    const asking = (person: string) => ask(session.get(person)?.label ?? 'none', 'market/prod', ['FLAG']);
    const reading = new Map<string, Read>();
    const decided = new Map<string, Prepared<null>>();
    for (const [i, state] of states.entries()) {
      const { p, t, op } = state.nondetPicks;
      const where = `${file} step ${i}: ${state.actionTaken} ${p ?? ''} ${op ?? ''} ${t ?? ''}`;
      if (state.actionTaken === 'read') {
        const prepared = await prepare(vault, act(p!, op!, t!));
        if ('refused' in prepared) refusals += 1;
        else decided.set(p!, prepared);
        // The model's refusal leaves its change undecided.
        assert.equal(!('refused' in prepared), state.chg[p!]!.decided, where);
      } else if (state.actionTaken === 'write') {
        if (!(await commit(vault, decided.get(p!)!))) lost += 1;
        decided.delete(p!);
      } else if (state.actionTaken === 'tick') {
        vault.tick(1000);
      } else if (state.actionTaken === 'useStart') {
        // The model answers from its memory at once, and otherwise reads.
        const hit = !state.use[p!]!.reading;
        const before = states[i - 1]!;
        if (!hit && before.role[p!] !== 'Out' && session.get(p!)?.generation !== before.gen[p!]) {
          session.set(p!, { label: `${p}-${before.gen[p!]}`, generation: before.gen[p!]! });
          await write(vault, ...rows('credentials', credential(session.get(p!)!.label, id(p!), { generation: before.gen[p!]! })));
          // And is granted again: a grant counts only in its member's generation.
          await amend(vault, 'grants', sql`principal = ${id(p!)}`, { generation: before.gen[p!]! });
        }
        const kept = recall(vault, asking(p!));
        assert.equal(kept !== undefined, hit, `${where}: the vault's memory`);
        if (kept === undefined) reading.set(p!, await read(vault, asking(p!)));
        else assert.ok('values' in (await answer(vault, asking(p!), kept)), `${where}: an answer from memory`);
        remembered += hit ? 1 : 0;
      } else if (state.actionTaken === 'useAnswer') {
        const result = await answer(vault, asking(p!), reading.get(p!)!);
        assert.equal('values' in result, states[i - 1]!.use[p!]!.ok, `${where}: ${JSON.stringify(result)}`);
        uses += 1;
      }
      const found = await rowsOf<{ id: string; status: string; role: string; generation: number }>(vault.owner, sql`SELECT id, status, role, generation FROM principals`);
      assert.deepEqual(
        Object.fromEntries(found.map((row) => [row.id, [roleOf(row), row.generation]]).sort()),
        Object.fromEntries(people.map((person) => [id(person), [state.role[person], state.gen[person]]]).sort()),
        where,
      );
      steps += 1;
    }
  }
} finally {
  await vault.close();
}
console.log(`replayed ${process.argv.length - 2} runs, ${steps} steps, ${refusals} refusals, ${lost} writes that lost, ${uses} uses read and ${remembered} answered from memory: the vault agrees with the model`);
