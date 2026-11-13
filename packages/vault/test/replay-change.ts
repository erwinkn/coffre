// Holds the vault's change to its model: replays runs of formal/quint/change.qnt,
// as Quint's simulator writes them, against src/change.ts on Postgres. Each
// step names the action the model took and what it picked; after each one,
// the rows in the database must be the model's.
//
//   quint run change.qnt --main sound --mbt --n-traces 500 --max-samples 500 --max-steps 40 --out-itf 't{seq}.itf.json'
//   node --conditions=coffre:source test/replay-change.ts t*.itf.json
//
// The model's uses and its clock change no row, and are skipped until the
// use is built.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { and, eq, sql } from 'drizzle-orm';

import { change, commit, part, prepare, put, type Operation, type Prepared, type Seen } from '../src/change.ts';
import type { Fresh, Row } from '../src/rows.ts';
import { emptyDatabase, openTestVault } from './database.ts';

type Role = 'Out' | 'Member' | 'Owner';
type Op = 'Promote' | 'Demote' | 'Remove';
type State = { actionTaken: string; nondetPicks: { p?: string; t?: string; op?: Op }; role: Record<string, Role>; gen: Record<string, number>; chg: Record<string, { decided: boolean }> };

/** ITF's big integers, maps, sets, tuples and variants, as plain values, each variable under its own name. */
function plain(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(plain);
  if (value === null || typeof value !== 'object') return value;
  const v = value as Record<string, unknown>;
  if ('#bigint' in v) return Number(v['#bigint']);
  if ('#map' in v) return Object.fromEntries((v['#map'] as [string, unknown][]).map(([key, item]) => [key, plain(item)]));
  if ('#set' in v) return (v['#set'] as unknown[]).map(plain);
  if ('#tup' in v) return (v['#tup'] as unknown[]).map(plain);
  if ('tag' in v && 'value' in v) return v.tag === 'Some' ? plain(v.value) : v.tag === 'None' ? undefined : v.tag;
  return Object.fromEntries(Object.entries(v).map(([key, item]) => [key.split('::').at(-1)!, plain(item)]));
}

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
let [steps, refusals, lost] = [0, 0, 0];
try {
  for (const file of process.argv.slice(2)) {
    const states = (JSON.parse(readFileSync(file, 'utf8')) as { states: unknown[] }).states.map(plain) as State[];
    await emptyDatabase(vault.owner);
    const people = Object.keys(states[0]!.role);
    const admitted = people.map((person): Fresh<typeof principals> => ({
      id: id(person), status: 'active', role: 'owner', scope: null, generation: 0, createdAt: at, createdBy: id(person), statusChangedAt: at, statusChangedBy: id(person), frozenAt: null,
    }));
    await change(vault, { read: { none: part(principals, sql`false`) }, decide: () => ({ writes: admitted.map((row) => put(principals, row)), entry: { kept: true, action: 'test.admit', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }) });
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
console.log(`replayed ${process.argv.length - 2} runs, ${steps} steps, ${refusals} refusals, ${lost} writes that lost: the vault's change agrees with the model`);
