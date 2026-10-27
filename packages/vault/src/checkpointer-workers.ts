// The 0.15 checkpointer on Workers (docs/design/audit-tree.md): one Durable
// Object for the instance, which seals the log on its alarm every 500 ms
// and keeps the signer's memory in its own storage. A write to that storage
// is held by the object's output gate until it is durable, so no message
// leaves it, the database write included, before the pair it signed is
// remembered (RememberFirst). It holds one connection to the database
// through the vault's Hyperdrive for as long as it lives: its ticks run one
// at a time, and a Durable Object may keep a connection across requests.
//
// The deployment binds it, exports it (`export const CoffreCheckpointer =
// checkpointer()`, beside `vault(…)`), and starts it once; nothing does yet:
// 0.15's log is switched on in plan PR 10. Asked with `fetch`, as the
// anchor and the gates are.
import { parseCheckpoint, splitNote, type PairNotes } from '@coffre/core/merkle';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';

import type { Alarm, Checkpointer, InclusionProof, Memory, SealThrough, Sealed, Tick, Witness } from './checkpointer.ts';
import { daysAround, openLogCheckpointer, reasonOf, TICK_MS, upkeep } from './log-checkpointer.ts';
import { logStore } from './log-store.ts';
import { dayOf } from './retention.ts';

/** The part of a Durable Object's state the checkpointer uses. */
export type ObjectState = {
  storage: {
    get<T>(key: string): Promise<T | undefined>;
    put<T>(key: string, value: T): Promise<void>;
    sync(): Promise<void>;
    delete(keys: string[]): Promise<number>;
    list<T>(options: { prefix: string; start?: string; end?: string; limit?: number }): Promise<Map<string, T>>;
    getAlarm(): Promise<number | null>;
    setAlarm(scheduledTime: number): Promise<void>;
  };
  blockConcurrencyWhile<T>(work: () => Promise<T>): Promise<T>;
};

/** A Durable Object binding: `env.CHECKPOINTER`, `env.WITNESS`. */
export type ObjectNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
};

export type CheckpointerSettings = {
  /** The vault's Hyperdrive, its own login. */
  hyperdrive: { readonly connectionString: string };
  /** The vault's signing seed. */
  seed: Uint8Array;
  witnesses?: readonly Witness[];
  /** How long its connection may sit idle before it closes; the next query opens it again. Ticking, it never is. */
  closeIdleMs?: number;
  /** Full days of uses kept before today's; null keeps every day (retention.ts). */
  retainDays?: number | null;
};

/**
 * The signer's memory in the object's storage: one key, the pair's record,
 * durable before `remember` returns. The output gate holds a Response and a
 * new connection until the write is, but not a query on a connection
 * already open, as the database write is: `sync()` makes RememberFirst hold
 * without leaning on it (Fable's review).
 */
export function durableMemory(storage: ObjectState['storage']): Memory {
  return {
    last: async () => (await storage.get<string>('pair')) ?? null,
    async remember(record) {
      await storage.put('pair', record);
      await storage.sync();
    },
  };
}

/** How long alarms are kept. */
const ALARMS_KEPT_MS = 30 * 86_400_000;
/** An alarm's key: its time, then random bytes, so that two at one millisecond never share one, evicted or not. */
const alarmKey = (at: number, suffix = '') => `alarm:${String(at).padStart(16, '0')}:${suffix}`;

/** The Durable Object class the deployment binds, configured from `env` as the vault is. */
export function checkpointerObject<Env>(settings: (env: Env) => CheckpointerSettings | Promise<CheckpointerSettings>) {
  return class CoffreCheckpointer {
    readonly #state: ObjectState;
    readonly #env: Env;
    #checkpointer: Checkpointer | null = null;
    #pool: HyperdrivePool | null = null;
    /** The log's upkeep after each tick (log-checkpointer.ts), with the checkpointer it was opened with. */
    #upkeep: (() => Promise<void>) | null = null;
    /** The day the next days of uses were last made for without the checkpointer (`#makeDays`). */
    #daysFor: string | null = null;
    /** The last ticks, newest last, with their wall time in the object: `status`. */
    readonly #ticks: (Tick & { wallMs: number; at: number })[] = [];

    constructor(state: ObjectState, env: Env) {
      this.#state = state;
      this.#env = env;
    }

    /** The checkpointer, opened once, every other request held meanwhile, so that two never open it side by side. */
    /**
     * Null when it cannot be opened: `open()` refuses the gravest states the log has (entries the signer sealed lost,
     * another pair at its place, time run back), and each is an alarm, kept once while it stands. Never thrown from
     * inside the gate, which would reset the object.
     */
    async #open(): Promise<Checkpointer | null> {
      if (this.#checkpointer !== null) return this.#checkpointer;
      return this.#state.blockConcurrencyWhile(async () => {
        if (this.#checkpointer !== null) return this.#checkpointer;
        let pool: HyperdrivePool | null = null;
        try {
          const s = await settings(this.#env);
          pool = new HyperdrivePool(s.hyperdrive.connectionString, { closeIdleMs: s.closeIdleMs ?? 10_000 });
          const store = logStore(createDatabase(pool));
          const checkpointer = await openLogCheckpointer({
            store,
            seed: s.seed,
            memory: durableMemory(this.#state.storage),
            witnesses: s.witnesses,
            record: (alarm) => this.#record(alarm),
          });
          this.#checkpointer = checkpointer;
          this.#upkeep = upkeep(checkpointer, store, {
            keepDays: s.retainDays ?? null,
            seed: s.seed,
            alert: (message) => {
              console.warn(`coffre audit: ${message}`);
              void this.#record({ at: Date.now(), message }).catch(() => {});
            },
          });
        } catch (error) {
          await pool?.end().catch(() => {});
          await this.#failure(`the checkpointer cannot open: ${reasonOf(error)}`);
          return null;
        }
        this.#pool = pool;
        return this.#checkpointer;
      });
    }

    /** The failure that stands, alarmed once: a refused open, a tick that threw. */
    #failed: string | null = null;

    async #failure(message: string): Promise<void> {
      if (message === this.#failed) return;
      this.#failed = message;
      console.warn(`coffre audit: ${message}`);
      await this.#record({ at: Date.now(), message }).catch((error: Error) => console.warn(`coffre audit: the alarm could not be kept: ${error.message}`));
    }

    /**
     * Nothing else delivered meanwhile, and the old checkpointer closed, its tick in flight ended, before the next
     * request may open another: a change still waiting on the old one can tick it no more, so two never sign at once.
     */
    async #reset(): Promise<void> {
      await this.#state.blockConcurrencyWhile(async () => {
        const [old, pool] = [this.#checkpointer, this.#pool];
        this.#checkpointer = null;
        this.#pool = null;
        this.#upkeep = null;
        await old?.close();
        await pool?.end().catch(() => {});
      });
    }

    async #record(alarm: Alarm): Promise<void> {
      const storage = this.#state.storage;
      await storage.put(alarmKey(alarm.at, crypto.randomUUID()), alarm.message);
      const old = await storage.list<string>({ prefix: 'alarm:', end: alarmKey(alarm.at - ALARMS_KEPT_MS), limit: 128 });
      if (old.size > 0) await storage.delete([...old.keys()]);
    }

    /**
     * The next days of uses, made once a day when the checkpointer cannot open or tick, over a connection of their own:
     * a use needs its day's partition whatever the audit's state, and making one needs no signer.
     */
    async #makeDays(): Promise<void> {
      const today = dayOf(Date.now());
      if (this.#daysFor === today) return;
      let pool: HyperdrivePool | null = null;
      try {
        const s = await settings(this.#env);
        pool = new HyperdrivePool(s.hyperdrive.connectionString, { closeIdleMs: 1000 });
        await logStore(createDatabase(pool)).makeDays(daysAround(Date.now()));
        this.#daysFor = today;
      } catch (error) {
        await this.#failure(`the next days of uses were not made: ${reasonOf(error)}`);
      } finally {
        await pool?.end().catch(() => {});
      }
    }

    async alarm(): Promise<void> {
      try {
        const checkpointer = await this.#open();
        if (checkpointer === null) return await this.#makeDays();
        const t0 = performance.now();
        const t = await checkpointer.tick();
        this.#ticks.push({ ...t, wallMs: performance.now() - t0, at: Date.now() });
        if (this.#ticks.length > 64) this.#ticks.shift();
        this.#failed = null;
        await this.#upkeep?.();
      } catch (error) {
        // A write that failed may be a tamper signal (a tile changed under the signer): an alarm, kept once.
        await this.#failure(`a checkpoint failed: ${reasonOf(error)}`);
        await this.#reset();
        await this.#makeDays();
      } finally {
        await this.#state.storage.setAlarm(Date.now() + TICK_MS);
      }
    }

    async fetch(request: Request): Promise<Response> {
      try {
        const call = (await request.json()) as { op: 'start' } | { op: 'seal'; number: string; deadline?: number } | { op: 'alarms'; since?: number } | { op: 'status' };
        if (call.op === 'start') {
          if ((await this.#open()) === null) return Response.json({ error: this.#failed }, { status: 503 });
          if ((await this.#state.storage.getAlarm()) === null) await this.#state.storage.setAlarm(Date.now() + TICK_MS);
          return Response.json({ ok: true });
        }
        if (call.op === 'seal') {
          const checkpointer = await this.#open();
          if (checkpointer === null) return Response.json({ error: this.#failed }, { status: 503 });
          return Response.json(sealedToJson(await checkpointer.sealThrough(BigInt(call.number), call.deadline)));
        }
        if (call.op === 'status') {
          // The object's own view: after an eviction, nothing until its next tick opens it again (`open: false`).
          const head = this.#checkpointer?.pair.pair;
          return Response.json({
            open: this.#checkpointer !== null,
            upto: head === undefined ? null : String(head.upto), sizes: head === undefined ? null : { changes: head.changes.size, uses: head.uses.size },
            ticks: this.#ticks.map((t) => ({ ...t, upto: String(t.upto) })),
          });
        }
        if (call.op === 'alarms') {
          // A page at a time, each from the last key of the one before (which it lists again): a list is 1,000 keys at most.
          const alarms: Alarm[] = [];
          let start = alarmKey(call.since ?? 0);
          let last: string | null = null;
          for (;;) {
            const page = await this.#state.storage.list<string>({ prefix: 'alarm:', start, limit: 1000 });
            for (const [key, message] of page) if (key !== last) alarms.push({ at: Number(key.split(':')[1]), message });
            if (page.size < 1000) break;
            last = start = [...page.keys()].at(-1)!;
          }
          return Response.json(alarms);
        }
        return new Response('unknown op', { status: 400 });
      } catch (error) {
        return Response.json({ error: (error as Error).message }, { status: 500 });
      }
    }
  };
}

/** Asks the checkpointer's object, as `durableSealThrough(env.CHECKPOINTER)` and `startCheckpointer(env.CHECKPOINTER)` do. */
async function ask<T>(namespace: ObjectNamespace, name: string, call: object): Promise<T> {
  if (typeof namespace?.idFromName !== 'function') throw new Error('there is no CHECKPOINTER binding: bind the CoffreCheckpointer Durable Object to the vault');
  const response = await namespace.get(namespace.idFromName(name)).fetch(new Request('https://checkpointer/', { method: 'POST', body: JSON.stringify(call) }));
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(`the checkpointer failed: ${body.error ?? response.status}`);
  return body;
}

/** The change path's seam on Workers (plan PR 4): seal through the checkpointer's object. */
export function durableSealThrough(namespace: ObjectNamespace, name = 'checkpointer'): SealThrough {
  return async (number, deadline) => sealedFromJson(await ask<SealedJson>(namespace, name, { op: 'seal', number: String(number), deadline }));
}

/** Starts the object's ticks, once; again is harmless. */
export async function startCheckpointer(namespace: ObjectNamespace, name = 'checkpointer'): Promise<void> {
  await ask(namespace, name, { op: 'start' });
}

/** The object's head and its last ticks, each with its barrier, write and wall time. */
export function checkpointerStatus(namespace: ObjectNamespace, name = 'checkpointer'): Promise<{ open: boolean; upto: string | null; sizes: Record<'changes' | 'uses', number> | null; ticks: (Omit<Tick, 'upto'> & { upto: string; wallMs: number; at: number })[] }> {
  return ask(namespace, name, { op: 'status' });
}

/** The alarms the object kept since `since` (ms). */
export function checkpointerAlarms(namespace: ObjectNamespace, since = 0, name = 'checkpointer'): Promise<Alarm[]> {
  return ask<Alarm[]>(namespace, name, { op: 'alarms', since });
}

type SealedJson = {
  notes: PairNotes; witnessed: boolean | null; failures: string[]; cosigned: PairNotes[];
  proof: { number: string; tree: InclusionProof['tree']; index: number; size: number; leaf: string; proof: string[]; notes: PairNotes };
};

function sealedToJson(s: Sealed): SealedJson {
  const p = s.proof;
  return {
    notes: s.notes, witnessed: s.witnessed, failures: s.failures, cosigned: s.cosigned,
    proof: { number: String(p.number), tree: p.tree, index: p.index, size: p.size, leaf: p.leaf.toString('base64'), proof: p.proof.map((h) => h.toString('base64')), notes: p.notes },
  };
}

/** The answer as the object sent it. Its notes are the vault's own, signed in the object: read, not verified again. */
function sealedFromJson(j: SealedJson): Sealed {
  const read = (note: string) => parseCheckpoint(splitNote(note).text);
  const [changes, uses] = [read(j.notes.changes), read(j.notes.uses)];
  return {
    pair: { upto: changes.upto, at: changes.at, floor: changes.floor, prev: changes.prev, changes, uses },
    notes: j.notes, witnessed: j.witnessed, failures: j.failures, cosigned: j.cosigned,
    proof: { ...j.proof, number: BigInt(j.proof.number), leaf: Buffer.from(j.proof.leaf, 'base64'), proof: j.proof.proof.map((h) => Buffer.from(h, 'base64')) },
  };
}

