// The 0.15 checkpointer on Workers (docs/design/audit-tree.md): one Durable
// Object for the instance, which seals the log on its alarm every 500 ms
// and keeps the signer's memory in its own storage. A write to that storage
// is held by the object's output gate until it is durable, so no message
// leaves it, the database write included, before the pair it signed is
// remembered (RememberFirst). It holds one connection to the database
// through the vault's Hyperdrive for as long as it lives: its ticks run one
// at a time, and a Durable Object may keep a connection across requests.
// Nothing it awaits is unbounded (T169): a tick past its bound stalls the
// checkpointer, its connection is cut, and the next alarm opens another; a
// change waits at most `SEAL_WAIT_MS` for its seal, then answers 503.
//
// The deployment binds it and exports it (`export const CoffreCheckpointer =
// checkpointer()`, beside `vault(…)`); the vault starts it, from each
// isolate's first call (cloudflare.ts). Asked with `fetch`, as the anchor
// and the gates are.
//
// The reads' projector (reads.ts, T166) is another object of the same class,
// named `reads` (`startProjector`), which its storage says it is: its own
// alarm, its own invocation and its own connection, so that no invocation
// ever holds two connections (a Worker that opened several at once was
// cancelled as hung, AGENTS.md), and a projection behind, or failing, delays
// no tick, no seal, no change and no use (formal/Reads.tla).
import { parseCheckpoint, splitNote, type PairNotes } from '@coffre/core/merkle';
import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';

import type { Sealing } from '@coffre/core/vault';

import {
  Fence,
  heldIn,
  SEAL_WAIT_MS,
  sealingOf,
  TICK_BOUND_MS,
  Unsealed,
  WITNESS_DEADLINE_MS,
  within,
  type Alarm,
  type Checkpointer,
  type InclusionProof,
  type Memory,
  type SealThrough,
  type Sealed,
  type Tick,
  type Witness,
} from './checkpointer.ts';
import { daysAround, openLogCheckpointer, reasonOf, RETAIN_EVERY_MS, TICK_MS, upkeep } from './log-checkpointer.ts';
import { Projector } from './reads.ts';
import { verifierKeys } from './verifier.ts';
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
  /** The vault's signing keys (`ResolvedVaultConfig.signingKeys`): the one it signs with first, then those it replaced (T168). */
  signingKeys: readonly Uint8Array[];
  witnesses?: readonly Witness[];
  /** How long its connection may sit idle before it closes; the next query opens it again. Ticking, it never is. */
  closeIdleMs?: number;
  /** Full days of uses kept before today's; null keeps every day (retention.ts). */
  retainDays?: number | null;
  /** `TICK_BOUND_MS`, which also bounds an open and the next days made without one: for the tests. */
  tickBoundMs?: number;
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
/**
 * How long the object waits on an open, which reads the newest pair and the trees' edges, and on the next days of
 * uses made without it (T169): as long as a tick.
 */
const OPEN_BOUND_MS = TICK_BOUND_MS;
/** How long it waits on the log's upkeep after a tick: retention drops a day's partition and its tiles, hourly. */
const UPKEEP_BOUND_MS = 60_000;
/** How long the vault waits on the object for anything but a seal: a start, its status, the pair it remembers. */
const ASK_BOUND_MS = 2000;
/** How long the vault waits on the object for a seal: its own bound, and the witnesses', and a second more. */
const SEAL_ASK_BOUND_MS = SEAL_WAIT_MS + WITNESS_DEADLINE_MS + 1000;
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
    /** Whether this object is the reads' projector, as its storage says (`startProjector`); asked once. */
    #projects: boolean | null = null;
    /** The projector, on a connection of its own for as long as the object lives, as the checkpointer's. */
    #projector: Projector | null = null;
    /** The day the next days of uses were last made for without the checkpointer (`#makeDays`), when it last tried, and its failure. */
    #daysFor: string | null = null;
    #daysTried = -Infinity;
    #daysFailed: string | null = null;
    /** Whether the upkeep after a tick that held runs now (`alarm`), which readiness counts as the tick's time. */
    #upkeeping = false;

    /**
     * The last tick as readiness reads it: during the upkeep after it, as if it had just ended. What stood since, a seal's
     * tick that stalled or was refused meanwhile, readiness reads from the checkpointer itself (`standing`).
     */
    #lastSeen(): { at: number; failures: readonly string[] } | null {
      const last = this.#ticks.at(-1) ?? null;
      return last === null || !this.#upkeeping ? last : { at: Date.now(), failures: last.failures };
    }

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
        // Bounded (T169): an open that stalls is fenced and its connection cut, so that the gate lets go well before the
        // platform's 30 s would reset the object.
        const fence = new Fence();
        try {
          const s = await settings(this.#env);
          const opening = new HyperdrivePool(s.hyperdrive.connectionString, { closeIdleMs: s.closeIdleMs ?? 10_000 });
          pool = opening;
          const store = logStore(createDatabase(pool));
          const checkpointer = await within(openLogCheckpointer({
            store,
            signingKeys: s.signingKeys,
            memory: durableMemory(this.#state.storage),
            witnesses: s.witnesses,
            record: (alarm) => this.#record(alarm),
            fence,
            ...(s.tickBoundMs === undefined ? {} : { tickBoundMs: s.tickBoundMs }),
          }), s.tickBoundMs ?? OPEN_BOUND_MS, 'the open', () => {
            void fence.close('its open stalled');
            opening.destroy();
          });
          this.#checkpointer = checkpointer;
          // Behind the checkpointer's fence, as everything it does: nothing of it runs once another opens.
          this.#upkeep = upkeep(checkpointer, fence.store(store), {
            keepDays: s.retainDays ?? null,
            signingKey: s.signingKeys[0]!,
            alert: (message) => {
              console.warn(`coffre audit: ${message}`);
              void this.#record({ at: Date.now(), message }).catch((error: Error) => console.warn(`coffre audit: the alarm could not be kept: ${error.message}`));
            },
          });
        } catch (error) {
          await fence.close('its open failed');
          pool?.destroy();
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
     * Nothing else delivered meanwhile, and the old checkpointer closed, fenced, its tick in flight ended or stalled,
     * before the next request may open another: a change still waiting on the old one can tick it no more, so two
     * never sign at once. Its connection is cut first, so that what it still awaits fails now rather than whenever the
     * database answers (T169); a statement it had sent may still land, which the fence's rules allow.
     */
    async #reset(): Promise<void> {
      await this.#state.blockConcurrencyWhile(async () => {
        const [old, pool] = [this.#checkpointer, this.#pool];
        this.#checkpointer = null;
        this.#pool = null;
        this.#upkeep = null;
        pool?.destroy();
        await old?.close();
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
      const now = Date.now();
      const today = dayOf(now);
      // Once a day when it works; when it fails, an hour later (DAYS_AHEAD days of slack), alarmed once while it stands
      // apart from the checkpointer's own failures, so that neither hides the other.
      if (this.#daysFor === today || now - this.#daysTried < RETAIN_EVERY_MS) return;
      this.#daysTried = now;
      let pool: HyperdrivePool | null = null;
      try {
        const s = await settings(this.#env);
        const making = new HyperdrivePool(s.hyperdrive.connectionString, { closeIdleMs: 1000 });
        pool = making;
        await within(logStore(createDatabase(making)).makeDays(daysAround(now)), s.tickBoundMs ?? OPEN_BOUND_MS, 'making them', () => making.destroy());
        this.#daysFor = today;
        this.#daysFailed = null;
      } catch (error) {
        const message = `the next days of uses were not made: ${reasonOf(error)}`;
        if (message !== this.#daysFailed) {
          console.warn(`coffre audit: ${message}`);
          await this.#record({ at: now, message }).catch((e: Error) => console.warn(`coffre audit: the alarm could not be kept: ${e.message}`));
        }
        this.#daysFailed = message;
      } finally {
        pool?.destroy();
      }
    }

    /**
     * The projector's run: some steps of `projectReads`, then the next alarm, a tick later, or at once while a run
     * leaves sealed uses to project. A failure is an alarm, said once while it stands (`Projector`), and the next
     * tick tries again, on the same connection, which postgres.js opens again when it is lost.
     */
    async #project(): Promise<void> {
      let more = false;
      try {
        if (this.#projector === null) {
          const s = await settings(this.#env);
          const pool = new HyperdrivePool(s.hyperdrive.connectionString, { closeIdleMs: s.closeIdleMs ?? 10_000 });
          const store = logStore(createDatabase(pool));
          this.#projector = new Projector(store, await verifierKeys(s.signingKeys), (message) => {
            console.warn(`coffre audit: ${message}`);
            void this.#record({ at: Date.now(), message }).catch((error: Error) => console.warn(`coffre audit: the alarm could not be kept: ${error.message}`));
          });
        }
        more = await this.#projector.run();
      } catch (error) {
        this.#projector = null;
        await this.#failure(`the reads' projection cannot open: ${reasonOf(error)}`);
      } finally {
        await this.#state.storage.setAlarm(Date.now() + (more ? 0 : TICK_MS));
      }
    }

    async #isProjector(): Promise<boolean> {
      return (this.#projects ??= (await this.#state.storage.get<string>('role')) === 'reads');
    }

    async alarm(): Promise<void> {
      if (await this.#isProjector()) return this.#project();
      // A window sealed only in part (T169, WINDOW_MAX): the next alarm at once, its upkeep once it has caught up.
      let more = false;
      try {
        const checkpointer = await this.#open();
        if (checkpointer === null) return await this.#makeDays();
        const t0 = performance.now();
        // Bounded by the checkpointer itself (TICK_BOUND_MS): one that stalled throws, and is replaced below.
        const t = await checkpointer.tick();
        this.#ticks.push({ ...t, wallMs: performance.now() - t0, at: Date.now() });
        if (this.#ticks.length > 64) this.#ticks.shift();
        this.#failed = null;
        more = t.more;
        // On the same connection, cut past its bound: the checkpointer goes with it. Meanwhile readiness counts the
        // checkpointer as sealing (review by Fable): its last tick was good, and the upkeep is bounded.
        const pool = this.#pool;
        if (this.#upkeep !== null && !more) {
          this.#upkeeping = true;
          try {
            await within(this.#upkeep(), UPKEEP_BOUND_MS, "the log's upkeep", () => pool?.destroy());
          } finally {
            this.#upkeeping = false;
            const last = this.#ticks.at(-1);
            if (last !== undefined) last.at = Date.now();
          }
        }
      } catch (error) {
        // A write that failed may be a tamper signal (a tile changed under the signer): an alarm, kept once.
        await this.#failure(`a checkpoint failed: ${reasonOf(error)}`);
        await this.#reset();
        await this.#makeDays();
      } finally {
        await this.#state.storage.setAlarm(Date.now() + (more ? 0 : TICK_MS));
      }
    }

    async fetch(request: Request): Promise<Response> {
      try {
        const call = (await request.json()) as { op: 'start' } | { op: 'project' } | { op: 'seal'; number: string; deadline?: number } | { op: 'alarms'; since?: number } | { op: 'status' } | { op: 'remembered' };
        if (call.op === 'project') {
          // The reads' projector from now on, its role kept for when it wakes evicted, and its alarm set.
          if (!(await this.#isProjector())) {
            await this.#state.storage.put('role', 'reads');
            this.#projects = true;
          }
          if ((await this.#state.storage.getAlarm()) === null) await this.#state.storage.setAlarm(Date.now() + TICK_MS);
          return Response.json({ ok: true });
        }
        if (await this.#isProjector() && call.op !== 'alarms') return new Response('the reads\' projector seals nothing', { status: 400 });
        if (call.op === 'start') {
          // The alarm first, whether it opens or not: refused, each tick tries again and makes the next days of uses meanwhile.
          if ((await this.#state.storage.getAlarm()) === null) await this.#state.storage.setAlarm(Date.now() + TICK_MS);
          if ((await this.#open()) === null) return Response.json({ error: this.#failed }, { status: 503 });
          return Response.json({ ok: true });
        }
        if (call.op === 'seal') {
          // A 503 is a seal that did not come in time (T169): the change is in force, and asked again, sealed.
          const checkpointer = await this.#open();
          if (checkpointer === null) return Response.json({ error: new Unsealed(BigInt(call.number), this.#failed ?? 'the checkpointer cannot open').message }, { status: 503 });
          try {
            return Response.json(sealedToJson(await checkpointer.sealThrough(BigInt(call.number), call.deadline)));
          } catch (error) {
            if (error instanceof Unsealed) return Response.json({ error: error.message }, { status: 503 });
            throw error;
          }
        }
        if (call.op === 'status') {
          // The object's own view: after an eviction, nothing until its next tick opens it again (`open: false`); the
          // failure that stands, if any, which readiness reads with the last tick's time (`sealingOf`).
          const head = this.#checkpointer?.pair.pair;
          return Response.json({
            open: this.#checkpointer !== null,
            failed: this.#failed,
            // By the object's clock, as its ticks' times are.
            sealing: sealingOf({ open: this.#checkpointer !== null, failed: this.#failed ?? this.#checkpointer?.standing ?? null, last: this.#lastSeen() }),
            upto: head === undefined ? null : String(head.upto), sizes: head === undefined ? null : { changes: head.changes.size, uses: head.uses.size },
            ticks: this.#ticks.map((t) => ({ ...t, upto: String(t.upto) })),
          });
        }
        if (call.op === 'remembered') {
          // The pair the signer remembers, read from the object's storage, opened or not; a record that is no pair, refused.
          return Response.json({ held: heldIn(await durableMemory(this.#state.storage).last()) });
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

/**
 * Asks the checkpointer's object, as `durableSealThrough(env.CHECKPOINTER)` and `startCheckpointer(env.CHECKPOINTER)`
 * do, for at most `ms` (T169): an object that does not answer, its gate held or its isolate wedged, fails the ask
 * rather than the call that asked.
 */
async function ask<T>(namespace: ObjectNamespace, name: string, call: object, ms = ASK_BOUND_MS): Promise<T> {
  if (typeof namespace?.idFromName !== 'function') throw new Error('there is no CHECKPOINTER binding: bind the CoffreCheckpointer Durable Object to the vault');
  const asked = (async () => {
    const response = await namespace.get(namespace.idFromName(name)).fetch(new Request('https://checkpointer/', { method: 'POST', body: JSON.stringify(call) }));
    return { response, body: (await response.json()) as T & { error?: string } };
  })();
  const { response, body } = await within(asked, ms, "the checkpointer's object");
  // Its status kept: a 503 is an object that refused to open, its alarm set (`start`).
  if (!response.ok) throw Object.assign(new Error(`the checkpointer failed: ${body.error ?? response.status}`), { status: response.status });
  return body;
}

/**
 * The change path's seam on Workers (plan PR 4): seal through the checkpointer's object. Its 503, or no answer in
 * time, is `Unsealed` (T169): the change is committed and in force, and the app says 503, try again.
 */
export function durableSealThrough(namespace: ObjectNamespace, name = 'checkpointer'): SealThrough {
  return async (number, deadline) => {
    let sealed: SealedJson;
    try {
      sealed = await ask<SealedJson>(namespace, name, { op: 'seal', number: String(number), deadline }, SEAL_ASK_BOUND_MS);
    } catch (error) {
      // The object's 503 says so in core's words; an object that did not answer, or not in time, is the same. Its 500 is
      // a seal refused (an entry that fails its MAC, a database at another pair): an alarm, kept by the object.
      if ((error as { status?: number }).status === undefined) throw new Unsealed(number, `the checkpointer's object did not answer: ${(error as Error).message}`, error);
      throw error;
    }
    return sealedFromJson(sealed);
  };
}

/** Starts the object's ticks, once; again is harmless. Throws when it cannot open, its alarm set all the same. */
export async function startCheckpointer(namespace: ObjectNamespace, name = 'checkpointer'): Promise<void> {
  await ask(namespace, name, { op: 'start' });
}

/**
 * Starts the reads' projector (reads.ts, T166): the object of the same class named `name`, which projects from then
 * on, on its own alarm. Again is harmless.
 */
export async function startProjector(namespace: ObjectNamespace, name = 'reads'): Promise<void> {
  await ask(namespace, name, { op: 'project' });
}

/** The object's head and its last ticks, each with its barrier, write and wall time. */
export function checkpointerStatus(namespace: ObjectNamespace, name = 'checkpointer'): Promise<{ open: boolean; failed: string | null; sealing: Sealing; upto: string | null; sizes: Record<'changes' | 'uses', number> | null; ticks: (Omit<Tick, 'upto'> & { upto: string; wallMs: number; at: number })[] }> {
  return ask(namespace, name, { op: 'status' });
}

/** Whether the object seals (`Vault.sealing`, T169): its own view, or, if it does not answer within 2 s, that it does not. */
export function durableSealing(namespace: ObjectNamespace, name = 'checkpointer'): () => Promise<Sealing> {
  return async () => {
    try {
      return (await checkpointerStatus(namespace, name)).sealing;
    } catch (error) {
      return { ok: false, reason: `the checkpointer's object did not answer: ${(error as Error).message}` };
    }
  };
}

/**
 * The pair the signer remembers, where no database writer reaches: what the
 * vault's verifier holds its walks to (`VaultOptions.heldOutside`).
 */
export function durableHeldOutside(namespace: ObjectNamespace, name = 'checkpointer'): () => Promise<PairNotes[]> {
  return async () => {
    const { held } = await ask<{ held: PairNotes[] }>(namespace, name, { op: 'remembered' });
    return held;
  };
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

