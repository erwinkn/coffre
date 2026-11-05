import { DurableObject } from 'cloudflare:workers';
import { Client } from 'pg';

import { sealAll, type Fields } from './chain.ts';
import { keysFrom, refusal, unwrap, type Keys, type Snapshot } from './model.ts';
import { appendLane, LANES_SNAPSHOT, readHead, snapshot, type Head } from './sql.ts';

export type Env = { HD: Hyperdrive; LANE: DurableObjectNamespace<Lane>; SEED: string; LANES: string };

export type UseInput = { principal: string; environmentId: string; secretId: string; requestId: string };
export type UseResult =
  | { ok: true; key: string; seq: string; lane: number; t: Timing }
  | { ok: false; code: string; retryAfter?: number; t: Timing };
/** Where a call's time went inside the lane, in milliseconds. */
export type Timing = { read: number; queued: number; append: number; batch: number; tries: number };

/** A decision waiting for its batch to commit. */
type Pending = { fields: Fields; enqueued: number; done: (outcome: { seq: bigint } | { stale: true } | { error: unknown }) => void };

/**
 * Most entries waiting at once, and the longest the oldest may have waited,
 * before a call is refused at once: overload answers in well under a
 * second, with Retry-After, rather than joining a queue that only grows.
 */
const MAX_QUEUE = 2000;
const MAX_WAIT_MS = 100;
/** Connections a lane reads on at once, besides the one it writes on. */
const READERS = 4;
/** Entries in one statement at most. */
const MAX_BATCH = 500;

/**
 * One lane of the audit log, and its only writer: it holds the lane's head
 * in memory, so it seals entries with no round trip, and writes whatever
 * decisions are waiting in one statement (`appendLane`), while the next
 * ones queue behind it: a round trip per batch, not per entry. A call
 * returns only once its entry has committed. It keeps what each principal's
 * decisions read, which the append holds to the control lane's head: a
 * change to anything a read decides on appends there first, so a decision
 * made on a read from before it is refused at the append and made again.
 */
export class Lane extends DurableObject<Env> {
  #keys: Keys;
  #lane = -1;
  #head: Head | null = null;
  #queue: Pending[] = [];
  #flushing = false;
  #writer: Client | null = null;
  #readers: Client[] = [];
  /** Readers open, at most READERS: calls past that wait for one. */
  #open = 0;
  #waiting: ((client: Client) => void)[] = [];
  /** What each principal's decisions last read, and the control lane's head it was read at. */
  #reads = new Map<string, Snapshot>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#keys = keysFrom(env.SEED);
  }

  async use(lane: number, input: UseInput): Promise<UseResult> {
    this.#lane = lane;
    const t: Timing = { read: 0, queued: 0, append: 0, batch: 0, tries: 0 };
    // Overload: refuse now, saying when to come back, rather than queue.
    const oldest = this.#queue[0];
    if (this.#queue.length >= MAX_QUEUE || (oldest !== undefined && Date.now() - oldest.enqueued > MAX_WAIT_MS)) {
      return { ok: false, code: 'overloaded', retryAfter: 1, t };
    }
    for (let attempt = 0; attempt < 3; attempt += 1) {
      t.tries += 1;
      let read = this.#reads.get(input.principal);
      if (read === undefined || read.environment?.id !== input.environmentId || read.secret?.id !== input.secretId) {
        const started = Date.now();
        read = await this.#read(input);
        t.read += Date.now() - started;
        this.#reads.set(input.principal, read);
      }
      const why = refusal(this.#keys, read, input.environmentId);
      const fields: Fields = {
        actor: input.principal,
        action: 'secret.read',
        decision: why === null ? 'allow' : 'deny',
        subject: input.principal,
        environmentId: input.environmentId,
        controlSeq: read.control,
        occurredAt: Date.now(),
        metadata: JSON.stringify({ requestId: input.requestId, secretId: input.secretId, ...(why === null ? {} : { code: why }) }),
      };
      // The key is opened before the entry commits, and handed back only after.
      const key = why === null ? unwrap(this.#keys.kek, Buffer.from(read.secret!.wrapped, 'hex'), Buffer.from(read.secret!.iv, 'hex')) : null;
      const enqueued = Date.now();
      const outcome = await new Promise<{ seq: bigint } | { stale: true } | { error: unknown }>((done) => {
        this.#queue.push({ fields, enqueued, done });
        if (!this.#flushing) void this.#flush();
      });
      t.queued += Date.now() - enqueued;
      if ('stale' in outcome) {
        // Something it decided on changed: read again, decide again.
        this.#reads.delete(input.principal);
        key?.fill(0);
        continue;
      }
      if ('error' in outcome) {
        key?.fill(0);
        return { ok: false, code: 'unavailable', retryAfter: 1, t };
      }
      if (key === null) return { ok: false, code: why!, t };
      const value = key.toString('base64');
      key.fill(0);
      return { ok: true, key: value, seq: String(outcome.seq), lane, t };
    }
    return { ok: false, code: 'changing', retryAfter: 1, t };
  }

  /** What the lane's queue holds now: for the load test's own view. */
  async depth(): Promise<{ queue: number; cached: number; head: string | null }> {
    return { queue: this.#queue.length, cached: this.#reads.size, head: this.#head === null ? null : String(this.#head.nextSeq) };
  }

  /** Where this object runs, and its round trip to the database: for the load test's own view. */
  async where(): Promise<{ colo: string; selectMs: number[] }> {
    const trace = await (await fetch('https://www.cloudflare.com/cdn-cgi/trace')).text();
    const client = await this.#reader();
    const selectMs: number[] = [];
    try {
      for (let i = 0; i < 5; i += 1) {
        const started = performance.now();
        await client.query('SELECT 1');
        selectMs.push(performance.now() - started);
      }
    } finally {
      this.#release(client);
    }
    return { colo: /colo=(\w+)/.exec(trace)?.[1] ?? '?', selectMs };
  }

  /** Forget every read, as a deploy would. */
  async forget(): Promise<void> {
    this.#reads.clear();
    this.#head = null;
  }

  async #read(input: UseInput): Promise<Snapshot> {
    const client = await this.#reader();
    try {
      const read = await snapshot(client, LANES_SNAPSHOT, input.principal, input.environmentId, input.secretId);
      this.#release(client);
      return read;
    } catch (error) {
      this.#open -= 1;
      void client.end().catch(() => {});
      throw error;
    }
  }

  async #reader(): Promise<Client> {
    const idle = this.#readers.pop();
    if (idle !== undefined) return idle;
    if (this.#open < READERS) {
      this.#open += 1;
      try {
        return await this.#connect();
      } catch (error) {
        this.#open -= 1;
        throw error;
      }
    }
    return new Promise((resolve) => this.#waiting.push(resolve));
  }

  #release(client: Client): void {
    const next = this.#waiting.shift();
    if (next !== undefined) next(client);
    else this.#readers.push(client);
  }

  async #connect(): Promise<Client> {
    const client = new Client({ connectionString: this.env.HD.connectionString });
    await client.connect();
    return client;
  }

  /**
   * Write what waits, a batch at a time, until nothing does. Entries decided
   * on a control head older than the newest any of them read are stale
   * without asking; the rest go in one statement, which writes nothing if
   * the control lane moved meanwhile, and then those decided before it are
   * stale too.
   */
  async #flush(): Promise<void> {
    this.#flushing = true;
    try {
      while (this.#queue.length > 0) {
        const batch = this.#queue.splice(0, MAX_BATCH);
        try {
          await this.#write(batch);
        } catch (error) {
          for (const pending of batch) pending.done({ error });
          this.#head = null;
          void this.#writer?.end().catch(() => {});
          this.#writer = null;
        }
      }
    } finally {
      this.#flushing = false;
    }
  }

  async #write(batch: Pending[]): Promise<void> {
    this.#writer ??= await this.#connect();
    this.#head ??= await readHead(this.#writer, this.#lane);
    let waiting = batch;
    for (let tries = 0; waiting.length > 0; tries += 1) {
      if (tries > 5) throw new Error('the lane would not take the batch');
      const newest = waiting.reduce((max, p) => (BigInt(p.fields.controlSeq!) > max ? BigInt(p.fields.controlSeq!) : max), 0n);
      const stale = waiting.filter((p) => BigInt(p.fields.controlSeq!) < newest);
      for (const pending of stale) pending.done({ stale: true });
      waiting = waiting.filter((p) => BigInt(p.fields.controlSeq!) === newest);
      const sealed = sealAll(this.#keys.log, this.#lane, this.#head, waiting.map((p) => p.fields));
      const result = await appendLane(this.#writer, this.#lane, this.#head, String(newest), sealed);
      if (result.written) {
        this.#head = { nextSeq: sealed.at(-1)!.seq + 1n, hash: sealed.at(-1)!.hash };
        waiting.forEach((pending, i) => pending.done({ seq: sealed[i]!.seq }));
        return;
      }
      if (result.control !== String(newest)) {
        // The control lane moved: every decision here read it before.
        for (const pending of waiting) pending.done({ stale: true });
        return;
      }
      // Another writer moved the lane: take its head, seal again.
      this.#head = await readHead(this.#writer, this.#lane);
    }
  }
}
