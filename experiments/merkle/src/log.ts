import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { checkpointBody, openCheckpoint, signerFrom, signNote, verifierFrom, type Checkpoint, type Signer } from './note.ts';
import { Edge, edgeOf, nodesFrom, tileMap, tilesFor, type Tile, type TileKey } from './tiles.ts';
import { consistencyProof, inclusionProof, leafHash, treeHash, type Hash } from './tree.ts';

/**
 * W209's audit log: entries numbered by a Postgres sequence, each with a MAC
 * over everything but its number, sealed every tick into one growing RFC 9162
 * tree whose head the vault signs. The MAC keeps an entry honest until it is
 * sealed; the tree keeps it, its number and every entry around it honest after,
 * for anyone holding a signed head, with the public key alone.
 */
export type Db = { query(query: string | { name: string; text: string; values: unknown[] }, params?: unknown[]): Promise<{ rows: any[] }> };

export type Keys = { origin: string; mac: Buffer; signer: Signer; witness: Signer };

/** Synthetic keys from one test seed. */
export async function keysFrom(seed: string): Promise<Keys> {
  const derive = (label: string) => createHash('sha256').update(`w209.${label}`).update(seed).digest();
  const origin = 'coffre.example/audit';
  return { origin, mac: derive('mac'), signer: await signerFrom(origin, derive('signer')), witness: await signerFrom('witness.example', derive('witness')) };
}

/** An entry as W208 shapes it: `seal` is a change's seal over the member row it leaves, null for a use. */
export type Fields = { at: number; principal: string; credential: string | null; kind: string; requestId: string; payload: string; seal?: Buffer | null };
export type Entry = Fields & { number: string; mac: Buffer };

/** What the MAC covers: everything but the number, which the append takes in the database. */
export function entryMac(key: Buffer, f: Fields): Buffer {
  return createHmac('sha256', key).update('coffre.audit.mac.v1\n')
    .update(JSON.stringify([f.at, f.principal, f.credential, f.kind, f.requestId, f.payload, f.seal?.toString('base64') ?? null])).digest();
}

/** A leaf: the whole entry, its number and MAC included, so its place is sealed with it. */
export function leafData(e: Entry): Buffer {
  return Buffer.from(JSON.stringify(['coffre.audit.v1', e.number, e.at, e.principal, e.credential, e.kind, e.requestId, e.payload, e.seal?.toString('base64') ?? null, e.mac.toString('base64')]));
}

export const leafOf = (e: Entry): Hash => leafHash(leafData(e));

/**
 * A new, empty log: the schema, laid out by `mode` (schema.sql), with the day
 * partitions the appends will need: day 0 for `number`, today and tomorrow for
 * `at`.
 */
export async function createLog(db: Db, mode: 'number' | 'at' = 'number', dayMs = 86_400_000): Promise<void> {
  await db.query(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  await db.query('SELECT lay_out($1, $2)', [mode, dayMs]);
  const today = mode === 'number' ? 0 : Math.floor(Date.now() / dayMs);
  for (const d of [today, today + 1]) await db.query('SELECT new_day($1)', [d]);
}

const APPEND = 'SELECT append_entry($1, $2, $3, $4, $5, $6, $7, $8)::text AS number';

/** A use's entry: one statement. Returns its number. */
export async function append(db: Db, keys: Keys, f: Fields): Promise<string> {
  const mac = entryMac(keys.mac, f);
  const { rows: [row] } = await db.query({ name: 'append_entry', text: APPEND, values: [f.at, f.principal, f.credential, f.kind, f.requestId, f.payload, f.seal ?? null, mac] });
  return row.number;
}

type EntryRow = { upto: string; newest?: string | null; number: string | null; at: string; principal: string; credential: string | null; kind: string; request_id: string; payload: string; seal: Buffer | null; mac: Buffer; written_at: Date };

const toEntry = (r: EntryRow): Entry => ({
  number: r.number!, at: Number(r.at), principal: r.principal, credential: r.credential, kind: r.kind, requestId: r.request_id, payload: r.payload, seal: r.seal, mac: r.mac,
});

/**
 * What the signer remembers of the last head it signed, kept where a database
 * writer cannot reach (a Durable Object's storage, a file beside a Node vault).
 * Without it, a signer that restarts from the database's last checkpoint signs
 * whatever the database now says: a writer who rolled the log back gets a second,
 * different head for the same entries' places (a split view), signed.
 */
export type Memory = { last(): Promise<string | null>; remember(note: string): Promise<void> };

/** Somewhere each signed head goes that a database writer cannot reach: a witness, an archive. */
export type Witness = { name: string; publish(note: string, proofFrom: (size: number) => Promise<Hash[]>): Promise<WitnessAnswer> };
export type WitnessAnswer = { ok: true; cosigned?: string } | { ok: false; reason: string };

type Pump = {
  busy: boolean; next: { note: string; head: Checkpoint } | null; acked: bigint; cosigned: string | null; failure: string | null;
  waiters: { upto: bigint; done: (failure: string | null) => void }[];
};

/** A closed day, as its signed entry records it. */
export type DayRecord = { action: 'audit.day'; day: number; first: string; last: string; firstLeaf: number; lastLeaf: number };

export type Tick = {
  upto: string; size: number; entries: number; signed: boolean;
  /** Database time: the sealing read, then the write of tiles and the checkpoint. */
  sealMs: number; writeMs: number;
  /** This process's CPU for the tick: verifying MACs, hashing leaves, the tree, signing. */
  cpuMs: number;
  /** From the oldest entry's commit to the checkpoint's commit, then to every witness having it. */
  oldestToSealMs: number; oldestToWitnessedMs: number; newestToSealMs: number;
  witnessMs: number; tilesWritten: number; failures: string[];
};

export class Checkpointer {
  private db: Db;
  private keys: Keys;
  private edge: Edge;
  private head: Checkpoint;
  /** The newest head's signed note, as the witnesses get it. */
  private note: string;
  private memory: Memory | null;
  private witnesses: Witness[];

  private constructor(db: Db, keys: Keys, edge: Edge, head: Checkpoint, note: string, memory: Memory | null, witnesses: Witness[]) {
    this.db = db;
    this.keys = keys;
    this.edge = edge;
    this.head = head;
    this.note = note;
    this.memory = memory;
    this.witnesses = witnesses;
  }

  get size(): number {
    return this.edge.size;
  }

  get upto(): string {
    return this.head.upto;
  }

  /**
   * From the last checkpoint row, checked against what the signer remembers.
   * The signer remembers a head before the database has it (formal/Seal.tla,
   * RememberFirst), so the memory may be ahead of the database: after a crash
   * between the two, or because a writer deleted the newest checkpoint rows.
   * Either way, if the entries the database still holds give the remembered
   * head, its row is written again and nothing was lost; if they do not, the
   * database lost entries the signer sealed, and it refuses to go on. A
   * database beside the memory (another head at the same place) is refused too.
   */
  static async open(db: Db, keys: Keys, opts: { memory?: Memory; witnesses?: Witness[] } = {}): Promise<Checkpointer> {
    const memory = opts.memory ?? null;
    const verifier = await verifierFrom(keys.signer.verifierKey);
    // What the signer remembers comes first: nothing is signed or remembered before it is compared.
    const remembered = (await memory?.last()) ?? null;
    let mine: Checkpoint | null = null;
    if (remembered !== null) {
      mine = await openCheckpoint(remembered, verifier);
      if (mine === null) throw new Error('the signer remembers a head it did not sign');
    }
    const { rows: [last] } = await db.query('SELECT note FROM checkpoints ORDER BY upto DESC LIMIT 1');
    if (last === undefined) {
      if (mine !== null && (mine.size > 0 || mine.upto !== '0')) {
        throw new Error(`the database holds no checkpoint; the signer signed ${mine.size} leaves up to ${mine.upto}`);
      }
      // A new log: the empty tree at number 0, sealing nothing, so the first tick seals every entry there is.
      const head: Checkpoint = { origin: keys.origin, size: 0, root: treeHash(() => Buffer.alloc(0), 0), upto: '0', at: Date.now() };
      const note = await signNote(checkpointBody(head), [keys.signer]);
      await memory?.remember(note);
      await db.query('INSERT INTO checkpoints (upto, size, root, note) VALUES ($1, 0, $2, $3)', [head.upto, head.root, note]);
      return new Checkpointer(db, keys, Edge.empty(), head, note, memory, opts.witnesses ?? []);
    }
    const newest = await openCheckpoint(last.note, verifier);
    if (newest === null) throw new Error('the last checkpoint is not signed by this log');
    let head = newest;
    let note: string = last.note;
    let edge = await loadEdge(db, head.size);
    if (!edge.root().equals(head.root)) throw new Error('the tiles at the edge do not give the signed head');
    if (mine !== null) {
      // One rule: the remembered head and the database's must be one history, the shorter a prefix of the longer.
      if (mine.upto === head.upto) {
        if (!(mine.size === head.size && mine.root.equals(head.root))) throw new Error(`the database's checkpoint at ${head.upto} is not the one signed`);
      } else if (BigInt(mine.upto) > BigInt(head.upto)) {
        // The memory is ahead (a crash between remembering and writing, or rows deleted): seal again from the
        // database's newest row up to the remembered head, from the entries, and require exactly that head.
        const { rows } = await db.query(
          'SELECT a.number::text, a.at::text, a.principal, a.credential, a.kind, a.request_id, a.payload, a.seal, a.mac FROM audit a WHERE a.number > $1 AND a.number <= $2 ORDER BY a.number',
          [head.upto, mine.upto],
        );
        const tiles = edge.append(rows.map((r) => leafOf(toEntry({ ...r, upto: '' }))));
        if (edge.size !== mine.size || !edge.root().equals(mine.root)) {
          throw new Error(`the database lost entries the signer sealed: it holds ${edge.size} leaves up to ${mine.upto}, the signer signed ${mine.size}`);
        }
        await writeCheckpoint(db, tiles, mine, remembered!, null);
        head = mine;
        note = remembered!;
      } else {
        // The database is ahead, which RememberFirst rules out for this signer (a memory restored from a backup,
        // say): accept it only if the remembered head is a prefix of it.
        const prefix = mine.size <= head.size
          && treeHash(nodesFrom(tileMap(await readTiles(db, tilesFor((n) => treeHash(n, mine!.size))))), mine.size).equals(mine.root);
        if (!prefix) throw new Error(`the database's head (${head.size} leaves up to ${head.upto}) does not extend the one the signer remembers (${mine.size} up to ${mine.upto})`);
      }
      edge = await loadEdge(db, head.size);
    }
    return new Checkpointer(db, keys, edge, head, note, memory, opts.witnesses ?? []);
  }

  private running: Promise<unknown> = Promise.resolve();

  /**
   * One checkpoint: seal what has committed, sign it, store it, publish it.
   * `nextDay` also moves the sequence to that day (number days) and records the
   * day just closed in a signed `audit.day` entry. A witness slower than
   * `witnessTimeoutMs` is reported as such; its publication carries on.
   */
  async tick(opts: { nextDay?: number; witnessTimeoutMs?: number } = {}): Promise<Tick> {
    const t = await this.seal(opts);
    // The regular ticker does not wait for witnesses (a refusing one would set its pace); a caller that wants to
    // know, a bench or a change, says how long it waits.
    if (!t.signed || this.witnesses.length === 0 || opts.witnessTimeoutMs === undefined) return t;
    const w0 = performance.now();
    const { failures } = await this.witnessed(t.upto, opts.witnessTimeoutMs);
    const witnessMs = performance.now() - w0;
    return { ...t, failures: [...t.failures, ...failures], witnessMs, oldestToWitnessedMs: t.oldestToSealMs + witnessMs };
  }

  /** Sealing runs one tick at a time, the regular ones and those a change asks for; waiting for witnesses does not. */
  private seal(opts: { nextDay?: number }): Promise<Tick> {
    const run = this.running.then(() => this.tickNow(opts));
    this.running = run.catch(() => {});
    return run;
  }

  /**
   * Each witness's pump: one publication in flight at a time, always of the
   * newest head (a witness needs only that: it proves the ones between). A
   * failed one is tried again with the next tick's head, or the same head on a
   * tick that seals nothing. `cosigned` is the newest head it cosigned.
   */
  private pumps = new Map<Witness, Pump>();

  private pump(w: Witness): Pump {
    let p = this.pumps.get(w);
    if (p === undefined) this.pumps.set(w, (p = { busy: false, next: null, acked: -1n, cosigned: null, failure: null, waiters: [] }));
    return p;
  }

  private publish(note: string, head: Checkpoint): void {
    for (const w of this.witnesses) {
      const p = this.pump(w);
      p.next = { note, head };
      if (!p.busy) void this.drain(w, p);
    }
  }

  private async drain(w: Witness, p: Pump): Promise<void> {
    p.busy = true;
    while (p.next !== null) {
      const { note, head } = p.next;
      p.next = null;
      const a: WitnessAnswer = await w.publish(note, (from) => this.consistency(from, head.size))
        .catch((e: Error) => ({ ok: false, reason: `unreachable: ${e.message}` }));
      const upto = BigInt(head.upto);
      if (a.ok && upto > p.acked) {
        p.acked = upto;
        p.cosigned = a.cosigned ?? null;
      }
      p.failure = a.ok ? null : a.reason;
      p.waiters = p.waiters.filter((x) => {
        if (a.ok && x.upto <= p.acked) x.done(null);
        else return true;
        return false;
      });
    }
    p.busy = false;
    // Someone still waits on this witness after a failed try: try again shortly, with the newest head.
    if (p.waiters.length > 0 && p.failure !== null) {
      setTimeout(() => {
        if (!p.busy && p.waiters.length > 0) {
          p.next = { note: this.note, head: this.head };
          void this.drain(w, p);
        }
      }, 100).unref();
    }
  }

  /**
   * Whether every witness holds a head sealing `upto`, within the deadline: the
   * failures, if not, and the cosigned heads. A witness that is behind and idle
   * (its last try failed) is asked again now, with the newest head; at the
   * deadline the answer names its last failure, if it had one.
   */
  private async witnessed(upto: string, deadline: number): Promise<{ failures: string[]; cosigned: string[] }> {
    const answers = await Promise.all(this.witnesses.map((w) => {
      const p = this.pump(w);
      if (p.acked >= BigInt(upto)) return null;
      const answer = new Promise<string | null>((resolve) => {
        const waiter = { upto: BigInt(upto), done: (f: string | null) => { clearTimeout(timer); resolve(f); } };
        // At the deadline the waiter goes, so nothing keeps retrying on its behalf after the change has answered.
        const timer = setTimeout(() => {
          p.waiters = p.waiters.filter((x) => x !== waiter);
          resolve(`witness ${w.name}: no answer within ${deadline} ms${p.failure === null ? '' : ` (last: ${p.failure})`}`);
        }, deadline);
        timer.unref();
        p.waiters.push(waiter);
      });
      if (!p.busy && BigInt(this.head.upto) >= BigInt(upto)) {
        p.next = { note: this.note, head: this.head };
        void this.drain(w, p);
      }
      return answer;
    }));
    const cosigned = this.witnesses.map((w) => this.pump(w)).filter((p) => p.acked >= BigInt(upto) && p.cosigned !== null).map((p) => p.cosigned!);
    return { failures: answers.filter((a): a is string => a !== null), cosigned };
  }

  /**
   * A change answers once its entry is sealed and, where witnesses are set up,
   * witnessed (R51): seal now, unless a checkpoint already covers it, then wait
   * for every witness to hold a head that covers it, whichever tick sealed it.
   * A tick that cannot seal (an entry failing its MAC) fails the change's wait
   * rather than spinning.
   */
  async sealThrough(number: string, witnessTimeoutMs = 2000): Promise<{ head: Checkpoint; note: string; witnessed: boolean | null; failures: string[]; cosigned: string[] }> {
    while (BigInt(this.head.upto) < BigInt(number)) {
      const before = this.head.upto;
      const t = await this.seal({});
      if (this.head.upto === before) throw new Error(`cannot seal ${number}: ${t.failures.join('; ') || 'nothing to seal'}`);
    }
    const { failures, cosigned } = await this.witnessed(number, witnessTimeoutMs);
    // `witnessed`: null when no witness is set up (R40 without the plugin), so nothing reads "witnessed" there.
    return { head: this.head, note: this.note, witnessed: this.witnesses.length === 0 ? null : failures.length === 0, failures, cosigned };
  }

  private async tickNow(opts: { nextDay?: number; witnessTimeoutMs?: number }): Promise<Tick> {
    const cpu0 = process.cpuUsage();
    const t0 = performance.now();
    const { rows } = await this.db.query({
      name: 'seal_window', text: 'SELECT upto::text, newest::text, number::text, at::text, principal, credential, kind, request_id, payload, seal, mac, written_at FROM seal_window($1, $2)',
      values: [this.head.upto, opts.nextDay ?? null],
    });
    const sealMs = performance.now() - t0;
    const [first, ...found] = rows as EntryRow[];
    const upto = first!.upto;
    const entries = found.map(toEntry);
    const failures = entries.filter((e) => !entryMac(this.keys.mac, e).equals(e.mac)).map((e) => `${e.number}: mac`);
    // A running signer seals from the head it holds and never takes the database's word for it; but the database's
    // newest row must still be that head. Rows deleted since show here, within a tick; nothing is signed over them.
    if (first!.newest !== this.head.upto) failures.push(`the database's newest checkpoint is ${first!.newest ?? 'gone'}, the signer's head is at ${this.head.upto}`);
    const empty: Tick = {
      upto: this.head.upto, size: this.edge.size, entries: entries.length, signed: false, sealMs, writeMs: 0, cpuMs: 0,
      oldestToSealMs: 0, oldestToWitnessedMs: 0, newestToSealMs: 0, witnessMs: 0, tilesWritten: 0, failures,
    };
    // An entry that fails its MAC stops the checkpoint: nothing is signed over it, and an operator is told.
    if (failures.length > 0) return empty;
    if (upto === this.head.upto) {
      // Nothing new: the day, if one ended, ends at the last checkpoint.
      if (opts.nextDay !== undefined) {
        await this.db.query('UPDATE checkpoints SET closed_day = $1 WHERE upto = $2', [opts.nextDay - 1, upto]);
        await this.recordDay(opts.nextDay - 1, this.head);
      }
      // A quiet log: hand the newest head again to any witness that failed to take it.
      for (const w of this.witnesses) {
        const p = this.pump(w);
        if (p.acked < BigInt(this.head.upto) && !p.busy) this.publish(this.note, this.head);
      }
      return empty;
    }
    let tiles: Tile[], head: Checkpoint, note: string, cpu1: NodeJS.CpuUsage, t1: number;
    try {
      tiles = this.edge.append(entries.map(leafOf));
      head = { origin: this.keys.origin, size: this.edge.size, root: this.edge.root(), upto, at: Date.now() };
      note = await signNote(checkpointBody(head), [this.keys.signer]);
      cpu1 = process.cpuUsage(cpu0);
      // Remembered outside the database before the database has it (formal/Seal.tla, RememberFirst): a crash
      // between the two and a rollback can then never get a second head signed for the same place.
      await this.memory?.remember(note);
      t1 = performance.now();
      await writeCheckpoint(this.db, tiles, head, note, opts.nextDay === undefined ? null : opts.nextDay - 1);
    } catch (error) {
      // The edge has moved on in memory but not in the database, whichever step failed: start again from what the
      // database holds. (A head remembered but not written is the memory being ahead, which the next tick extends.)
      this.edge = await loadEdge(this.db, this.head.size);
      throw error;
    }
    const sealedAt = Date.now();
    const writeMs = performance.now() - t1;
    this.head = head;
    this.note = note;
    if (opts.nextDay !== undefined) await this.recordDay(opts.nextDay - 1, head);
    this.publish(note, head);
    const oldest = found.length === 0 ? sealedAt : Math.min(...found.map((r) => r.written_at.getTime()));
    const newest = found.length === 0 ? sealedAt : Math.max(...found.map((r) => r.written_at.getTime()));
    return {
      upto, size: head.size, entries: entries.length, signed: true, sealMs, writeMs, cpuMs: (cpu1.user + cpu1.system) / 1000,
      oldestToSealMs: sealedAt - oldest, oldestToWitnessedMs: 0, newestToSealMs: sealedAt - newest,
      witnessMs: 0, tilesWritten: tiles.length, failures,
    };
  }

  /**
   * The day just closed, as a signed change entry (kept forever): its numbers
   * [first, last] and its leaves [firstLeaf, lastLeaf], so retention and
   * verifiers read a day's extent from the log rather than infer it from
   * numbers. A day starts where the one before ended; the first day, at the
   * tree's start.
   */
  private async recordDay(day: number, closing: Checkpoint): Promise<void> {
    const { rows: [prev] } = await this.db.query(
      `SELECT a.payload FROM audit_changes a WHERE a.payload LIKE '{"action":"audit.day"%' ORDER BY a.number DESC LIMIT 1`,
    );
    const last = prev === undefined ? null : (JSON.parse(prev.payload) as DayRecord);
    // Once per day: closing it again (a retried barrier, a clock stepped back) records nothing.
    if (last !== null && last.day >= day) return;
    const record: DayRecord = {
      action: 'audit.day', day,
      first: last === null ? '1' : String(BigInt(last.last) + 1n), last: closing.upto,
      firstLeaf: last === null ? 0 : last.lastLeaf + 1, lastLeaf: closing.size - 1,
    };
    await append(this.db, this.keys, { at: Date.now(), principal: 'vault', credential: null, kind: 'change', requestId: `day-${day}`, payload: JSON.stringify(record) });
  }

  /** A consistency proof between two sizes of the tree, from the tiles. */
  consistency(from: number, to: number): Promise<Hash[]> {
    return proveConsistency(this.db, from, to);
  }
}

async function writeCheckpoint(db: Db, tiles: readonly Tile[], head: Checkpoint, note: string, closedDay: number | null): Promise<void> {
  await db.query({
    name: 'write_checkpoint',
    text: `WITH t AS (
             INSERT INTO audit_tiles (level, idx, hashes) SELECT * FROM unnest($1::smallint[], $2::bigint[], $3::bytea[])
             ON CONFLICT (level, idx) DO UPDATE SET hashes = excluded.hashes)
           INSERT INTO checkpoints (upto, size, root, note, closed_day) VALUES ($4, $5, $6, $7, $8)`,
    values: [tiles.map((t) => t.level), tiles.map((t) => t.index), tiles.map((t) => t.hashes), head.upto, head.size, head.root, note, closedDay],
  });
}

async function loadEdge(db: Db, size: number): Promise<Edge> {
  const keys = edgeOf(size).filter((e) => e.width > 0);
  return Edge.load(size, tileMap(await readTiles(db, keys)));
}

export async function readTiles(db: Db, keys: readonly TileKey[]): Promise<Tile[]> {
  if (keys.length === 0) return [];
  const { rows } = await db.query({
    name: 'read_tiles',
    text: 'SELECT level, idx::text, hashes FROM audit_tiles WHERE (level, idx) IN (SELECT * FROM unnest($1::smallint[], $2::bigint[]))',
    values: [keys.map((k) => k.level), keys.map((k) => k.index)],
  });
  return rows.map((r) => ({ level: r.level, index: Number(r.idx), hashes: r.hashes }));
}

export async function proveConsistency(db: Db, from: number, to: number): Promise<Hash[]> {
  const nodes = nodesFrom(tileMap(await readTiles(db, tilesFor((n) => consistencyProof(n, from, to)))));
  return consistencyProof(nodes, from, to);
}

export type InclusionProof = { number: string; index: number; size: number; leaf: Buffer; proof: Hash[]; checkpoint: string; entry: Entry };

/**
 * `GET /audit/proof?number=…`: where an entry is in the tree, and the proof that
 * it is there, against the newest checkpoint (or the newest of at most `size`
 * leaves). Two statements: the entry, its leaf index (its checkpoint's first
 * index, plus the entries of that window before it: at most one window's worth
 * of index entries) and the checkpoint; then the tiles the proof reads, one per
 * 8 levels.
 */
export async function proveNumber(db: Db, number: string, size?: number): Promise<InclusionProof | null> {
  const { rows: [r] } = await db.query({
    name: 'locate',
    text: `SELECT e.number::text, e.at::text, e.principal, e.credential, e.kind, e.request_id, e.payload, e.seal, e.mac,
             p.size::text AS first, (SELECT count(*) FROM audit a WHERE a.number > p.upto AND a.number < e.number)::text AS before,
             h.size::text AS size, h.note
           FROM audit e,
             LATERAL (SELECT size, upto FROM checkpoints WHERE upto < e.number ORDER BY upto DESC LIMIT 1) p,
             LATERAL (SELECT size FROM checkpoints WHERE upto >= e.number ORDER BY upto LIMIT 1) c,
             LATERAL (SELECT size, note FROM checkpoints WHERE $2::bigint IS NULL OR size <= $2 ORDER BY upto DESC LIMIT 1) h
           WHERE e.number = $1 AND h.size >= c.size`,
    values: [number, size ?? null],
  });
  if (r === undefined) return null;
  const entry = toEntry({ ...r, upto: '' });
  const index = Number(r.first) + Number(r.before);
  const n = Number(r.size);
  const nodes = nodesFrom(tileMap(await readTiles(db, tilesFor((x) => inclusionProof(x, index, n)))));
  return { number, index, size: n, leaf: leafOf(entry), proof: inclusionProof(nodes, index, n), checkpoint: r.note, entry };
}
