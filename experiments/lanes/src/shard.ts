import { DurableObject } from 'cloudflare:workers';
import { Client } from 'pg';

import { GENESIS, seal, type Fields } from './chain.ts';
import { keysFrom, memberMac, unwrap, type Grant, type Keys, type Member } from './model.ts';

export type ShardEnv = { HD: Hyperdrive; SHARD: DurableObjectNamespace<Shard>; SEED: string; SHARDS: string };

export type ShardUse = { principal: string; credential: string; environmentId: string; secretId: string; requestId: string };
export type ShardAnswer =
  | { ok: true; value: string; seq: number; shard: number; loaded: boolean }
  | { ok: false; code: string; retryAfter?: number };

/**
 * What a shard knows of one principal: read from Postgres once, at a
 * revision, and kept until a change fences it.
 */
type Standing = {
  revision: number;
  member: Member | null;
  grants: Grant[];
  /** Credentials of theirs, by id: whether each is live. */
  credentials: Map<string, boolean>;
  /** Their newest access entry on the control lane, which the member row must name. */
  accessSeq: string | null;
};

/** A shard's own lane of the audit log starts at this lane number in Postgres, plus its index. */
export const SHARD_LANE_BASE = 100;

/** Entries a flush copies to Postgres at most, and how often it runs while some wait. */
const FLUSH_BATCH = 2000;
const FLUSH_EVERY_MS = 200;

/**
 * One shard of the vault's hot path, and the only writer of its own lane.
 *
 * It answers a use from memory: the principal's standing and credentials,
 * read once from Postgres at a revision, and the key it opened once. Each
 * use is an entry in its lane, sealed from the head it holds, written to
 * its own SQLite storage before the answer leaves (the output gate holds
 * the answer until the write is durable), and copied to Postgres in
 * batches behind it, each one statement that writes only if Postgres's
 * head for the lane is where the shard had it.
 *
 * A change to anything a use decides on fences every shard first, with
 * the revision it will commit at: from then, a shard answers only from
 * standing read at that revision or later, reading again (or refusing,
 * 'changing', while the change has not committed) for anything older. The
 * change commits, then answers. So a use that arrives after the answer is
 * decided on the change, whichever shard serves it.
 */
export class Shard extends DurableObject<ShardEnv> {
  #keys: Keys;
  #index = -1;
  #head: { seq: number; hash: Buffer };
  #flushed: number;
  /** The lowest revision a standing may be read at; raised by fences. */
  #floor = 0;
  #standing = new Map<string, Standing>();
  #loading = new Map<string, Promise<Standing>>();
  /** Opened keys, by secret id. */
  #values = new Map<string, Buffer>();
  /** One connection for standing reads, one for flushes: a statement on either never waits behind the other's. */
  #client: Client | null = null;
  #flusher: Client | null = null;
  /** Fences received since this instance started: a probe lowers the floor only if none came while it ran. */
  #fences = 0;
  #flushing = false;
  uses = 0;

  constructor(ctx: DurableObjectState, env: ShardEnv) {
    super(ctx, env);
    this.#keys = keysFrom(env.SEED);
    const sql = ctx.storage.sql;
    sql.exec(`CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, actor TEXT, action TEXT, decision TEXT, subject TEXT,
      environment_id TEXT, control_seq TEXT, occurred_at INTEGER, metadata TEXT, prev_hash BLOB, mac BLOB, hash BLOB)`);
    sql.exec('CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT)');
    const last = sql.exec<{ seq: number; hash: ArrayBuffer }>('SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1').toArray()[0];
    this.#head = last === undefined ? { seq: 0, hash: GENESIS } : { seq: last.seq + 1, hash: Buffer.from(last.hash) };
    const flushed = sql.exec<{ v: string }>("SELECT v FROM state WHERE k = 'flushed'").toArray()[0];
    this.#flushed = flushed === undefined ? 0 : Number(flushed.v);
    // A fence outlives a restart: a shard that forgot it would read standing from before the change that fenced it.
    const floor = sql.exec<{ v: string }>("SELECT v FROM state WHERE k = 'floor'").toArray()[0];
    if (floor !== undefined) this.#floor = Number(floor.v);
    const index = sql.exec<{ v: string }>("SELECT v FROM state WHERE k = 'index'").toArray()[0];
    if (index !== undefined) this.#index = Number(index.v);
  }

  async use(index: number, input: ShardUse): Promise<ShardAnswer> {
    this.#claim(index);
    this.uses += 1;
    let standing = this.#standing.get(input.principal);
    let loaded = false;
    if (standing === undefined || standing.revision < this.#floor) {
      standing = await this.#load(input.principal, input.environmentId, input.secretId);
      loaded = true;
      if (standing.revision < this.#floor) {
        if (!(await this.#probe())) return { ok: false, code: 'changing', retryAfter: 1 };
        standing = await this.#load(input.principal, input.environmentId, input.secretId);
        if (standing.revision < this.#floor) return { ok: false, code: 'changing', retryAfter: 1 };
      }
    }
    const why = refusal(this.#keys, standing, input);
    const key = why === null ? this.#values.get(input.secretId) : undefined;
    if (why === null && key === undefined) return { ok: false, code: 'missing' };
    const fields: Fields = {
      actor: input.principal,
      action: 'secret.use',
      decision: why === null ? 'allow' : 'deny',
      subject: input.principal,
      environmentId: input.environmentId,
      controlSeq: String(standing.revision),
      occurredAt: Date.now(),
      metadata: JSON.stringify({ requestId: input.requestId, credential: input.credential, secretId: input.secretId, ...(why === null ? {} : { code: why }) }),
    };
    const seq = this.#append(fields);
    if (why !== null) return { ok: false, code: why };
    return { ok: true, value: key!.toString('base64'), seq, shard: this.#index, loaded };
  }

  /** From now, answer only from standing read at `revision` or later. */
  async fence(index: number, revision: number): Promise<void> {
    this.#claim(index);
    this.#fences += 1;
    if (revision > this.#floor) this.#setFloor(revision);
  }

  /**
   * A change that fenced rolled back. Only a hint to probe: lowering the
   * floor here would undo a later change's fence at the same revision
   * (revisions are reused after a rollback), or a change whose commit
   * succeeded but whose answer was lost (formal/Shards.tla, UnfenceProbes).
   */
  async unfence(_revision: number): Promise<void> {
    await this.#probe().catch(() => false);
  }

  /** Durable before the fence is acknowledged: the output gate holds the answer until the write is. */
  #setFloor(floor: number): void {
    this.#floor = floor;
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO state VALUES ('floor', ?)", String(floor));
  }

  /**
   * Standing read below the floor: the change that fenced has not
   * committed. If no change holds the revision's row now, it never will:
   * it rolled back, and its unfence was lost. Then the floor comes down to
   * the revision there is. Exact, with no clock: a change holds the row
   * from before its fence until its commit.
   */
  async #probe(): Promise<boolean> {
    // A transaction of its own, on a connection of its own: never one that other calls' statements queue on.
    const seen = this.#fences;
    const client = new Client({ connectionString: this.env.HD.connectionString });
    await client.connect();
    let value: number;
    try {
      await client.query('BEGIN');
      const { rows } = await client.query('SELECT value::text AS value FROM revision WHERE only_row FOR UPDATE NOWAIT');
      value = Number(rows[0].value);
    } catch (error) {
      if ((error as { code?: string }).code === '55P03') return false;
      throw error;
    } finally {
      void client.query('ROLLBACK').catch(() => {}).finally(() => client.end().catch(() => {}));
    }
    // A fence that came while the probe was out may be a new change at the same revision: keep it (ProbeKeepsFence).
    if (this.#fences !== seen) return false;
    // A floor is never more than one past the revision: further below is a database restored from an older backup.
    if (value < this.#floor - 1) throw new Error(`the revision is ${value}, below this shard's floor ${this.#floor} by more than one: restored from a backup?`);
    if (value < this.#floor) this.#setFloor(value);
    return true;
  }

  async stats(): Promise<{ index: number; head: number; flushed: number; uses: number; principals: number; floor: number }> {
    return { index: this.#index, head: this.#head.seq, flushed: this.#flushed, uses: this.uses, principals: this.#standing.size, floor: this.#floor };
  }

  /** Forget everything, storage too: for a load test that starts the database over. */
  async reset(): Promise<void> {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, actor TEXT, action TEXT, decision TEXT, subject TEXT,
      environment_id TEXT, control_seq TEXT, occurred_at INTEGER, metadata TEXT, prev_hash BLOB, mac BLOB, hash BLOB)`);
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT)');
    this.#head = { seq: 0, hash: GENESIS };
    this.#flushed = 0;
    this.#floor = 0;
    this.#standing.clear();
    this.#values.clear();
    this.#index = -1;
    this.uses = 0;
  }

  /** Copy what Postgres lacks, then stop: the alarm runs while entries wait. */
  async alarm(): Promise<void> {
    await this.#flush();
    if (this.#flushed < this.#head.seq) await this.ctx.storage.setAlarm(Date.now() + FLUSH_EVERY_MS);
  }

  #claim(index: number): void {
    if (this.#index === index) return;
    this.#index = index;
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO state VALUES ('index', ?)", String(index));
  }

  /** Seal `fields` from the head and write it to this shard's storage: durable before any answer leaves. */
  #append(fields: Fields): number {
    const lane = SHARD_LANE_BASE + this.#index;
    const entry = seal(this.#keys.log, lane, BigInt(this.#head.seq), this.#head.hash, fields);
    this.ctx.storage.sql.exec(
      'INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      this.#head.seq, fields.actor, fields.action, fields.decision, fields.subject, fields.environmentId, fields.controlSeq,
      fields.occurredAt, fields.metadata, entry.prevHash, entry.mac, entry.hash,
    );
    const seq = this.#head.seq;
    this.#head = { seq: seq + 1, hash: entry.hash };
    if (!this.#flushing && seq === this.#flushed) void this.ctx.storage.setAlarm(Date.now() + FLUSH_EVERY_MS);
    return seq;
  }

  async #connect(): Promise<Client> {
    if (this.#client !== null) return this.#client;
    const client = new Client({ connectionString: this.env.HD.connectionString });
    await client.connect();
    this.#client = client;
    return client;
  }

  /**
   * A principal's standing, read from Postgres in one statement with the
   * revision it was read at; and the key the use asks for, opened once.
   * Calls that need the same principal at once share one read.
   */
  async #load(principal: string, environmentId: string, secretId: string): Promise<Standing> {
    const pending = this.#loading.get(principal);
    if (pending !== undefined) return pending;
    const loading = (async () => {
      const client = await this.#connect();
      try {
        const { rows } = await client.query(STANDING, [principal, environmentId, secretId]);
        const s = rows[0].s as {
          revision: string; member: Member | null; grants: Grant[]; credentials: { id: string; revoked: boolean }[];
          access: { seq: string } | null; secret: { wrapped: string; iv: string } | null;
        };
        const standing: Standing = {
          revision: Number(s.revision),
          member: s.member,
          grants: s.grants,
          credentials: new Map(s.credentials.map((c) => [c.id, !c.revoked])),
          accessSeq: s.access?.seq ?? null,
        };
        if (s.secret !== null && !this.#values.has(secretId)) {
          this.#values.set(secretId, unwrap(this.#keys.kek, Buffer.from(s.secret.wrapped, 'hex'), Buffer.from(s.secret.iv, 'hex')));
        }
        // A fence that came while this read was out may already ask for more: kept only if it is enough.
        if (standing.revision >= this.#floor) this.#standing.set(principal, standing);
        return standing;
      } catch (error) {
        this.#client = null;
        void client.end().catch(() => {});
        throw error;
      } finally {
        this.#loading.delete(principal);
      }
    })();
    this.#loading.set(principal, loading);
    return loading;
  }

  /** Copy the entries Postgres lacks, in one statement that writes only where Postgres's head for the lane is. */
  async #flush(): Promise<void> {
    if (this.#flushing) return;
    this.#flushing = true;
    try {
      const rows = this.ctx.storage.sql.exec<{
        seq: number; actor: string; action: string; decision: string; subject: string; environment_id: string; control_seq: string;
        occurred_at: number; metadata: string; prev_hash: ArrayBuffer; mac: ArrayBuffer; hash: ArrayBuffer;
      }>('SELECT * FROM entries WHERE seq >= ? ORDER BY seq LIMIT ?', this.#flushed, FLUSH_BATCH).toArray();
      if (rows.length === 0) return;
      const lane = SHARD_LANE_BASE + this.#index;
      // A storage write first: an instance that is no longer this shard's fails it, and its output gate holds what follows.
      this.ctx.storage.sql.exec("INSERT OR REPLACE INTO state VALUES ('flushing', ?)", String(rows.at(-1)!.seq));
      if (this.#flusher === null) {
        const flusher = new Client({ connectionString: this.env.HD.connectionString });
        await flusher.connect();
        this.#flusher = flusher;
      }
      const client = this.#flusher;
      const last = rows.at(-1)!;
      const { rows: done } = await client.query(
        `WITH moved AS (
           UPDATE lanes SET next_seq = $15, head_hash = $16 WHERE lane = $14 AND next_seq = $17 RETURNING 1
         ),
         appended AS (
           INSERT INTO lane_log (lane, seq, author, actor, action, decision, subject, environment_id, control_seq, occurred_at, metadata, prev_hash, mac, hash)
           SELECT $14, * FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::uuid[], $8::bigint[], $9::bigint[], $10::text[], $11::bytea[], $12::bytea[], $13::bytea[])
           WHERE EXISTS (SELECT 1 FROM moved) RETURNING 1
         )
         SELECT EXISTS (SELECT 1 FROM moved) AS written, (SELECT next_seq::text FROM lanes WHERE lane = $14) AS head`,
        [
          rows.map((r) => String(r.seq)), rows.map(() => 'vault'), rows.map((r) => r.actor), rows.map((r) => r.action), rows.map((r) => r.decision),
          rows.map((r) => r.subject), rows.map((r) => r.environment_id), rows.map((r) => r.control_seq), rows.map((r) => String(r.occurred_at)),
          rows.map((r) => r.metadata), rows.map((r) => Buffer.from(r.prev_hash)), rows.map((r) => Buffer.from(r.mac)), rows.map((r) => Buffer.from(r.hash)),
          lane, String(last.seq + 1), Buffer.from(last.hash), String(this.#flushed),
        ],
      );
      // Written, or Postgres already has them (a flush whose answer was lost): either way it is at its head.
      const at = done[0].written ? last.seq + 1 : Number(done[0].head);
      if (!done[0].written && at < this.#flushed) throw new Error(`Postgres's lane ${lane} is behind what this shard copied: rewound`);
      this.#flushed = at;
      this.ctx.storage.sql.exec("INSERT OR REPLACE INTO state VALUES ('flushed', ?)", String(at));
    } catch (error) {
      void this.#flusher?.end().catch(() => {});
      this.#flusher = null;
      throw error;
    } finally {
      this.#flushing = false;
    }
  }
}

/** Why a use is refused, or null: the credential, the member row and its seal, the grant. */
function refusal(keys: Keys, s: Standing, input: ShardUse): string | null {
  if (s.credentials.get(input.credential) !== true) return 'credential';
  if (s.member === null || s.member.status !== 'active') return 'not_member';
  if (!memberMac(keys.row, s.member, s.grants).equals(Buffer.from(s.member.mac, 'hex'))) return 'tampered';
  if (s.accessSeq !== String(s.member.access_seq)) return 'stale';
  if (!s.grants.some((g) => g.environment_id === input.environmentId)) return 'forbidden';
  return null;
}

/** A principal's standing and the revision it holds at, in one statement. */
const STANDING = `
  SELECT json_build_object(
    'revision', (SELECT value::text FROM revision WHERE only_row),
    'member', (SELECT json_build_object('principal', principal, 'status', status, 'role', role, 'access_seq', access_seq::text, 'mac', encode(mac, 'hex')) FROM members WHERE principal = $1),
    'grants', (SELECT coalesce(json_agg(json_build_object('principal', principal, 'environment_id', environment_id, 'role', role)), '[]') FROM grants WHERE principal = $1),
    'credentials', (SELECT coalesce(json_agg(json_build_object('id', id, 'revoked', revoked)), '[]') FROM credentials WHERE principal = $1),
    'access', (SELECT json_build_object('seq', seq::text) FROM lane_log WHERE lane = 0 AND subject = $1 AND action LIKE 'access.%' ORDER BY seq DESC LIMIT 1),
    'secret', (SELECT json_build_object('wrapped', encode(wrapped, 'hex'), 'iv', encode(iv, 'hex')) FROM secrets WHERE id = $3 AND environment_id = $2)
  ) AS s`;
