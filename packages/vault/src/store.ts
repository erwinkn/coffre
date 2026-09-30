import { migrate } from './schema.ts';
import type { Sqlite } from './sqlite.ts';

/** A member's row; `schema.ts` says what each column means. */
export type Member = { principal: string; status: 'active' | 'removed'; owner: boolean; since: number; by: string };

/** Where a grant applies: a project (`environmentId` null), or one of its environments. */
export type Place = { projectId: string; environmentId: string | null };

export type GrantRow = Place & {
  principal: string;
  role: string;
  expiresAt: number | null;
  grantedAt: number;
  grantedBy: string;
};

export type LogRow = {
  seq: number;
  at: number;
  actor: string;
  action: string;
  outcome: 'allow' | 'refuse';
  code: string | null;
  subject: string | null;
  /** JSON. */
  detail: string;
  prevHash: string;
  hash: string;
};

export type CheckpointRow = {
  seq: number;
  headHash: string;
  vaultSeq: number;
  vaultHash: string;
  signedAt: number;
  keyId: string;
  signature: string;
};

const GRANT = `principal, project_id AS projectId, environment_id AS environmentId, role,
  expires_at AS expiresAt, granted_at AS grantedAt, granted_by AS grantedBy`;
const LOG = 'seq, at, actor, action, outcome, code, subject, detail, prev_hash AS prevHash, hash';
const CHECKPOINT = `seq, head_hash AS headHash, vault_seq AS vaultSeq, vault_hash AS vaultHash,
  signed_at AS signedAt, key_id AS keyId, signature`;

/** The vault's store on `db`, migrated. */
export function openStore(db: Sqlite): Store {
  migrate(db);
  return new Store(db);
}

/**
 * Every query the vault makes, and the only code in it that holds SQL. Each
 * reads or writes one thing; what they add up to, a decision, is in
 * `vault.ts`, which runs them inside `transaction`.
 */
export class Store {
  readonly #db: Sqlite;

  constructor(db: Sqlite) {
    this.#db = db;
  }

  transaction<T>(fn: () => T): T {
    return this.#db.transaction(fn);
  }

  // --- members ------------------------------------------------------------

  member(principal: string): Member | undefined {
    const row = this.#db.get<Omit<Member, 'owner'> & { owner: number }>(
      'SELECT principal, status, owner, since, by FROM principals WHERE principal = ?',
      principal,
    );
    return row && { ...row, owner: row.owner === 1 };
  }

  memberNames(): string[] {
    return this.#db.all<{ principal: string }>('SELECT principal FROM principals').map((row) => row.principal);
  }

  /** Every member's row, for the replay in `replay.ts`. */
  allMembers(): Member[] {
    return this.#db
      .all<Omit<Member, 'owner'> & { owner: number }>('SELECT principal, status, owner, since, by FROM principals')
      .map((row) => ({ ...row, owner: row.owner === 1 }));
  }

  /** Admit, restore or remove: `member`'s row becomes this one. */
  putMember(member: Member): void {
    this.#db.run(
      `INSERT INTO principals (principal, status, owner, since, by) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (principal) DO UPDATE
       SET status = excluded.status, owner = excluded.owner, since = excluded.since, by = excluded.by`,
      member.principal,
      member.status,
      member.owner ? 1 : 0,
      member.since,
      member.by,
    );
  }

  setOwner(principal: string, owner: boolean): void {
    this.#db.run('UPDATE principals SET owner = ? WHERE principal = ?', owner ? 1 : 0, principal);
  }

  // --- grants -------------------------------------------------------------

  /** Every grant `principal` has, lapsed ones too. */
  grants(principal: string): GrantRow[] {
    return this.#db.all<GrantRow>(`SELECT ${GRANT} FROM grants WHERE principal = ?`, principal);
  }

  /** Every grant anyone has, lapsed ones too. */
  allGrants(): GrantRow[] {
    return this.#db.all<GrantRow>(`SELECT ${GRANT} FROM grants`);
  }

  grant(principal: string, place: Place): GrantRow | undefined {
    return this.#db.get<GrantRow>(
      `SELECT ${GRANT} FROM grants WHERE principal = ? AND project_id = ? AND environment_id IS ?`,
      principal,
      place.projectId,
      place.environmentId,
    );
  }

  /** `grant`, replacing whatever `grant.principal` held at its place. */
  putGrant(grant: GrantRow): void {
    this.deleteGrant(grant.principal, grant);
    this.#db.run(
      `INSERT INTO grants (principal, project_id, environment_id, role, expires_at, granted_at, granted_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      grant.principal,
      grant.projectId,
      grant.environmentId,
      grant.role,
      grant.expiresAt,
      grant.grantedAt,
      grant.grantedBy,
    );
  }

  deleteGrant(principal: string, place: Place): void {
    this.#db.run(
      'DELETE FROM grants WHERE principal = ? AND project_id = ? AND environment_id IS ?',
      principal,
      place.projectId,
      place.environmentId,
    );
  }

  deleteGrants(principal: string): void {
    this.#db.run('DELETE FROM grants WHERE principal = ?', principal);
  }

  // --- the log ------------------------------------------------------------

  /** How many keys `principal` has been given since `after`, for the bulk limit. */
  unwrapsSince(principal: string, after: number): number {
    return this.#db.get<{ n: number }>(
      `SELECT count(*) AS n FROM log WHERE actor = ? AND action = 'unwrap' AND outcome = 'allow' AND at > ?`,
      principal,
      after,
    )!.n;
  }

  logHead(): Pick<LogRow, 'seq' | 'hash'> | undefined {
    return this.#db.get('SELECT seq, hash FROM log ORDER BY seq DESC LIMIT 1');
  }

  logEntry(seq: number): LogRow | undefined {
    return this.#db.get<LogRow>(`SELECT ${LOG} FROM log WHERE seq = ?`, seq);
  }

  /** Up to `limit` entries before `before` (the head when undefined), newest first. */
  logPage(before: number | undefined, limit: number): LogRow[] {
    return this.#db.all<LogRow>(
      `SELECT ${LOG} FROM log WHERE seq < ? ORDER BY seq DESC LIMIT ?`,
      before ?? Number.MAX_SAFE_INTEGER,
      limit,
    );
  }

  /** Every entry after `seq`, oldest first, read one at a time. */
  logAfter(seq: number): Iterable<LogRow> {
    return this.#db.iterate<LogRow>(`SELECT ${LOG} FROM log WHERE seq > ? ORDER BY seq`, seq);
  }

  /** Every allowed entry of these actions, oldest first, read one at a time. */
  logOf(actions: readonly string[]): Iterable<LogRow> {
    return this.#db.iterate<LogRow>(
      `SELECT ${LOG} FROM log WHERE outcome = 'allow' AND action IN (${actions.map(() => '?').join(', ')}) ORDER BY seq`,
      ...actions,
    );
  }

  appendLog(row: LogRow): void {
    this.#db.run(
      `INSERT INTO log (seq, at, actor, action, outcome, code, subject, detail, prev_hash, hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      row.seq,
      row.at,
      row.actor,
      row.action,
      row.outcome,
      row.code,
      row.subject,
      row.detail,
      row.prevHash,
      row.hash,
    );
  }

  // --- checkpoints --------------------------------------------------------

  latestCheckpoint(): CheckpointRow | undefined {
    return this.#db.get<CheckpointRow>(`SELECT ${CHECKPOINT} FROM checkpoints ORDER BY seq DESC LIMIT 1`);
  }

  addCheckpoint(row: CheckpointRow): void {
    this.#db.run(
      `INSERT INTO checkpoints (seq, head_hash, vault_seq, vault_hash, signed_at, key_id, signature)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      row.seq,
      row.headHash,
      row.vaultSeq,
      row.vaultHash,
      row.signedAt,
      row.keyId,
      row.signature,
    );
  }
}
