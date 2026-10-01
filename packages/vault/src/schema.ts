import type { Sqlite } from './sqlite.ts';

/**
 * The vault's store: who is in, what they hold, what it signed, and its log.
 * One SQLite database the app has no credentials for: a Durable Object's on
 * Workers, a file of the vault's own in a Node process.
 *
 * Times are milliseconds since the epoch. Principals are the strings the
 * app writes in URLs: `user:ada@acme.example`, `token:ci-deploy`, and
 * `sync:<id>` for a sync.
 *
 * Each migration is a list of statements, one per call, and is never edited
 * once released: a change to the store is a new one at the end.
 */
const MIGRATIONS: readonly (readonly string[])[] = [
  [
    // Everyone the vault has admitted. A principal with no row is no member.
    // `owner` is an instance owner: manages every project and every member,
    // users only. `since` and `by` are when the status last changed, and who
    // changed it.
    `CREATE TABLE principals (
      principal TEXT PRIMARY KEY,
      status TEXT NOT NULL CHECK (status IN ('active', 'removed')),
      owner INTEGER NOT NULL DEFAULT 0 CHECK (owner IN (0, 1)),
      since INTEGER NOT NULL,
      by TEXT NOT NULL
    ) STRICT`,

    // One role per principal per place: a project (`environment_id` null) or
    // one of its environments. A revoked grant is deleted; an expired one
    // stays until the place is granted again, so the members page can say it
    // lapsed.
    `CREATE TABLE grants (
      principal TEXT NOT NULL,
      project_id TEXT NOT NULL,
      environment_id TEXT,
      role TEXT NOT NULL,
      expires_at INTEGER,
      granted_at INTEGER NOT NULL,
      granted_by TEXT NOT NULL
    ) STRICT`,
    `CREATE UNIQUE INDEX grants_on_project ON grants (principal, project_id) WHERE environment_id IS NULL`,
    `CREATE UNIQUE INDEX grants_on_environment ON grants (principal, environment_id) WHERE environment_id IS NOT NULL`,
    // Every decision reads one principal's grants.
    `CREATE INDEX grants_by_principal ON grants (principal)`,

    // The vault's log. Each row commits to the one before it (`hash` is an
    // HMAC over `prev_hash` and the row, keyed from the signing key), and the
    // only code that touches this table appends. Triggers refuse UPDATE and
    // DELETE besides, so a bug cannot rewrite it either; only someone holding
    // the raw storage can, and without the key the chain shows it. `actor` is who asked: the principal an unwrap is
    // for, or who changed access. `code` is why a refusal was one. `subject`
    // is what it was about: a secret's path, a principal, the app's log.
    // `detail` is everything else, as JSON: ids, roles, the purpose of a read.
    `CREATE TABLE log (
      seq INTEGER PRIMARY KEY,
      at INTEGER NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'refuse')),
      code TEXT,
      subject TEXT,
      detail TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    ) STRICT`,
    // The bulk limit counts one principal's recent unwraps.
    `CREATE INDEX log_by_actor ON log (actor, action, at)`,
    `CREATE TRIGGER log_no_update BEFORE UPDATE ON log
    BEGIN
      SELECT RAISE(ABORT, 'the vault log is append-only');
    END`,
    `CREATE TRIGGER log_no_delete BEFORE DELETE ON log
    BEGIN
      SELECT RAISE(ABORT, 'the vault log is append-only');
    END`,

    // Heads of the app's audit log the vault has signed, newest last, each
    // with the head of this log at the time. `seq` is the app log's last
    // sequence number at that head. Append-only, as the log is.
    `CREATE TABLE checkpoints (
      seq INTEGER PRIMARY KEY,
      head_hash TEXT NOT NULL,
      vault_seq INTEGER NOT NULL,
      vault_hash TEXT NOT NULL,
      signed_at INTEGER NOT NULL,
      key_id TEXT NOT NULL,
      signature TEXT NOT NULL
    ) STRICT`,
    `CREATE TRIGGER checkpoints_no_update BEFORE UPDATE ON checkpoints
    BEGIN
      SELECT RAISE(ABORT, 'checkpoints are append-only');
    END`,
    `CREATE TRIGGER checkpoints_no_delete BEFORE DELETE ON checkpoints
    BEGIN
      SELECT RAISE(ABORT, 'checkpoints are append-only');
    END`,
  ],
  [
    'ALTER TABLE principals ADD COLUMN generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0)',
    // Existing removals already belong to the log. Preserve their generations.
    `UPDATE principals SET generation = (
      SELECT count(*) FROM log WHERE action = 'principal.remove'
      AND outcome = 'allow' AND subject = principals.principal
    )`,
  ],
];

/**
 * Bring the store up to date, in one transaction: a store is at one version
 * or the next, never between. `migrations` records each one applied; a store
 * that has more than this code knows was written by a newer vault, and is
 * refused rather than half understood.
 */
export function migrate(db: Sqlite): void {
  db.transaction(() => {
    db.run('CREATE TABLE IF NOT EXISTS migrations (version INTEGER PRIMARY KEY) STRICT');
    const { applied } = db.get<{ applied: number }>('SELECT count(*) AS applied FROM migrations')!;
    if (applied > MIGRATIONS.length) {
      throw new Error(`the vault's store is at version ${applied}; this vault knows ${MIGRATIONS.length}`);
    }
    for (const [i, statements] of MIGRATIONS.entries()) {
      if (i < applied) continue;
      for (const statement of statements) db.run(statement);
      db.run('INSERT INTO migrations (version) VALUES (?)', i + 1);
    }
  });
}
