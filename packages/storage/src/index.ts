import { sql, type SQL } from 'drizzle-orm';
import { PgDialect } from 'drizzle-orm/pg-core';
import { MySqlDialect } from 'drizzle-orm/mysql-core';
import { SQLiteSyncDialect } from 'drizzle-orm/sqlite-core';
import { Client } from 'pg';
import { createConnection, type Connection, type ResultSetHeader } from 'mysql2/promise';
import { RetryConflict, type AuditEvent, type Command, type CommitPlan, type Mutation, type Snapshot, type Storage, type StorageCapabilities } from '../../contracts/src/index';
import { canonical } from '../../crypto/src/index';

type Row = Record<string, unknown>;
interface Driver {
  engine: StorageCapabilities['engine'];
  snapshot(queries: SQL[]): Promise<Row[][]>;
  atomic(cas: SQL, statements: SQL[]): Promise<void>;
  query(statement: SQL): Promise<Row[]>;
  close(): Promise<void>;
}
const tables = { projects: 'coffre_projects', environments: 'coffre_environments', secrets: 'coffre_secrets', principals: 'coffre_principals', grants: 'coffre_grants', versions: 'coffre_versions' } as const;
function mutationStatements(m: Mutation, engine: Driver['engine']): SQL[] {
  if (m.table === 'revokeGrant') return [sql`DELETE FROM coffre_grants WHERE id=${m.id}`];
  const columns: Record<string, unknown> = m.table === 'versions' ? { secret_id: m.record.secretId, version: m.record.version, record: canonical(m.record) } : { id: m.record.id, record: canonical(m.record) };
  if (m.table === 'projects') Object.assign(columns, { name: m.record.name });
  if (m.table === 'environments') Object.assign(columns, { project_id: m.record.projectId, name: m.record.name });
  if (m.table === 'secrets') Object.assign(columns, { env_id: m.record.envId, secret_key: m.record.key });
  if (m.table === 'principals') Object.assign(columns, { subject: m.record.subject, kind: m.record.kind });
  if (m.table === 'grants') Object.assign(columns, { principal_id: m.record.principalId, scope_type: m.record.scope.type, scope_id: m.record.scope.id });
  const names = Object.keys(columns);
  const table = sql.identifier(tables[m.table]);
  let statement = sql`INSERT INTO ${table} (${sql.join(names.map(n => sql.identifier(n)), sql`, `)}) VALUES (${sql.join(Object.values(columns).map(v => sql`${v}`), sql`, `)})`;
  if (m.table !== 'versions') {
    const updates = names.filter(n => n !== 'id');
    statement = engine === 'mysql'
      ? sql`${statement} ON DUPLICATE KEY UPDATE ${sql.join(updates.map(n => sql`${sql.identifier(n)}=VALUES(${sql.identifier(n)})`), sql`, `)}`
      : sql`${statement} ON CONFLICT(id) DO UPDATE SET ${sql.join(updates.map(n => sql`${sql.identifier(n)}=excluded.${sql.identifier(n)}`), sql`, `)}`;
  }
  return [statement];
}
const decode = <T>(rows: Row[]) => rows.map(row => JSON.parse(String(row.record)) as T);
export class SqlStorage implements Storage {
  constructor(private readonly driver: Driver) {}
  async capabilities(): Promise<StorageCapabilities> {
    let protectedAudit = false;
    if (this.driver.engine === 'postgres') {
      const [r] = await this.driver.query(sql`SELECT (NOT has_table_privilege(current_user, 'coffre_audit', 'UPDATE') AND NOT has_table_privilege(current_user, 'coffre_audit', 'DELETE') AND NOT has_table_privilege(current_user, 'coffre_audit', 'TRUNCATE')) AS protected`);
      protectedAudit = r?.protected === true;
    }
    // MySQL's contract is implemented, but its role certification is intentionally not asserted yet.
    return { engine: this.driver.engine, databaseEnforcedAppendOnly: protectedAudit };
  }
  async snapshot(command: Command, requestId: string): Promise<Snapshot> {
    const versionQuery = 'id' in command && command.type.startsWith('secret.')
      ? sql`SELECT record FROM coffre_versions WHERE secret_id=${command.id} ORDER BY version DESC`
      : command.type === 'environment.export'
      ? sql`SELECT v.record FROM coffre_versions v JOIN coffre_secrets s ON s.id=v.secret_id WHERE s.env_id=${command.envId} ORDER BY v.version DESC`
      : sql`SELECT record FROM coffre_versions WHERE 1=0`;
    const auditQuery = command.type === 'audit.list'
      ? sql`SELECT record FROM coffre_audit WHERE seq < ${command.before ?? Number.MAX_SAFE_INTEGER} ORDER BY seq DESC LIMIT ${command.limit}`
      : sql`SELECT record FROM coffre_audit WHERE 1=0`;
    const result = await this.driver.snapshot([
      sql`SELECT instance_id, revision, audit_seq, audit_hash FROM coffre_meta WHERE singleton=1`,
      ...(['projects', 'environments', 'secrets', 'principals', 'grants'] as const).map(t => sql`SELECT record FROM ${sql.identifier(tables[t])} ORDER BY id`),
      versionQuery, auditQuery, sql`SELECT record FROM coffre_receipts WHERE request_id=${requestId}`,
    ]);
    const meta = result[0]?.[0];
    if (!meta) throw new Error('Database not initialized');
    return { instanceId: String(meta.instance_id), revision: Number(meta.revision), auditSeq: Number(meta.audit_seq), auditHash: String(meta.audit_hash), projects: decode(result[1]!), environments: decode(result[2]!), secrets: decode(result[3]!), principals: decode(result[4]!), grants: decode(result[5]!), versions: decode(result[6]!), events: decode(result[7]!), receipt: decode<Snapshot['receipt']>(result[8]!)[0] ?? null };
  }
  async commit(plan: CommitPlan): Promise<void> {
    if (!plan.events.length) throw new Error('An audited commit requires at least one event');
    const last = plan.events.at(-1)!;
    if (plan.events[0]!.seq !== plan.snapshot.auditSeq + 1 || plan.events[0]!.prevHash !== plan.snapshot.auditHash) throw new Error('Invalid audit append');
    const cas = sql`UPDATE coffre_meta SET revision=revision+1, audit_seq=${last.seq}, audit_hash=${last.hash} WHERE singleton=1 AND revision=${plan.snapshot.revision}`;
    const statements = plan.mutations.flatMap(m => mutationStatements(m, this.driver.engine));
    for (const e of plan.events) {
      statements.push(sql`INSERT INTO coffre_audit(seq,id,actor_id,project_id,env_id,record) VALUES (${e.seq},${e.id},${e.actorId},${e.projectId},${e.envId},${canonical(e)})`);
      statements.push(sql`INSERT INTO coffre_outbox(seq,event_hash,record) VALUES (${e.seq},${e.hash},${canonical(e)})`);
    }
    if (plan.receipt) statements.push(sql`INSERT INTO coffre_receipts(request_id,record) VALUES (${plan.receipt.requestId},${canonical(plan.receipt)})`);
    await this.driver.atomic(cas, statements);
  }
  async pendingArchive(limit: number) { return decode<AuditEvent>(await this.driver.query(sql`SELECT record FROM coffre_outbox ORDER BY seq LIMIT ${limit}`)); }
  async acknowledgeArchive(event: AuditEvent) { await this.driver.query(sql`DELETE FROM coffre_outbox WHERE seq=${event.seq} AND event_hash=${event.hash}`); }
  close() { return this.driver.close(); }
}
export function d1Storage(db: D1Database): Storage {
  const dialect = new SQLiteSyncDialect();
  const prepare = (q: SQL) => { const { sql: text, params } = dialect.sqlToQuery(q); return db.prepare(text).bind(...params); };
  return new SqlStorage({
    engine: 'd1',
    async snapshot(qs) { return (await db.batch(qs.map(prepare))).map(r => r.results as Row[]); },
    async query(q) { return (await prepare(q).all()).results as Row[]; },
    async atomic(cas, statements) {
      const guardId = crypto.randomUUID();
      try {
        await db.batch([prepare(cas), prepare(sql`INSERT INTO coffre_guard(id,ok) VALUES (${guardId},changes())`), ...statements.map(prepare), prepare(sql`DELETE FROM coffre_guard WHERE id=${guardId}`)]);
      } catch (error) {
        if (String(error).includes('coffre_cas')) throw new RetryConflict('Concurrent transaction');
        throw error;
      }
    },
    async close() {},
  });
}
export interface SqlConnection { url: string; hyperdrive?: boolean; local?: boolean; ca?: string }
function connectionOptions(config: SqlConnection) {
  const u = new URL(config.url);
  if (!['postgres:', 'postgresql:', 'mysql:'].includes(u.protocol) || !u.hostname || u.search || u.hash) throw new Error('Database URL must not contain query options; configure verified TLS separately');
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
  if (config.local && !local) throw new Error('Plaintext database connections are allowed only on loopback');
  return { host: u.hostname, port: Number(u.port || (u.protocol === 'mysql:' ? 3306 : 5432)), user: decodeURIComponent(u.username), password: decodeURIComponent(u.password), database: decodeURIComponent(u.pathname.slice(1)), ...(config.hyperdrive || config.local ? {} : { ssl: { rejectUnauthorized: true, ...(config.ca ? { ca: config.ca } : {}) } }) };
}
export function postgresStorage(config: SqlConnection): Storage {
  const options = connectionOptions(config);
  const client = new Client({ ...options, connectionTimeoutMillis: 10000, statement_timeout: 15000 });
  let connected = false;
  const dialect = new PgDialect();
  const query = async (q: SQL): Promise<Row[]> => {
    if (!connected) { await client.connect(); connected = true; }
    const compiled = dialect.sqlToQuery(q);
    return (await client.query(compiled.sql, compiled.params)).rows as Row[];
  };
  return new SqlStorage({
    engine: 'postgres', query,
    async snapshot(queries) {
      await query(sql`BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`);
      try { const result: Row[][] = []; for (const q of queries) result.push(await query(q)); await query(sql`COMMIT`); return result; }
      catch (error) { await query(sql`ROLLBACK`); throw error; }
    },
    async atomic(cas, statements) {
      await query(sql`BEGIN`);
      try {
        if (!(await query(sql`${cas} RETURNING revision`)).length) throw new RetryConflict('Concurrent transaction');
        for (const q of statements) await query(q);
        await query(sql`COMMIT`);
      } catch (error) { await query(sql`ROLLBACK`); throw error; }
    },
    async close() { if (connected) await client.end(); },
  });
}
export function mysqlStorage(config: SqlConnection): Storage {
  let connection: Connection | undefined;
  const options = connectionOptions(config);
  const dialect = new MySqlDialect();
  const execute = async (q: SQL) => {
    connection ??= await createConnection({ ...options, connectTimeout: 10000, multipleStatements: false });
    const compiled = dialect.sqlToQuery(q);
    // MySQL does not support every transaction-control command in its prepared
    // statement protocol. Parameter-free SQL here is authored by the adapter;
    // user values always remain bound parameters in execute(), never interpolated.
    return compiled.params.length === 0
      ? (await connection.query(compiled.sql))[0]
      : (await connection.execute(compiled.sql, compiled.params as (string | number | boolean | null)[]))[0];
  };
  const query = async (q: SQL): Promise<Row[]> => { const result = await execute(q); return Array.isArray(result) ? result as Row[] : []; };
  return new SqlStorage({
    engine: 'mysql', query,
    async snapshot(queries) {
      await query(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`); await query(sql`START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY`);
      try { const result: Row[][] = []; for (const q of queries) result.push(await query(q)); await query(sql`COMMIT`); return result; }
      catch (error) { await query(sql`ROLLBACK`); throw error; }
    },
    async atomic(cas, statements) {
      await query(sql`START TRANSACTION`);
      try {
        if ((await execute(cas) as ResultSetHeader).affectedRows !== 1) throw new RetryConflict('Concurrent transaction');
        for (const q of statements) await query(q);
        await query(sql`COMMIT`);
      } catch (error) { await query(sql`ROLLBACK`); throw error; }
    },
    async close() { if (connection) await connection.end(); },
  });
}
