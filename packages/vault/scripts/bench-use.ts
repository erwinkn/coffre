// 0.15's use, benchmarked at the database (docs/design/hot-path-one.md, "The use
// path on main"): `use_credential` called as the hot path's login at a fixed
// rate, each form on its own, on an instance of realistic size with a log of
// `--history` entries. It prints Postgres's CPU per use, from the container's
// cgroup, and its buffers per use, from pg_stat_statements. It runs on
// coffre's own driver (postgres.js, @coffre/db's copy): unnamed statements, as
// the vault sends them. (Named statements, measured on node-postgres by W219,
// are not what coffre sends: hot-path-one.md, "The cuts".)
//
//   node --conditions=coffre:source packages/vault/scripts/bench-use.ts --owner <url> --hot <url> --container <name> \
//     [--seed] [--history 10000] [--form probing|cached|reference|mixed] [--rate 1000] [--seconds 20] [--pool 40]
//
// The rig: Postgres 16 in Docker held to 2 vCPU and 2 GB, with pg_stat_statements
// (track=all). `--seed` makes the instance and its genesis changes, sealed as the
// change path seals them (nothing decides here: the statement's cost does not
// depend on what the Worker then decides).
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';

import { postgresClient, type PostgresClient } from '@coffre/db/connect';

import { objectKey, sealKey, sealOf, type Input, type Ref } from '../src/inputs.ts';
import { rowOf } from '../src/use.postgres.ts';

const { values: args } = parseArgs({
  options: {
    owner: { type: 'string' }, hot: { type: 'string' }, container: { type: 'string' },
    seed: { type: 'boolean', default: false }, history: { type: 'string', default: '0' },
    form: { type: 'string', default: 'mixed' }, rate: { type: 'string', default: '1000' }, seconds: { type: 'string', default: '20' },
    pool: { type: 'string', default: '40' }, pairs: { type: 'string', default: '1000' }, json: { type: 'boolean', default: false }, parse: { type: 'boolean', default: false },
    probing: { type: 'string', default: '0.27' }, function: { type: 'string', default: 'use_credential' },
  },
});
const owner = postgresClient(args.owner!, { max: 4 });
const SEAL = sealKey(Buffer.alloc(32, 9));
const PROJECTS = 100;
const MEMBERS = 1000;
const KEYS_PER_ENVIRONMENT = 10;

const q = async <T = Record<string, unknown>>(text: string, values: unknown[] = []) => [...await owner.unsafe(text, values as never[])] as T[];

/** A transaction's statements, as `seed` sends them. */
type Tx = { unsafe: (text: string, values?: unknown[]) => Promise<Record<string, unknown>[]> };

async function change(ref: Ref, object: Input, client: Tx): Promise<Buffer> {
  const seal = sealOf(SEAL, ref, object);
  await client.unsafe(`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac) VALUES (nextval('log_number'), $1, $2, $3, 'system:bench', $4, $5, $6)`,
    [Date.now(), randomUUID(), objectKey(ref), JSON.stringify({ op: 'genesis', value: object, ...(object.kind === 'principal' ? { old: '0' } : {}) }), seal, randomBytes(16)]);
  return seal;
}

/** The instance: 100 projects of three environments (dev, prod, a personal config of dev), 10 keys in each, 1,000 members each with a credential and grants on one project, references and their sources. */
async function seed(): Promise<void> {
  await owner.begin(async (tx) => {
    const client = tx as unknown as Tx;
    const now = Date.now();
    await client.unsafe(`INSERT INTO log_config (name, value, seal) VALUES ('policy', $1, $2), ('roles', $3, $4)`, [
      JSON.stringify({ kind: 'policy', bulk: { count: 1000, windowMs: 900_000 } }), sealOf(SEAL, { kind: 'policy', id: 'instance' }, { kind: 'policy', bulk: { count: 1000, windowMs: 900_000 } }),
      JSON.stringify({ kind: 'roles', roles: {}, instanceRoles: {} }), sealOf(SEAL, { kind: 'roles', id: 'instance' }, { kind: 'roles', roles: {}, instanceRoles: {} }),
    ]);
    await change({ kind: 'policy', id: 'instance' }, { kind: 'policy', bulk: { count: 1000, windowMs: 900_000 } }, client);
    await change({ kind: 'roles', id: 'instance' }, { kind: 'roles', roles: {}, instanceRoles: {} }, client);
    const projects: { id: string; dev: string; prod: string; mine: string; owner: string }[] = [];
    for (let p = 0; p < PROJECTS; p += 1) {
      const id = randomUUID();
      const [dev, prod, mine] = [randomUUID(), randomUUID(), randomUUID()];
      const person = `user:p${p}@acme.example`;
      await client.unsafe(`INSERT INTO projects (id, slug, name) VALUES ($1, $2, 'P')`, [id, `p-${p}`]);
      await client.unsafe(`INSERT INTO environments (id, project_id, slug, name, protected) VALUES ($1, $3, 'dev', 'D', false), ($2, $3, 'prod', 'P', false)`, [dev, prod, id]);
      await client.unsafe(`INSERT INTO vault_members (principal, status, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac) VALUES ($1, 'active', 0, $2, 'system:bench', $2, 'system:bench', 0, $3)`,
        [person, now, Buffer.alloc(32)]);
      await client.unsafe(`INSERT INTO environments (id, project_id, slug, name, protected, parent_id, owner) VALUES ($1, $2, 'dev-mine', 'Mine', false, $3, $4)`, [mine, id, dev, person]);
      for (const [env, slug, parent, own] of [[dev, 'dev', null, null], [prod, 'prod', null, null], [mine, 'dev-mine', dev, person]] as const) {
        const object: Input = { kind: 'environment', id: env, projectId: id, slug, owner: own, parentId: parent, protected: false, deleted: false, archived: false };
        await client.unsafe('UPDATE environments SET seal = $1 WHERE id = $2', [await change({ kind: 'environment', id: env }, object, client), env]);
      }
      projects.push({ id, dev, prod, mine, owner: person });
    }
    const keys: { id: string; project: string; env: string }[] = [];
    for (const project of projects) {
      for (const env of [project.dev, project.prod, project.mine]) {
        for (let k = 0; k < KEYS_PER_ENVIRONMENT; k += 1) {
          const id = randomUUID();
          const version = randomUUID();
          await client.unsafe(`INSERT INTO secrets (id, project_id, environment_id, key) VALUES ($1, $2, $3, $4)`, [id, project.id, env, `K_${k}_${id.slice(0, 6)}`]);
          await client.unsafe(`INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, sensitive)
            VALUES ($1, $2, 1, 1, $3, $4, $5, $6, 'local', 'bench', '1', 'system:bench', false)`, [version, id, randomBytes(48), randomBytes(12), randomBytes(16), randomBytes(60)]);
          await client.unsafe('UPDATE secrets SET current_version_id = $1, current_version = 1 WHERE id = $2', [version, id]);
          keys.push({ id, project: project.id, env });
        }
      }
    }
    // References: each prod holds five keys that are references to the personal config's (the worst case: a source in a personal config, whose parent is weighed too).
    for (const project of projects) {
      const sources = keys.filter((key) => key.env === project.mine).slice(0, 5);
      for (const source of sources) {
        const holder = randomUUID();
        const [{ seq }] = (await client.unsafe(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
          VALUES ((SELECT coalesce(max(seq), 0) + 1 FROM audit_log), 'vault', 'vault:bench', $1, 'system:bench', 'reference.create', 'allow', '{}', $2, $2, $2) RETURNING seq`, [now, Buffer.alloc(32)])) as { seq: string }[];
        await client.unsafe(`INSERT INTO secrets (id, project_id, environment_id, key) VALUES ($1, $2, $3, $4)`, [holder, project.id, project.prod, `REF_${holder.slice(0, 6)}`]);
        await client.unsafe(`INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by)
          VALUES ($1, $2, $3, $4, $2, $5, $6, $7, 'system:bench')`, [randomUUID(), project.id, project.prod, holder, project.mine, source.id, seq]);
        keys.push({ id: holder, project: project.id, env: `ref:${project.prod}` });
      }
    }
    for (const key of keys) {
      const [row] = (await client.unsafe(`SELECT s.project_id, s.environment_id, s.current_version_id, v.wrapped_dek,
          (SELECT y.source_secret_id FROM secret_references y WHERE y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1) AS source
        FROM secrets s LEFT JOIN secret_versions v ON v.id = s.current_version_id WHERE s.id = $1`, [key.id])) as { project_id: string; environment_id: string; current_version_id: string | null; wrapped_dek: Buffer | null; source: string | null }[];
      const object: Input = row!.current_version_id === null
        ? { kind: 'secret', id: key.id, projectId: row!.project_id, environmentId: row!.environment_id, version: '', nature: 'secret', key: null, source: row!.source }
        : { kind: 'secret', id: key.id, projectId: row!.project_id, environmentId: row!.environment_id, version: row!.current_version_id, nature: 'secret',
          key: { kekProvider: 'local', kekId: 'bench', kekVersion: '1', bytes: row!.wrapped_dek!.toString('base64') }, source: null };
      await client.unsafe('UPDATE secrets SET seal = $1 WHERE id = $2', [await change({ kind: 'secret', id: key.id }, object, client), key.id]);
    }
    for (let m = 0; m < MEMBERS; m += 1) {
      const principal = `token:bench-${m}`;
      const project = projects[m % PROJECTS]!;
      const credential = randomUUID();
      await client.unsafe(`INSERT INTO vault_members (principal, status, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac) VALUES ($1, 'active', 0, $2, 'system:bench', $2, 'system:bench', 0, $3)`,
        [principal, now, Buffer.alloc(32)]);
      const grants = [project.dev, project.prod].map((env) => ({ projectId: project.id, environmentId: env, environmentSlug: null, role: 'viewer', expiresAt: null }));
      for (const grant of grants) {
        await client.unsafe(`INSERT INTO vault_grants (principal, environment_id, role, granted_at, granted_by) VALUES ($1, $2, 'viewer', $3, 'system:bench')`, [principal, grant.environmentId, now]);
      }
      const member: Input = { kind: 'principal', principal, status: 'active', role: 'member', scope: { projects: 'all', environments: 'all' }, grants };
      await client.unsafe('UPDATE vault_members SET seal = $1 WHERE principal = $2', [await change({ kind: 'principal', id: principal }, member, client), principal]);
      const expiresAt = now + 30 * 86_400_000;
      await client.unsafe(`INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at) VALUES ($1, 'service', $2, $3, 'h', 0, $4, 'system:bench', $5)`,
        [credential, Buffer.alloc(32), randomBytes(32), principal, new Date(expiresAt)]);
      const object: Input = { kind: 'credential', id: credential, principal, caller: 'bearer', scope: null, expiresAt, revoked: false };
      await client.unsafe('UPDATE credentials SET seal = $1 WHERE id = $2', [await change({ kind: 'credential', id: credential }, object, client), credential]);
    }
    // 0.14's log about the members: an access entry each, as a cutover finds them.
    await client.unsafe(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash)
      SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:bench', $1, 'system:bench', 'access.grant', 'deny', 'token:bench-' || (g - 1), '{}', $2, $2, $2
        FROM generate_series(1, ${MEMBERS}) g`, [now, Buffer.alloc(32)]);
    const today = new Date().toISOString().slice(0, 10);
    for (let d = -2; d <= 2; d += 1) await client.unsafe(`SELECT make_day($1::date + $2::integer)`, [today, d]);
    await client.unsafe('UPDATE log_fence SET at_floor = $1', [now - 86_400_000 * 2]);
  });
}

/** History that is not the bench's uses: as use-cost.test.ts grows it. */
async function grow(total: number): Promise<void> {
  const have = Number((await q<{ n: string }>('SELECT count(*) AS n FROM log_uses'))[0]!.n);
  const more = total - have;
  if (more <= 0) return;
  const now = Date.now();
  for (let done = 0; done < more; done += 200_000) {
    const n = Math.min(200_000, more - done);
    await q(`INSERT INTO log_uses (number, at, request_id, credential, secret, purpose, mac, place)
      SELECT nextval('log_number'), $1::bigint - (g * 86000000::bigint / $2), g + $3, gen_random_uuid(), gen_random_uuid(), 1, $4, NULL FROM generate_series(1, $2) g`, [now, n, done + have, randomBytes(16)]);
  }
  await q(`INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
    SELECT nextval('log_number'), $1, 'history-' || g || '-' || $3, gen_random_uuid(), 'system:x', '{"op":"x"}', NULL, $4 FROM generate_series(1, $2) g`, [now, Math.round(more / 100), String(total), randomBytes(16)]);
  await q(`INSERT INTO log_bulk (principal, secret, last) SELECT 'token:other-' || (g % 1000), gen_random_uuid(), $1 FROM generate_series(1, $2) g ON CONFLICT DO NOTHING`, [now, Math.round(more / 10)]);
  await q(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash)
    SELECT (SELECT coalesce(max(seq), 0) FROM audit_log) + g, 'vault', 'vault:x', $1, 'system:x', 'secret.read', 'allow', NULL, '{}', $3, $3, $3 FROM generate_series(1, $2) g`,
  [now, Math.round(more / 10), Buffer.alloc(32)]);
  await q('VACUUM ANALYZE');
}

type Pair = { credential: string; secret: string; place: string | null };

/** What each form asks for: a member's own key (probing or cached), or a reference read through a fork (probing, every input). */
async function pairs(form: string): Promise<Pair[]> {
  const rows = await q<{ credential: string; secret: string; place: string | null }>(form === 'reference'
    ? `SELECT c.id AS credential, s.id AS secret, (SELECT e.id FROM environments e WHERE e.project_id = s.project_id AND e.slug = 'dev' AND e.owner IS NULL) AS place
         FROM credentials c JOIN vault_grants g ON g.principal = c.principal JOIN environments e ON e.id = g.environment_id AND e.slug = 'prod'
         JOIN secrets s ON s.environment_id = e.id AND s.current_version_id IS NULL`
    : `SELECT c.id AS credential, s.id AS secret, NULL AS place FROM credentials c JOIN vault_grants g ON g.principal = c.principal
         JOIN secrets s ON s.environment_id = g.environment_id AND s.current_version_id IS NOT NULL`);
  return rows;
}

function cgroupUsec(container: string): number {
  const stat = execFileSync('docker', ['exec', container, 'cat', '/sys/fs/cgroup/cpu.stat'], { encoding: 'utf8' });
  return Number(/usage_usec (\d+)/.exec(stat)![1]);
}

async function run(): Promise<void> {
  const rate = Number(args.rate);
  const seconds = Number(args.seconds);
  const form = args.form!;
  // A steady state: a bounded set of (credential, key), each key's bulk row fresh, as hot keys' are (a row moves once a minute).
  const asked = (await pairs(form)).sort(() => Math.random() - 0.5).slice(0, Number(args.pairs));
  const hot = postgresClient(args.hot!, { max: Number(args.pool) });
  const [newest] = await q<{ number: string; mac: Buffer }>('SELECT number, mac FROM log_changes ORDER BY number DESC LIMIT 1');
  const probingShare = form === 'probing' || form === 'reference' ? 1 : form === 'cached' ? 0 : Number(args.probing);
  const legacy = args.function === 'use_credential_0022';
  // Every column, as a typed row; or the JSON as the vault reads it, one text column (use.postgres.ts).
  const text = legacy
    ? `SELECT * FROM use_credential_0022($1, $2, $3, $4, 4::smallint, $5, $6, $7, NULL, NULL, NULL, $8, $9)`
    : args.json
      ? `SELECT ${args.function}($1, $2, $3, $4, 4::smallint, $5, $6, $7, NULL, NULL, NULL, $8, $9, $10, $11)::text AS r`
      : `SELECT * FROM ${args.function}($1, $2, $3, $4, 4::smallint, $5, $6, $7, NULL, NULL, NULL, $8, $9, $10, $11)`;
  const call = async (pair: Pair, cached: boolean): Promise<{ rows: Record<string, unknown>[] }> => {
    const at = Date.now();
    const values = [
      pair.credential, pair.secret, (randomBytes(8).readBigUInt64BE() >> 1n).toString(), String(at), pair.place, randomBytes(16), String(at + 3000),
      cached ? newest!.number : null, cached ? newest!.mac : null, cached ? 1000 : null, cached ? '900000' : null,
    ].slice(0, legacy ? 9 : 11);
    const rows = [...await hot.unsafe(text, values as never[])] as Record<string, unknown>[];
    return { rows: args.json ? [rowOf(rows[0]!.r as string) as unknown as Record<string, unknown>] : rows };
  };
  // Every connection's plans made, and every key's bulk row written, before the measured run.
  await Promise.all(Array.from({ length: Number(args.pool) * 2 }, (_, i) => call(asked[i % asked.length]!, false)));
  for (let i = 0; i < asked.length; i += 20) await Promise.all(asked.slice(i, i + 20).map((pair) => call(pair, false)));
  await q('SELECT pg_stat_statements_reset()');
  const before = cgroupUsec(args.container!);
  const client = process.cpuUsage();
  const since = new Date();
  const started = Date.now();
  let sent = 0;
  let done = 0;
  let failed = 0;
  const latencies: number[] = [];
  const inflight = new Set<Promise<void>>();
  while (Date.now() - started < seconds * 1000) {
    const due = Math.floor(((Date.now() - started) / 1000) * rate);
    for (; sent < due; sent += 1) {
      const t0 = performance.now();
      const p = call(asked[Math.floor(Math.random() * asked.length)]!, Math.random() >= probingShare).then(
        (result) => { if (result.rows[0]?.state !== null) failed += 1; done += 1; latencies.push(performance.now() - t0); },
        () => { failed += 1; },
      ).finally(() => inflight.delete(p));
      inflight.add(p);
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  await Promise.all(inflight);
  const elapsed = (Date.now() - started) / 1000;
  const usec = cgroupUsec(args.container!) - before;
  const spent = process.cpuUsage(client);
  // How many backends served the run: each the pool picked, its state changed by a call since the start.
  const [backends] = await q<{ n: string }>(`SELECT count(*) AS n FROM pg_stat_activity WHERE usename = 'coffre_vault_hot' AND state_change >= $1`, [since]);
  const [stats] = await q<{ calls: string; blocks: string; ms: string }>(`SELECT sum(calls) AS calls, sum(shared_blks_hit + shared_blks_read) AS blocks, sum(total_exec_time) AS ms
    FROM pg_stat_statements WHERE query LIKE 'SELECT % ${args.function}(%' OR query LIKE 'SELECT ${args.function}(%'`);
  latencies.sort((a, b) => a - b);
  const pct = (p: number) => latencies[Math.floor((latencies.length - 1) * p)]?.toFixed(2);
  const history = Number((await q<{ n: string }>('SELECT count(*) AS n FROM log_uses'))[0]!.n);
  console.log(JSON.stringify({
    form, function: args.function, driver: 'postgres.js', json: args.json, history, rate, served: Math.round(done / elapsed), failed,
    backends: Number(backends!.n), cpuMsPerUse: Number((usec / 1000 / done).toFixed(3)), clientMsPerUse: Number(((spent.user + spent.system) / 1000 / done).toFixed(3)), buffersPerUse: Number((Number(stats!.blocks) / Number(stats!.calls)).toFixed(1)),
    serverMsPerUse: Number((Number(stats!.ms) / Number(stats!.calls)).toFixed(3)), p50: pct(0.5), p99: pct(0.99),
  }));
  await hot.end();
}

/**
 * The Worker's side of the answer: one probing use's JSON text, parsed as it
 * is parsed (one JSON.parse, each whole number kept exact) and as the vault
 * reads it (`rowOf`).
 */
async function parse(): Promise<void> {
  const [pair] = await pairs('probing');
  const raw: PostgresClient = postgresClient(args.hot!, { max: 1 });
  const at = Date.now();
  const values = [pair!.credential, pair!.secret, (randomBytes(8).readBigUInt64BE() >> 1n).toString(), String(at), null, randomBytes(16), String(at + 3000)];
  const [json] = await raw.unsafe(`SELECT use_credential_final($1, $2, $3::bigint + 1, $4, 4::smallint, $5, $6, $7)::text AS r`, values as never[]);
  await raw.end();
  const text = json!.r as string;
  const time = (work: () => void) => {
    for (let i = 0; i < 5000; i += 1) work();
    const t0 = process.cpuUsage();
    for (let i = 0; i < 50_000; i += 1) work();
    const spent = process.cpuUsage(t0);
    return Number(((spent.user + spent.system) / 50_000).toFixed(2));
  };
  const reviverUs = time(() => JSON.parse(text, (_key, value: unknown, context?: { source?: string }) => (typeof value === 'number' && !Number.isSafeInteger(value) && context?.source !== undefined ? context.source : value)));
  const plainUs = time(() => JSON.parse(text));
  // What the vault does: a plain parse, its bigints as text, its bytes from hex (rowOf).
  const rowOfUs = time(() => rowOf(text));
  console.log(JSON.stringify({ jsonBytes: text.length, jsonReviverUs: reviverUs, jsonPlainUs: plainUs, rowOfUs }));
}

if (args.parse) {
  await parse();
  await owner.end();
  process.exit(0);
}
if (args.seed) await seed();
await grow(Number(args.history));
await run();
await owner.end();
