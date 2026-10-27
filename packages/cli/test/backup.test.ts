import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveLogKey, GENESIS_HASH, sealEntry, type LogFields, type LogKey } from '@coffre/core/audit';
import { encrypt, ownerKey, type SecretContext } from '@coffre/core/envelope';
import { derivedSigningKey, LocalKekProvider } from '@coffre/core/kek';
import { postgresClient, type PostgresClient } from '@coffre/db/connect';

import { manifestPath, type Manifest } from '../src/backup.ts';
import { urlSecrets } from '../src/database-url.ts';
import { rowsVerdict } from '../src/restore.ts';
import { Failure } from '../src/verify/checks.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const port = process.env.COFFRE_POSTGRES_PORT ?? '55432';
const clone = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const url = (login: string, database: string) => `postgresql://${login}@127.0.0.1:${port}/${database}`;
const owner = (database: string) => url('coffre_owner:local-dev-only', database);
const backupLogin = (database: string) => url('coffre_backup_login:local-backup-only', database);

// PostgreSQL's own tools, which the commands run: of the server's major version, as a deployment's pipeline has them.
const tools = spawnSync('pg_restore', ['--version'], { encoding: 'utf8' });
const postgres = {
  skip: process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only: coffre backup runs pg_dump' : tools.status !== 0 ? 'needs pg_dump and pg_restore on PATH' : false,
};

// --- without a database --------------------------------------------------------------

test('a dump names its manifest beside it', () => {
  assert.equal(manifestPath('backups/coffre-20261026T0800Z.dump'), 'backups/coffre-20261026T0800Z.manifest.json');
  assert.equal(manifestPath('nightly'), 'nightly.manifest.json');
});

test("a connection string's password is a secret wherever it is, the query included", () => {
  const text = 'postgresql://coffre_backup_login:p%40ss@db.example/coffre?sslmode=require&password=other&sslpassword=key-pass';
  assert.deepEqual(urlSecrets(text, new URL(text)), [text, 'p%40ss', 'p@ss', 'other', 'key-pass']);
  const bare = 'postgresql://coffre_backup_login@db.example/coffre';
  assert.deepEqual(urlSecrets(bare, new URL(bare)), [bare]);
});

test('rows hold when every table has the rows backed up, and each difference is named', () => {
  const tables = { 'public.projects': { rows: 2, digest: '7' }, 'public.secrets': { rows: 5, digest: '9' } };
  assert.equal(rowsVerdict({ tables }, { tables }), "every table's, as backed up: 7 rows in 2 tables");
  assert.throws(
    () => rowsVerdict({ tables }, { tables: { 'public.projects': { rows: 2, digest: '8' }, 'public.extra': { rows: 0, digest: '0' } } }),
    (error: unknown) =>
      error instanceof Failure &&
      error.message === "3 tables differ: public.extra, which the backup does not hold; public.projects's 2 rows are not those backed up; public.secrets is missing",
  );
  assert.throws(() => rowsVerdict({ tables }, { tables: { ...tables, 'public.secrets': { rows: 4, digest: '9' } } }), /one table differs: public.secrets has 4 rows, and the backup 5/);
});

// --- against Postgres -----------------------------------------------------------------

/** Each author's key now, and the one it replaced: the vault's vault keys under their own IDs. */
const kek = randomBytes(32);
const earlierKek = randomBytes(32);
const appKey = randomBytes(32);
const earlierAppKey = randomBytes(32);
const signingKey = randomBytes(32);
const keys = {
  app: deriveLogKey('app', appKey),
  earlierApp: deriveLogKey('app', earlierAppKey),
  vault: deriveLogKey('vault', derivedSigningKey(kek)),
  earlierVault: deriveLogKey('vault', derivedSigningKey(earlierKek)),
  // A vault given a signing key of its own signs with it, whatever its vault key.
  ownSigning: deriveLogKey('vault', signingKey),
};
const work = mkdtempSync(join(tmpdir(), 'coffre-backup-test-'));
const made: string[] = [];

async function asOwner<T>(database: string, run: (client: PostgresClient) => Promise<T>): Promise<T> {
  const client = postgresClient(owner(database), { max: 1 });
  try {
    return await run(client);
  } finally {
    await client.end();
  }
}

/** A new database: empty, or a copy of this file's migrated clone. */
async function database(kind: 'empty' | 'migrated'): Promise<string> {
  const name = `${clone}_${randomBytes(4).toString('hex')}`;
  await asOwner('postgres', (client) => client.unsafe(`CREATE DATABASE ${name}${kind === 'migrated' ? ` TEMPLATE ${clone}` : ''}`));
  made.push(name);
  return name;
}

/** An entry of the log a test writes: under whose key, and, for a key rotation, the key it moves on from. */
type Written = { key: LogKey; moves?: LogKey };

/**
 * A log as a rotation leaves it: the app and the vault began under earlier
 * keys; the app's `key.rotate` names the one it moves on from, and the
 * vault moved forward to its new vault key.
 */
const ROTATED: Written[] = [
  { key: keys.earlierApp },
  { key: keys.earlierVault },
  { key: keys.earlierApp },
  { key: keys.app, moves: keys.earlierApp },
  { key: keys.vault },
  { key: keys.app },
  { key: keys.vault },
  { key: keys.app },
];

type Seeded = { versions: number; entries: number };

/**
 * An instance's rows as the app and the vault write them: a project with an
 * environment and a personal config, values plain, secret, sensitive and
 * personal, sealed under the vault key, and one older, under the vault key
 * it replaced; and `log`. `edit` changes an entry after it is sealed, as a
 * forger would.
 */
async function seed(name: string, { log = ROTATED, edit }: { log?: Written[]; edit?: { seq: bigint; action: string } } = {}): Promise<Seeded> {
  return asOwner(name, async (client) => {
    const project = randomUUID();
    const environment = randomUUID();
    const personal = randomUUID();
    await client.unsafe("INSERT INTO projects (id, slug, name) VALUES ($1, 'market', 'Market')", [project]);
    await client.unsafe("INSERT INTO environments (id, project_id, slug, name) VALUES ($1, $2, 'prod', 'Prod')", [environment, project]);
    await client.unsafe("INSERT INTO environments (id, project_id, slug, name, parent_id, owner) VALUES ($1, $2, 'prod~ada', 'Prod', $3, 'user:ada@acme.example')", [personal, project, environment]);
    const current = new LocalKekProvider(kek, 'test-vault');
    const earlier = new LocalKekProvider(earlierKek, 'old-vault');
    const values: { key: string; environment: string; value: string; plain?: boolean; sensitive?: boolean; owner?: string; under?: LocalKekProvider }[] = [
      { key: 'API_URL', environment, value: 'https://api.acme.example', plain: true },
      { key: 'DATABASE_URL', environment, value: 'postgresql://app:hunter2@db/app' },
      { key: 'STRIPE_KEY', environment, value: 'sk_live_123', sensitive: true },
      { key: 'DATABASE_URL', environment: personal, value: 'postgresql://ada@localhost/app', owner: 'user:ada@acme.example' },
      { key: 'OLD_TOKEN', environment, value: 'wrapped before the rotation', under: earlier },
    ];
    for (const value of values) {
      const secret = randomUUID();
      await client.unsafe('INSERT INTO secrets (id, project_id, environment_id, key) VALUES ($1, $2, $3, $4)', [secret, project, value.environment, value.key]);
      const ids = { projectId: project, environmentId: value.environment, secretId: secret };
      const context: SecretContext = { ...ids, ...(value.owner === undefined ? {} : { owner: ownerKey(value.owner) }), ...(value.sensitive ? { sensitive: true as const } : {}) };
      const dek = randomBytes(32);
      const sealed = encrypt(Buffer.from(value.value), ids, dek);
      const wrapped = await (value.under ?? current).wrap(dek, context);
      await client.unsafe(
        `INSERT INTO secret_versions (secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, plaintext, sensitive)
         VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9, 'user:admin@acme.example', $10, $11)`,
        [secret, sealed.envelopeVersion, sealed.ciphertext, sealed.iv, sealed.authTag, wrapped.bytes, wrapped.kekProvider, wrapped.kekId, wrapped.kekVersion, value.plain ? value.value : null, value.sensitive === true],
      );
    }
    // A version deleted for good: its row stays, its value gone (`eraseVersions` in @coffre/server).
    const erased = randomUUID();
    await client.unsafe("INSERT INTO secrets (id, project_id, environment_id, key) VALUES ($1, $2, $3, 'GONE')", [erased, project, environment]);
    await client.unsafe(
      `INSERT INTO secret_versions (secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by)
       VALUES ($1, 1, 1, '', $2, $3, '', 'local', 'test-vault', '1', 'user:admin@acme.example')`,
      [erased, Buffer.alloc(12), Buffer.alloc(16)],
    );
    let prev = GENESIS_HASH;
    for (const [i, written] of log.entries()) {
      const fields = entry(BigInt(i), written);
      const { mac, hash } = sealEntry(written.key, prev, fields);
      if (edit?.seq === fields.seq) fields.action = edit.action;
      await client.unsafe(
        `INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [fields.seq.toString(), fields.author, fields.keyId, fields.occurredAt, fields.actor, fields.action, fields.decision, fields.subjectPrincipal, fields.metadata, prev, mac, hash],
      );
      prev = hash;
    }
    await client.unsafe('UPDATE audit_chain_head SET next_seq = $1, head_hash = $2', [log.length, prev]);
    return { versions: values.length + 1, entries: log.length };
  });
}

function entry(seq: bigint, { key, moves }: Written): LogFields {
  return {
    seq, author: key.author, keyId: key.keyId, occurredAt: 1_790_000_000_000 + Number(seq), actor: 'system:test',
    action: moves === undefined ? 'test.entry' : 'key.rotate', decision: 'allow', code: null, subjectPrincipal: moves?.keyId ?? null,
    projectId: null, environmentId: null, secretId: null, secretVersionId: null, operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: '{}',
  };
}

/** The CLI, with `stdin` piped in: no terminal, as in a pipeline. */
function coffre(args: string[], stdin: string): Promise<{ code: number | null; stderr: string; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...args], { cwd: work, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}

/** stdin for --keys: the connection string, then each author's keys, the current first, on a line of their own. */
const withKeys = (database: string, vault: Buffer[], app: Buffer[]) =>
  `${owner(database)}\n${vault.map((key) => key.toString('base64')).join(' ')}\n${app.map((key) => key.toString('base64')).join(' ')}\n`;

/** A database seeded with `log` and backed up: the dump. */
async function backedUp(file: string, options: Parameters<typeof seed>[1]): Promise<string> {
  const name = await database('migrated');
  await seed(name, options);
  const dump = join(work, file);
  const { code, stderr } = await coffre(['backup', dump], backupLogin(name));
  assert.equal(code, 0, stderr);
  return dump;
}

/** One seeded instance, backed up once, which the cases below restore. */
let source: string;
let seeded: Seeded;
const dump = join(work, 'coffre.dump');

before(async () => {
  if (postgres.skip) return;
  source = await database('migrated');
  seeded = await seed(source);
  const { code, stderr } = await coffre(['backup', dump], backupLogin(source));
  assert.equal(code, 0, stderr);
});

after(async () => {
  rmSync(work, { recursive: true, force: true });
  if (postgres.skip) return;
  await asOwner('postgres', async (client) => {
    for (const name of made) await client.unsafe(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  });
});

test('backup dumps as the backup login, and its manifest says what the snapshot held', postgres, async () => {
  const manifest = JSON.parse(readFileSync(manifestPath(dump), 'utf8')) as Manifest;
  assert.equal(manifest.format, 'coffre.backup.v1');
  assert.equal(manifest.login, 'coffre_backup_login');
  assert.equal(manifest.database, `127.0.0.1/${source}`);
  assert.equal(manifest.dump.bytes, statSync(dump).size);
  assert.equal(statSync(dump).mode & 0o777, 0o600);
  assert.equal(statSync(manifestPath(dump)).mode & 0o777, 0o600);
  assert.equal(manifest.tables['public.audit_log']!.rows, seeded.entries);
  assert.equal(manifest.tables['public.secret_versions']!.rows, seeded.versions);
  assert.equal(manifest.log!.nextSeq, String(seeded.entries));
  assert.ok(manifest.migrations.applied > 0 && manifest.migrations.last !== null);

  const again = await coffre(['backup', dump], backupLogin(source));
  assert.equal(again.code, 1);
  assert.match(again.stderr, /coffre\.dump already exists: coffre backup writes only a new file/);
});

test('backup refuses a login whose row-level security hides the log, and leaves no file', postgres, async () => {
  const reader = `coffre_test_reader_${randomBytes(4).toString('hex')}`;
  await asOwner('postgres', (client) => client.unsafe(`CREATE ROLE ${reader} LOGIN PASSWORD 'reader-only' IN ROLE pg_read_all_data`));
  try {
    const file = join(work, 'reader.dump');
    const { code, stderr } = await coffre(['backup', file], url(`${reader}:reader-only`, source));
    assert.equal(code, 1);
    assert.match(stderr, new RegExp(`row-level security hides rows of public\\.audit_log from ${reader}, and no policy shows it all of them: pg_dump would dump only those it sees, 0 of the log's ${seeded.entries} entries among them`));
    assert.throws(() => statSync(file), { code: 'ENOENT' });
    assert.throws(() => statSync(manifestPath(file)), { code: 'ENOENT' });
  } finally {
    await asOwner('postgres', (client) => client.unsafe(`DROP ROLE ${reader}`));
  }
});

test('backup refuses the backup login too, once a restrictive policy hides entries from it', postgres, async () => {
  const name = await database('migrated');
  await seed(name);
  // Restrictive policies are ANDed with the permissive ones: coffre_backup's USING (true) no longer shows every row.
  await asOwner(name, (client) => client.unsafe("CREATE POLICY audit_log_hide ON audit_log AS RESTRICTIVE FOR SELECT TO coffre_backup USING (action <> 'key.rotate')"));
  const { code, stderr } = await coffre(['backup', join(work, 'restricted.dump')], backupLogin(name));
  assert.equal(code, 1);
  assert.match(stderr, /row-level security hides rows of public\.audit_log from coffre_backup_login, and no policy shows it all of them: pg_dump would dump only those it sees, 7 of the log's 8 entries among them/);
});

test('restore brings the backup back into an empty database, then checks it whole with every key', postgres, async () => {
  const target = await database('empty');
  const { code, stderr } = await coffre(['restore', dump, '--keys'], withKeys(target, [kek, earlierKek], [appKey, earlierAppKey]));
  assert.equal(code, 0, stderr);
  assert.match(stderr, /✓ rows {16}every table's, as backed up/);
  assert.match(stderr, /✓ audit log {11}8 entries, every link and hash, from the first to the head, each key in its turn; 5 by the app, each MAC checked; 3 by the vault, each MAC checked\n/);
  assert.match(stderr, /✓ values {14}every one of 5 versions opens, under vault ID (old-vault and test-vault|test-vault and old-vault), each plain one as its text; not opened: 1 erased, deleted for good/);
  assert.match(stderr, /Left to do before traffic/);
  for (const key of [kek, earlierKek, appKey]) assert.ok(!stderr.includes(key.toString('base64')));
  // The grants and row policies came back with it.
  const policies = await asOwner(target, (client) => client.unsafe<{ policyname: string }[]>("SELECT policyname FROM pg_policies WHERE tablename = 'audit_log' ORDER BY 1"));
  assert.ok(policies.some((row) => row.policyname === 'audit_log_backup_read'));

  const again = await coffre(['restore', dump], owner(target));
  assert.equal(again.code, 1);
  assert.match(again.stderr, new RegExp(`${target} is not empty: it holds drizzle\\.__drizzle_migrations`));
});

test('verify backup checks without a key, and needs no role: no grant or policy comes back', postgres, async () => {
  const target = await database('empty');
  const { code, stderr } = await coffre(['verify', 'backup', dump], owner(target));
  assert.equal(code, 0, stderr);
  assert.match(stderr, /✓ audit log {11}8 entries, every link and hash, from the first to the head, each key in its turn \(without keys: not who wrote them\)/);
  assert.match(stderr, new RegExp(`The copy stays in 127\\.0\\.0\\.1/${target}`));
  const [{ n }] = await asOwner(target, (client) => client.unsafe<[{ n: number }]>("SELECT count(*)::int AS n FROM pg_policies WHERE tablename = 'audit_log'"));
  assert.equal(n, 0);
});

test('with the current keys alone, the earlier entries are linked only, and what the earlier vault key wrapped does not open', postgres, async () => {
  const { code, stderr } = await coffre(['verify', 'backup', dump, '--keys'], withKeys(await database('empty'), [kek], [appKey]));
  assert.equal(code, 1);
  assert.match(stderr, /✓ audit log {11}8 entries.*; 3 by the app, each MAC checked, after 2 under keys not given, linked only \(app:[0-9a-f]{16}\); 2 by the vault, each MAC checked, after 1 under keys not given, linked only \(vault:[0-9a-f]{16}\)\n/);
  assert.match(stderr, /✗ values {14}1 of 5 versions do not open with the vault keys given: market\/prod\/OLD_TOKEN v1 \(vault ID old-vault\); those under an earlier vault ID open only with the vault key it names/);
});

test('the wrong vault key opens no value and made no entry; an earlier app key given as the current one stops at the next key', postgres, async () => {
  const wrong = await coffre(['verify', 'backup', dump, '--keys'], withKeys(await database('empty'), [randomBytes(32)], [appKey, earlierAppKey]));
  assert.equal(wrong.code, 1);
  // In order of their paths: the personal config's, prod~ada, comes after prod's.
  assert.match(wrong.stderr, /✗ values {14}5 of 5 versions do not open with the vault keys given: market\/prod\/API_URL v1 \(vault ID test-vault\), market\/prod\/DATABASE_URL v1 \(vault ID test-vault\), market\/prod\/OLD_TOKEN v1 \(vault ID old-vault\) and 2 more; none of the vault keys given is this instance's/);
  assert.match(wrong.stderr, /✗ audit log {11}the vault's newest entries are under vault:[0-9a-f]{16}, which the first vault key given does not make/);

  const earlier = await coffre(['verify', 'backup', dump, '--keys'], withKeys(await database('empty'), [kek, earlierKek], [earlierAppKey]));
  assert.equal(earlier.code, 1);
  assert.match(earlier.stderr, new RegExp(`✗ audit log {11}broken at entry 3: written under ${keys.app.keyId} after the app signed with ${keys.earlierApp.keyId}, the key given as its current one: either that is not the one the app signs with now`));

  const appOnly = await coffre(['verify', 'backup', dump, '--keys'], `${owner(await database('empty'))}\n\n${appKey.toString('base64')} ${earlierAppKey.toString('base64')}\n`);
  assert.equal(appOnly.code, 0, appOnly.stderr);
  assert.match(appOnly.stderr, /5 by the app, each MAC checked; the vault's not authenticated \(no key given\)/);
  assert.match(appOnly.stderr, /– values {14}not opened: no vault key given/);

  const none = await coffre(['verify', 'backup', dump, '--keys'], `${owner(await database('empty'))}\n\n\n`);
  assert.equal(none.code, 1);
  assert.match(none.stderr, /--keys, and no key given/);
});

test("a vault's own signing key, typed as a vault key, authenticates what it signed", postgres, async () => {
  const file = await backedUp('own-signing.dump', { log: [{ key: keys.app }, { key: keys.ownSigning }, { key: keys.app }] });
  // It signs with that key, so it comes first; the vault keys after it open the values.
  const run = await coffre(['verify', 'backup', file, '--keys'], withKeys(await database('empty'), [signingKey, kek, earlierKek], [appKey]));
  assert.equal(run.code, 0, run.stderr);
  assert.match(run.stderr, /✓ audit log {11}3 entries.*; 2 by the app, each MAC checked; 1 by the vault, each MAC checked\n/);
});

test('once the key given as current has written, an earlier one writing after it breaks the log, even for the first time', postgres, async () => {
  const file = await backedUp('stale.dump', { log: [{ key: keys.app }, { key: keys.vault }, { key: keys.earlierVault }] });
  const run = await coffre(['verify', 'backup', file, '--keys'], withKeys(await database('empty'), [kek, earlierKek], [appKey]));
  assert.equal(run.code, 1);
  assert.match(run.stderr, new RegExp(`✗ audit log {11}broken at entry 2: written under ${keys.earlierVault.keyId} after the vault signed with ${keys.vault.keyId}, the key given as its current one`));
});

test('a dump that is not the one described, or a manifest that disagrees, fails its check', postgres, async () => {
  const copy = join(work, 'changed.dump');
  writeFileSync(copy, readFileSync(dump));
  appendFileSync(copy, 'x');
  writeFileSync(manifestPath(copy), readFileSync(manifestPath(dump)));
  const longer = await coffre(['verify', 'backup', copy], owner(await database('empty')));
  assert.equal(longer.code, 1);
  assert.match(longer.stderr, /✗ dump {16}.*changed\.dump is \d[\d,]* bytes, and the backup made/);

  const partial = join(work, 'partial.dump');
  writeFileSync(partial, readFileSync(dump));
  writeFileSync(manifestPath(partial), JSON.stringify({ format: 'coffre.backup.v1', dump: { bytes: 1 } }));
  const lacking = await coffre(['verify', 'backup', partial], owner(await database('empty')));
  assert.equal(lacking.code, 1);
  assert.match(lacking.stderr, /partial\.manifest\.json is not a whole manifest: it lacks dump, tables, migrations and log/);

  const counted = join(work, 'counted.dump');
  writeFileSync(counted, readFileSync(dump));
  const manifest = JSON.parse(readFileSync(manifestPath(dump), 'utf8')) as Manifest;
  manifest.tables['public.projects']!.rows += 1;
  manifest.log!.head = '00'.repeat(32);
  writeFileSync(manifestPath(counted), JSON.stringify(manifest));
  const differs = await coffre(['verify', 'backup', counted], owner(await database('empty')));
  assert.equal(differs.code, 1);
  assert.match(differs.stderr, /✗ rows {16}one table differs: public\.projects has 1 row, and the backup 2/);
  assert.match(differs.stderr, /✗ audit log {11}the head is at entry 8, [0-9a-f]{12}…; the backup's was 8, 000000000000…/);
});

test('without a key, the check finds an entry changed after it was sealed, and each key used out of its turn', postgres, async () => {
  const cases: [string, Parameters<typeof seed>[1], RegExp][] = [
    ['forged', { edit: { seq: 4n, action: 'test.forged' } }, /broken at entry 4: hash does not match the entry/],
    // A key the app moved on from writes nothing after: a leaked one cannot add to the log.
    ['moved', { log: [{ key: keys.earlierApp }, { key: keys.app, moves: keys.earlierApp }, { key: keys.earlierApp }] }, /broken at entry 2: written under app:[0-9a-f]{16} after the app moved on from it/],
    // The vault's keys only move forward.
    ['back', { log: [{ key: keys.earlierVault }, { key: keys.vault }, { key: keys.earlierVault }] }, /broken at entry 2: written under vault:[0-9a-f]{16} after the vault moved to vault:/],
  ];
  for (const [name, options, broken] of cases) {
    const file = await backedUp(`${name}.dump`, options);
    const run = await coffre(['verify', 'backup', file], owner(await database('empty')));
    assert.equal(run.code, 1, name);
    assert.match(run.stderr, new RegExp(`✗ audit log {11}${broken.source}`), name);
  }
});
