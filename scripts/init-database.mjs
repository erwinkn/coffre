import { Client } from 'pg';
import { createConnection } from 'mysql2/promise';
import { readFile } from 'node:fs/promises';
const engine = process.argv[2], instanceId = process.env.INSTANCE_ID;
if (!['postgres', 'mysql'].includes(engine) || !/^[a-f0-9-]{36}$/.test(instanceId ?? '')) throw new Error('Set INSTANCE_ID and DATABASE_URL, then run: node scripts/init-database.mjs postgres|mysql');
const url = new URL(process.env.DATABASE_URL ?? '');
if (url.search || url.hash) throw new Error('Use a database URL without query options. Set DATABASE_CA_FILE for a private CA.');
const local = process.env.COFFRE_LOCAL === '1' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
const options = { host: url.hostname, port: Number(url.port || (engine === 'postgres' ? 5432 : 3306)), user: decodeURIComponent(url.username), password: decodeURIComponent(url.password), database: url.pathname.slice(1), ...(local ? {} : { ssl: { rejectUnauthorized: true, ...(process.env.DATABASE_CA_FILE ? { ca: await readFile(process.env.DATABASE_CA_FILE, 'utf8') } : {}) } }) };
const db = engine === 'postgres' ? new Client(options) : await createConnection({ ...options, multipleStatements: false });
if (engine === 'postgres') await db.connect();
try {
  const sql = (await readFile(`packages/storage/migrations/${engine}.sql`, 'utf8')).replace(/^--.*$/gm, '').split(';').map(s => s.trim()).filter(Boolean);
  // This intentionally refuses an existing schema: no destructive reset or automatic migration guessing.
  for (const statement of sql) await db.query(statement);
  await db.query(`INSERT INTO coffre_meta(singleton,instance_id,revision,audit_seq,audit_hash) VALUES (1,${engine === 'postgres' ? '$1' : '?'},0,0,${engine === 'postgres' ? '$2' : '?'})`, [instanceId, 'GENESIS']);
  console.log('Schema initialized. Configure the restricted runtime role separately before deployment.');
} finally { await db.end(); }
