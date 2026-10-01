import { execFileSync } from 'node:child_process';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import {
  generateDrizzleJson,
  generateMigration,
  generateMySQLDrizzleJson,
  generateMySQLMigration,
  generateSQLiteDrizzleJson,
  generateSQLiteMigration,
} from 'drizzle-kit/api';

import type { Engine } from './dialect.ts';
import { migrationsFolder } from './migrate.ts';
import * as postgres from './schema.ts';
import * as mysql from './schema.mysql.ts';
import * as sqlite from './schema.sqlite.ts';

/**
 * coffre has never been deployed, so there is no database to upgrade: each
 * engine has one migration, its baseline, and a schema change regenerates it
 * rather than adding a second. After the first deployment, changes become new
 * migrations and this goes.
 *
 * A baseline is baseline/<engine>.sql with its `-- @schema` line replaced by
 * the tables drizzle-kit generates from that engine's schema. The template
 * holds what a schema cannot say: the MySQL collation, the audit chain's
 * first rows, and the Postgres runtime role and its grants.
 *
 * `pnpm db:generate` runs this file and rewrites the baselines that are stale.
 */

export const ENGINES: readonly Engine[] = ['postgres', 'mysql', 'sqlite'];

const TAG = '0000_baseline';
const MARKER = '-- @schema\n';
const packageRoot = fileURLToPath(new URL('..', import.meta.url));

async function template(engine: Engine): Promise<{ head: string; tail: string }> {
  const text = await readFile(`${packageRoot}baseline/${engine}.sql`, 'utf8');
  const [head, tail, ...more] = text.split(MARKER);
  if (tail === undefined || more.length > 0) {
    throw new Error(`baseline/${engine}.sql needs exactly one ${MARKER.trim()} line`);
  }
  return { head, tail };
}

export async function journal(engine: Engine): Promise<{ idx: number; tag: string }[]> {
  const text = await readFile(`${migrationsFolder(engine)}/meta/_journal.json`, 'utf8');
  return (JSON.parse(text) as { entries: { idx: number; tag: string }[] }).entries;
}

/** The statements that would bring the engine's last snapshot to its schema. */
async function pending(engine: Engine): Promise<string[]> {
  const last = String((await journal(engine)).at(-1)!.idx).padStart(4, '0');
  const snapshot = JSON.parse(
    await readFile(`${migrationsFolder(engine)}/meta/${last}_snapshot.json`, 'utf8'),
  ) as never;
  switch (engine) {
    case 'postgres':
      return generateMigration(snapshot, generateDrizzleJson(postgres) as never);
    case 'mysql':
      return generateMySQLMigration(snapshot, (await generateMySQLDrizzleJson(mysql)) as never);
    case 'sqlite':
      return generateSQLiteMigration(snapshot, (await generateSQLiteDrizzleJson(sqlite)) as never);
  }
}

/** Why the engine's baseline is out of date: empty when it is not. */
export async function staleness(engine: Engine): Promise<string[]> {
  const tags = await journal(engine).then(
    (entries) => entries.map((entry) => entry.tag),
    () => [],
  );
  if (tags.length !== 1 || tags[0] !== TAG) return [`expected only ${TAG}, found [${tags.join(', ')}]`];
  const reasons = await pending(engine);
  const { head, tail } = await template(engine);
  const baseline = await readFile(`${migrationsFolder(engine)}/${TAG}.sql`, 'utf8');
  if (!baseline.startsWith(head) || !baseline.endsWith(tail)) reasons.push(`baseline/${engine}.sql changed`);
  return reasons;
}

async function regenerate(engine: Engine): Promise<void> {
  const folder = migrationsFolder(engine);
  await rm(folder, { recursive: true, force: true });
  execFileSync(
    `${packageRoot}node_modules/.bin/drizzle-kit`,
    ['generate', '--config', `drizzle.${engine}.config.ts`, '--name', 'baseline'],
    { cwd: packageRoot, stdio: 'inherit' },
  );
  const tables = (await readFile(`${folder}/${TAG}.sql`, 'utf8')).trimEnd();
  const breakpoint = tables.endsWith('--> statement-breakpoint') ? '' : '--> statement-breakpoint';
  const { head, tail } = await template(engine);
  await writeFile(`${folder}/${TAG}.sql`, `${head}${tables}${breakpoint}\n${tail}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  for (const engine of ENGINES) {
    const reasons = await staleness(engine);
    if (reasons.length === 0) {
      console.log(`${engine}: the baseline is up to date`);
      continue;
    }
    console.log(`${engine}: regenerating the baseline (${reasons.length} change${reasons.length === 1 ? '' : 's'})`);
    await regenerate(engine);
  }
}
