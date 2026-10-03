import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import {
  generateDrizzleJson,
  generateMigration,
  generateSQLiteDrizzleJson,
  generateSQLiteMigration,
} from 'drizzle-kit/api';

import type { Engine } from './dialect.ts';
import { migrationsFolder } from './migrate.ts';
import * as postgres from './schema.ts';
import * as sqlite from './schema.sqlite.ts';

/**
 * Applied migrations are immutable. Schema changes append a migration to
 * each engine's journal; custom safety checks belong in that new migration.
 *
 * A baseline is baseline/<engine>.sql with its `-- @schema` line replaced by
 * the tables drizzle-kit generates from that engine's schema. The template
 * holds what a schema cannot say: the audit chain's first rows, and the
 * Postgres runtime role and its grants.
 *
 * `pnpm db:generate` runs this file and appends pending schema changes.
 */

export const ENGINES: readonly Engine[] = ['postgres', 'sqlite'];

const TAG = '0000_baseline';
const MARKER = '-- @schema\n';
const here = fileURLToPath(new URL('.', import.meta.url));
const packageRoot = fileURLToPath(new URL('..', import.meta.url));

async function template(engine: Engine): Promise<{ head: string; tail: string }> {
  const text = await readFile(`${here}baseline/${engine}.sql`, 'utf8');
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
    case 'sqlite':
      return generateSQLiteMigration(snapshot, (await generateSQLiteDrizzleJson(sqlite)) as never);
  }
}

/** Why the migration tree is out of date: empty when it matches the schema. */
export async function staleness(engine: Engine): Promise<string[]> {
  const tags = await journal(engine).then(
    (entries) => entries.map((entry) => entry.tag),
    () => [],
  );
  if (tags[0] !== TAG) return [`expected the immutable ${TAG} first`];
  const reasons = await pending(engine);
  const { head, tail } = await template(engine);
  const baseline = await readFile(`${migrationsFolder(engine)}/${TAG}.sql`, 'utf8');
  if (!baseline.startsWith(head) || !baseline.endsWith(tail)) reasons.push(`baseline/${engine}.sql changed`);
  return reasons;
}

function generate(engine: Engine): void {
  execFileSync(
    `${packageRoot}node_modules/.bin/drizzle-kit`,
    ['generate', '--config', `drizzle.${engine}.config.ts`, '--name', process.argv[2] ?? 'schema'],
    { cwd: here, stdio: 'inherit' },
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  for (const engine of ENGINES) {
    const reasons = await staleness(engine);
    if (reasons.length === 0) {
      console.log(`${engine}: the migration tree is up to date`);
      continue;
    }
    console.log(`${engine}: appending a migration (${reasons.length} change${reasons.length === 1 ? '' : 's'})`);
    generate(engine);
  }
}
