import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { generateDrizzleJson, generateMigration } from 'drizzle-kit/api';

import { migrationsFolder } from './migrate.ts';
import * as schema from './schema.ts';

/**
 * Applied migrations are immutable. Schema changes append a migration to
 * the journal; custom safety checks belong in that new migration.
 *
 * The baseline is baseline/postgres.sql with its `-- @schema` line replaced
 * by the tables drizzle-kit generates from the schema. The template holds
 * what a schema cannot say: the audit chain's first rows, the audit log's
 * append-only and the secret versions' erase-only triggers, and the runtime
 * roles and their grants. Since 0.4.0, every database starts from this one
 * baseline.
 *
 * `pnpm db:generate` runs this file and appends pending schema changes.
 */

const TAG = '0000_baseline';
const MARKER = '-- @schema\n';
const here = fileURLToPath(new URL('.', import.meta.url));
const packageRoot = fileURLToPath(new URL('..', import.meta.url));

async function template(): Promise<{ head: string; tail: string }> {
  const text = await readFile(`${here}baseline/postgres.sql`, 'utf8');
  const [head, tail, ...more] = text.split(MARKER);
  if (tail === undefined || more.length > 0) {
    throw new Error(`baseline/postgres.sql needs exactly one ${MARKER.trim()} line`);
  }
  return { head, tail };
}

export async function journal(): Promise<{ idx: number; tag: string }[]> {
  const text = await readFile(`${migrationsFolder()}/meta/_journal.json`, 'utf8');
  return (JSON.parse(text) as { entries: { idx: number; tag: string }[] }).entries;
}

/** The statements that would bring the last snapshot to the schema. */
async function pending(): Promise<string[]> {
  const last = String((await journal()).at(-1)!.idx).padStart(4, '0');
  const snapshot = JSON.parse(
    await readFile(`${migrationsFolder()}/meta/${last}_snapshot.json`, 'utf8'),
  ) as never;
  return generateMigration(snapshot, generateDrizzleJson(schema) as never);
}

/** Why the migration tree is out of date: empty when it matches the schema. */
export async function staleness(): Promise<string[]> {
  const tags = await journal().then(
    (entries) => entries.map((entry) => entry.tag),
    () => [],
  );
  if (tags[0] !== TAG) return [`expected the immutable ${TAG} first`];
  const reasons = await pending();
  const { head, tail } = await template();
  const baseline = await readFile(`${migrationsFolder()}/${TAG}.sql`, 'utf8');
  if (!baseline.startsWith(head) || !baseline.endsWith(tail)) reasons.push('baseline/postgres.sql changed');
  return reasons;
}

function generate(): void {
  execFileSync(
    `${packageRoot}node_modules/.bin/drizzle-kit`,
    ['generate', '--config', 'drizzle.postgres.config.ts', '--name', process.argv[2] ?? 'schema'],
    // drizzle-kit loads the schema, which imports the workspace's other packages by their sources.
    { cwd: here, stdio: 'inherit', env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --conditions=coffre:source`.trim() } },
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const reasons = await staleness();
  if (reasons.length === 0) {
    console.log('the migration tree is up to date');
  } else {
    console.log(`appending a migration (${reasons.length} change${reasons.length === 1 ? '' : 's'})`);
    generate();
  }
}
