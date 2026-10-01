import { createDatabase, type Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import type { Engine } from '@coffre/db/dialect';

import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL } from './connections.ts';
import { guardTransactions } from '../transaction-guard.ts';

/**
 * Which database the integration suite runs on: `COFFRE_TEST_ENGINE` is
 * postgres (the default) or sqlite. scripts/test-suite.sh prepares it,
 * and for SQLite hands its URL over in `COFFRE_TEST_DATABASE_URL`.
 */
export const TEST_ENGINE = testEngine(process.env.COFFRE_TEST_ENGINE ?? 'postgres');

function testEngine(name: string): Engine {
  if (name === 'postgres' || name === 'sqlite') return name;
  throw new Error(`COFFRE_TEST_ENGINE must be postgres or sqlite, not ${name}`);
}

/**
 * The integration database twice: as its owner, to reset and inspect, and
 * as the app. On Postgres the app is the restricted runtime role. SQLite
 * has no logins, but opens two clients all the same, as two servers would.
 */
export async function openTestDatabase(): Promise<{ owner: Database; runtime: Database; close: () => Promise<void> }> {
  if (TEST_ENGINE === 'postgres') {
    const pg = (await import('pg')).default;
    const ownerPool = new pg.Pool({ connectionString: TEST_OWNER_DATABASE_URL });
    const runtimePool = new pg.Pool({ connectionString: TEST_RUNTIME_DATABASE_URL });
    return {
      owner: guardTransactions(createDatabase(ownerPool)),
      runtime: guardTransactions(createDatabase(runtimePool)),
      close: async () => {
        await Promise.all([ownerPool.end(), runtimePool.end()]);
      },
    };
  }
  const url = process.env.COFFRE_TEST_DATABASE_URL;
  if (!url) throw new Error(`COFFRE_TEST_DATABASE_URL is required on ${TEST_ENGINE}; see scripts/setup-test-database.sh`);
  const [owner, runtime] = await Promise.all([openDatabase(url), openDatabase(url)]);
  return {
    owner: guardTransactions(owner.db),
    runtime: guardTransactions(runtime.db),
    close: async () => {
      await Promise.all([owner.close(), runtime.close()]);
    },
  };
}

/** Test options that run a test on Postgres only, saying why it cannot run elsewhere. */
export function postgresOnly(reason: string): { skip: string | false } {
  return { skip: TEST_ENGINE === 'postgres' ? false : `Postgres only: ${reason}` };
}
