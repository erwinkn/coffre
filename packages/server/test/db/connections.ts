/** `COFFRE_TEST_DATABASE` points a run at another scratch database. */
const database = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
/** `COFFRE_POSTGRES_PORT`, at another compose Postgres. */
const port = process.env.COFFRE_POSTGRES_PORT ?? '55432';

export const TEST_OWNER_DATABASE_URL =
  `postgresql://coffre_owner:local-dev-only@127.0.0.1:${port}/${database}`;

export const TEST_RUNTIME_DATABASE_URL =
  `postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${port}/${database}`;

export const TEST_VAULT_DATABASE_URL =
  `postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${port}/${database}`;
