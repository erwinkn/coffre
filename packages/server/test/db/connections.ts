/** `COFFRE_TEST_DATABASE` points a run at another scratch database. */
const database = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';

export const TEST_OWNER_DATABASE_URL =
  `postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/${database}`;

export const TEST_RUNTIME_DATABASE_URL =
  `postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/${database}`;

export const TEST_VAULT_DATABASE_URL =
  `postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:55432/${database}`;
