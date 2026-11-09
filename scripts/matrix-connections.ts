// The use matrices' shares of Postgres's connections (T246). `pnpm test:matrices` runs its files side by side, a process
// each, on one server, which lets a login open `max_connections` less the slots it keeps for superusers and for
// `pg_use_reserved_connections`: past that, a connection is refused (53300) and the cell that asked for it fails. So each
// file keeps to a share: what the server lets open, split evenly among the files still running. A file whose cells are
// fixed (a row of them at once) is held to its share as it starts; use.matrix.ts, whose batches take as many rows as
// fit, sizes each batch from its share then.
//
// `scripts/test-suite.sh --files` says how many files it runs (`COFFRE_TEST_FILES`), how many at once
// (`COFFRE_TEST_CONCURRENCY`), and gives them a directory (`COFFRE_TEST_FILES_ENDED`) where each, once its process exits,
// its connections closed, leaves its id. A share only grows: the files running are never more than those that have not
// ended, so the shares of the files running never add up past what the server lets open. A file that crashed leaves no
// id and keeps its share: the others' are only smaller.
import { readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Each pool of a matrix's test database (its owner's, the vault's, the hot path's): `openTestDatabase({ connections })`. */
export const POOL = 4;

/**
 * What a matrix of the vault holds open beside its cells: its test database's three pools of `POOL`, and the connection
 * that holds its batch's principals' locks (`holding`). Its weighing, once the cells have ended, holds fewer.
 */
export const BESIDE_CELLS = 3 * POOL + 1;

/** The connections the server lets a login open: run as the database's owner, the matrices' first query. */
export const FREE_CONNECTIONS = `SELECT current_setting('max_connections')::int - current_setting('superuser_reserved_connections')::int
  - coalesce(current_setting('reserved_connections', true), '0')::int AS free`;

// This file's process, as it exits: imported by every matrix, so each says it ended, its share then the others'.
const endedAt = process.env.COFFRE_TEST_FILES_ENDED;
if (endedAt !== undefined && endedAt !== '') process.on('exit', () => writeFileSync(join(endedAt, String(process.pid)), ''));

/** This file's share of `free` connections: split evenly among the files of the run still running, this one included. */
export function connectionShare(free: number): number {
  const { COFFRE_TEST_FILES: files, COFFRE_TEST_CONCURRENCY: atOnce, COFFRE_TEST_FILES_ENDED: ended } = process.env;
  if (!(Number(files) >= 1 && Number(atOnce) >= 1) || ended === undefined || ended === '') {
    throw new Error('a use matrix runs through scripts/test-suite.sh --files (pnpm test:matrices), which says how many files share Postgres');
  }
  // This file has not ended: it is one of those running.
  const running = Math.max(1, Math.min(Number(atOnce), Number(files) - readdirSync(ended).length));
  return Math.floor(free / running);
}

/** Fails, before any cell, a file whose `needs` connections at once are past its share of `free`, rather than a cell later on 53300. */
export function withinShare(file: string, needs: number, free: number): void {
  const share = connectionShare(free);
  if (needs > share) {
    throw new Error(`${file} holds up to ${needs} connections at once, past its share of Postgres's ${free}, ${share}, beside the other files running`);
  }
}
