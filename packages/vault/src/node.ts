/**
 * The vault on Node, one of two ways, each over the database the server
 * uses, through the vault's own login and its uses' (`hotDatabase`), with
 * the checkpointer that seals its log in the same process (`checkpointer`):
 *
 * - in the server's own process: `vault: await localVault({ database, hotDatabase, checkpointer, ...keys })`;
 * - as a process of its own, which the server reaches over a Unix socket:
 *   `serveVault({ socket, database, hotDatabase, checkpointer, ...keys })` there, and
 *   `vault: connectVault(socket)` in the server.
 *
 * The second keeps every key out of the process that faces the network. The
 * socket is the whole of its authentication: a file only the vault's user
 * and the group it shares with the server may open, so no port to reach and
 * no shared secret to leak. Each call is one HTTP POST over it, `/call`,
 * the version gate's envelope (`{ release, method, args }`), and refusals
 * come back as values, as from any vault; only a failure is an error.
 */
import { chmodSync, existsSync, lstatSync, rmSync } from 'node:fs';
import { Agent, createServer, request as httpRequest, type IncomingMessage } from 'node:http';

import type { Vault, VaultAnswer, VaultEntry, VaultMethod } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';

import { keepCheckpointer } from './checkpointer-node.ts';
import { resolveVaultConfig, type VaultConfig } from './config.ts';
import { failureOf } from './failure.ts';
import { METHODS, openLocalVault, spoken, type LocalVault, type SpokenVault } from './local.ts';
import type { VaultOptions } from './vault.ts';

export type { Vault, VaultConfig, VaultEntry };
export * from './index.ts';
export type { LocalVault, SpokenVault, VaultOptions };
export { spoken };
/** 0.15's checkpointer on Node (docs/design/audit-tree.md), which `localVault` runs in the vault's process. */
export { fileMemory, keepCheckpointer, runCheckpointer, type KeptCheckpointer, type RunningCheckpointer } from './checkpointer-node.ts';
/**
 * 0.15's log replayed as stored: what each use decides on the log, which every live answer must be (R53). For the
 * suites only: it reads the whole log into memory, every use ever made. Plan PR 8's verifier walks it a stretch at a time.
 */
export { replayStored } from './log-replay.ts';

export type NodeVaultConfig = VaultConfig & {
  /**
   * The database the server uses, as the vault's own login:
   * `postgres://coffre_vault_runtime:…@…/coffre`. Or one already open, which
   * the vault leaves open.
   */
  database: string | Database;
  /**
   * 0.15's uses (docs/design/0.15-plan.md, PR 5): the same database as
   * `coffre_vault_hot`, whose lock and statement timeouts bound a use, or
   * one already open. Required.
   */
  hotDatabase?: string | Database;
  /**
   * 0.15's checkpointer, which this process runs: `memory`, the file it
   * keeps the newest pair it signed in, where no database writer reaches,
   * such as `/var/lib/coffre/checkpointer-memory`, writable by the vault's
   * user alone (its alarms go beside it, in `<memory>.alarms`). Required,
   * unless the caller seals through a checkpointer of its own
   * (`VaultOptions.sealThrough` and `heldOutside`).
   */
  checkpointer?: { memory: string };
};

/**
 * The vault in this process, and its checkpointer, opened before the vault
 * serves, so that no call meets a log with no checkpoint yet. A
 * configuration without what 0.15's log needs is refused.
 */
export async function localVault(config: NodeVaultConfig, options: VaultOptions = {}): Promise<LocalVault> {
  // The cover a repeat rides is the deployment's `audit.repeatsWithinSeconds`, which `uses.coverMs` gave until 0.16.
  const coverMs = options.uses?.coverMs;
  const resolved = resolveVaultConfig(config, coverMs === undefined ? [] : [{ old: 'serveVault(config, { uses: { coverMs } })', options: { audit: { repeatsWithinSeconds: coverMs / 1000 } } }]);
  const own = options.sealThrough === undefined;
  if (config.hotDatabase === undefined) {
    throw new Error("the vault's uses run as a login of their own: set hotDatabase in the vault's configuration, the database as coffre_vault_hot (HOT_DATABASE_URL)");
  }
  if (own && config.checkpointer?.memory === undefined) {
    throw new Error("the vault answers a change once its checkpointer has sealed it: set checkpointer: { memory } in the vault's configuration, the file its signer remembers in (CHECKPOINTER_MEMORY)");
  }
  const opened: (() => Promise<void>)[] = [];
  const open = async (database: string | Database) => {
    if (typeof database !== 'string') return database;
    const { db, close } = await openDatabase(database);
    opened.push(close);
    return db;
  };
  let checkpointer: { stop(): Promise<void> } | null = null;
  // The checkpointer stopped first, its tick in flight ended, then the databases closed.
  const close = async () => {
    await checkpointer?.stop();
    await Promise.all(opened.map((done) => done()));
  };
  try {
    const db = await open(config.database);
    // The same URL is the same connection.
    const hot = config.hotDatabase === config.database ? db : await open(config.hotDatabase);
    const uses = { ...options.uses, coverMs: resolved.deployment.audit.repeatsWithinSeconds * 1000 };
    if (own) {
      // A connection of its own, which it cuts once it stalls (T169): what a stalled tick awaits holds none of the vault's.
      const url = typeof config.database === 'string' ? config.database : null;
      const where = url === null ? { database: db } : { connect: () => openDatabase(url, { max: 2 }) };
      // Days of uses kept: the deployment's `audit.keepUsesDays`, every day when null (retention.ts).
      const kept = (checkpointer = await keepCheckpointer({ ...where, signingKeys: resolved.signingKeys, memory: config.checkpointer!.memory, retainDays: resolved.deployment.audit.keepUsesDays }));
      options = { ...options, sealThrough: kept.sealThrough, heldOutside: kept.heldOutside, sealing: kept.sealing };
    }
    return await openLocalVault(db, resolved, { ...options, uses }, close, hot);
  } catch (error) {
    await close();
    throw error;
  }
}

const MAX_BODY = 8 * 1024 * 1024;

export type VaultServer = { socket: string; close(): Promise<void> };

/**
 * The vault as a process of its own, answering on a Unix socket. The socket
 * is made `0660`: put it in a directory the server's user can reach through
 * a shared group, e.g. `/run/coffre/vault.sock`. One route, `POST /call`,
 * whose body is `{ release, method, args }`, the version gate's envelope,
 * answered whole: the entry it forwards to gates (`openLocalVault`), and
 * nothing here gates again. `options` are `localVault`'s, such as `uses`
 * (its cover window, name and batch sizes; how many keys it holds in flight is
 * derived, `USES_IN_FLIGHT` in `@coffre/core/memory`, not set here).
 */
export async function serveVault(config: NodeVaultConfig & { socket: string }, options: VaultOptions = {}): Promise<VaultServer> {
  const vault = await localVault(config, options);
  const server = createServer(async (req, res) => {
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'POST' || req.url !== '/call') return reply(404, { error: 'not a vault call' });
    let name = 'call';
    try {
      const envelope = JSON.parse(await readBody(req)) as { release?: unknown; method?: unknown; args?: unknown } | null;
      if (typeof envelope !== 'object' || envelope === null || !Array.isArray(envelope.args) || typeof envelope.method !== 'string' || !(METHODS as readonly string[]).includes(envelope.method)) {
        return reply(400, { error: 'a call is { release, method, args }, its arguments a JSON array' });
      }
      name = envelope.method;
      // Copied as a Workers vault's RPC copies a call, by V8's serializer (structured clone), so that a call nested
      // deeper than it carries is refused here as there, before any method runs, whatever the method checks first:
      // `JSON.parse` reads any depth, and Node 26's `JSON.stringify` writes 100,000 levels where 24's overflowed. For
      // JSON values the copy is the same value; it overflows (`RangeError`), answered 400 by `failureOf`.
      reply(200, await vault.call(String(envelope.release), envelope.method as VaultMethod, structuredClone(envelope.args)));
    } catch (error) {
      console.error(`vault ${name} failed`, error);
      const { status, body } = failureOf(error);
      reply(status, body);
    }
  });

  // The server's agent keeps its connections open for its next calls, so
  // the vault never ends an idle one. Node's default did, after five seconds
  // and one more, racing the server's next call on it, which then failed
  // with ECONNRESET: "coffre cannot check who you are right now".
  server.keepAliveTimeout = 0;

  // A socket file left by a vault that did not stop cleanly would make
  // listen fail; anything else at that path is not ours to remove.
  if (existsSync(config.socket)) {
    if (!lstatSync(config.socket).isSocket()) throw new Error(`${config.socket} exists and is not a socket`);
    rmSync(config.socket);
  }
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.socket, () => resolve());
  });
  chmodSync(config.socket, 0o660);

  return {
    socket: config.socket,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => void vault.close().then(resolve));
        server.closeAllConnections();
      }),
  };
}

/** The vault that `serveVault` runs, from the server's side of its socket: its one entry, whose answer is the envelope, whole. */
export function connectVault(socket: string): VaultEntry {
  const agent = new Agent({ keepAlive: true });
  const call = (release: string, name: VaultMethod, args: readonly unknown[]) =>
    new Promise<VaultAnswer>((resolve, reject) => {
      const body = JSON.stringify({ release, method: name, args });
      const req = httpRequest(
        {
          socketPath: socket,
          agent,
          method: 'POST',
          path: '/call',
          headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
        },
        (res) => {
          readBody(res).then((text) => {
            const payload = JSON.parse(text) as VaultAnswer & { error?: string; code?: string };
            if (res.statusCode === 200) return resolve(payload);
            const failed = new Error(`vault ${name}: ${payload.error ?? `status ${res.statusCode}`}`);
            reject(payload.code === undefined ? failed : Object.assign(failed, { code: payload.code }));
          }, reject);
        },
      );
      // No socket file is a vault that stopped cleanly, as a refused connection is one that did not: the same outage.
      req.on('error', (error: NodeJS.ErrnoException) =>
        reject(new Error(`the vault at ${socket} is unreachable: ${error.message}`, { cause: error.code === 'ENOENT' ? Object.assign(error, { code: 'ECONNREFUSED' }) : error })));
      req.end(body);
    });
  return { call };
}

async function readBody(stream: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error('the message is too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}
