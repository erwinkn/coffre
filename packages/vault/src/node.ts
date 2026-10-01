/**
 * The vault on Node, one of two ways, each over the database the server
 * uses, through the vault's own login:
 *
 * - in the server's own process: `vault: await localVault({ database, ...keys })`;
 * - as a process of its own, which the server reaches over a Unix socket:
 *   `serveVault({ socket, database, ...keys })` there, and
 *   `vault: connectVault(socket)` in the server.
 *
 * The second keeps every key out of the process that faces the network. The
 * socket is the whole of its authentication: a file only the vault's user
 * and the group it shares with the server may open, so no port to reach and
 * no shared secret to leak. Each call is one HTTP POST over it, `/<method>`
 * with the arguments as a JSON array, and refusals come back as values, as
 * from any vault; only a failure is an error.
 */
import { chmodSync, existsSync, lstatSync, rmSync } from 'node:fs';
import { Agent, createServer, request as httpRequest, type IncomingMessage } from 'node:http';

import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';

import { resolveVaultConfig, type VaultConfig } from './config.ts';
import { METHODS, openLocalVault, type LocalVault } from './local.ts';
import type { VaultOptions } from './vault.ts';

export type { Vault, VaultConfig };
export * from './index.ts';
export type { LocalVault, VaultOptions };

export type NodeVaultConfig = VaultConfig & {
  /**
   * The database the server uses, as the vault's own login:
   * `postgres://coffre_vault_runtime:…@…/coffre`, or a `file:` URL for local
   * development. Or one already open, which the vault leaves open.
   */
  database: string | Database;
};

/** The vault in this process. */
export async function localVault(config: NodeVaultConfig, options: VaultOptions = {}): Promise<LocalVault> {
  const resolved = resolveVaultConfig(config);
  if (typeof config.database !== 'string') return openLocalVault(config.database, resolved, options);
  const { db, close } = await openDatabase(config.database);
  return openLocalVault(db, resolved, options, close).catch(async (error: unknown) => {
    await close();
    throw error;
  });
}

const METHOD_NAMES = new Set<string>(METHODS);
const MAX_BODY = 8 * 1024 * 1024;

export type VaultServer = { socket: string; close(): Promise<void> };

/**
 * The vault as a process of its own, answering on a Unix socket. The socket
 * is made `0660`: put it in a directory the server's user can reach through
 * a shared group, e.g. `/run/coffre/vault.sock`.
 */
export async function serveVault(config: NodeVaultConfig & { socket: string }): Promise<VaultServer> {
  const vault = await localVault(config);
  const server = createServer(async (req, res) => {
    const name = (req.url ?? '').slice(1);
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'POST' || !METHOD_NAMES.has(name)) return reply(404, { error: 'not a vault call' });
    try {
      const args = JSON.parse(await readBody(req)) as unknown;
      if (!Array.isArray(args)) return reply(400, { error: 'the arguments must be a JSON array' });
      const result = await (vault[name as keyof Vault] as (...args: unknown[]) => Promise<unknown>)(...args);
      reply(200, result === undefined ? {} : { result });
    } catch (error) {
      console.error(`vault ${name} failed`, error);
      reply(500, { error: error instanceof Error ? error.message : 'the vault failed' });
    }
  });

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

/** The vault that `serveVault` runs, from the server's side of its socket. */
export function connectVault(socket: string): Vault {
  const agent = new Agent({ keepAlive: true });
  const call = (name: string) => (...args: unknown[]) =>
    new Promise<unknown>((resolve, reject) => {
      const body = JSON.stringify(args);
      const req = httpRequest(
        {
          socketPath: socket,
          agent,
          method: 'POST',
          path: `/${name}`,
          headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
        },
        (res) => {
          readBody(res).then((text) => {
            const payload = JSON.parse(text) as { result?: unknown; error?: string };
            if (res.statusCode === 200) resolve(payload.result);
            else reject(new Error(`vault ${name}: ${payload.error ?? `status ${res.statusCode}`}`));
          }, reject);
        },
      );
      req.on('error', (error) => reject(new Error(`the vault at ${socket} is unreachable: ${error.message}`)));
      req.end(body);
    });
  return Object.fromEntries(METHODS.map((name) => [name, call(name)])) as unknown as Vault;
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
