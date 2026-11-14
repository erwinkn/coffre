// The app on the 0.16 contract, in process, for the server's tests: the
// real vault over the suite's database, through JSON as over any transport,
// and the app's own login for what its pages list. `calls`, `statements`
// and `sent` say what one request cost (`request-cost.test.ts` holds each
// route to its budget).
import { github, signin, type Auth } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import { createDatabase, type Database } from '@coffre/db';
import { checkDatabaseUrl, postgresClient } from '@coffre/db/connect';
import { APP_URL, openConfiguredVault, type TestVault } from '@coffre/vault/testing';

import type { PageContext } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime } from '../src/runtime.ts';
import type { Gates } from '../src/gate.ts';
import { requestScope } from '../src/scope.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { watched } from './db/postgres-pool.ts';

export const PUBLIC_URL = 'https://secrets.acme.example';
/** The session's cookie, as an HTTPS deployment names it. */
export const SESSION = '__Host-coffre_session';

export type TestApp = {
  /** The suite's database as the app's vault writes it: where a test makes its instance. */
  world: TestVault;
  /** The app's vault, for a test to ask as the app would. */
  vault: Vault;
  /** The vault's calls the app made, by name, oldest first. */
  calls: string[];
  /** What each of `calls` was given, in the same order. */
  inputs: unknown[];
  /** How many statements the app ran on its own connection. */
  readonly statements: number;
  /** What it executed, oldest first, as Drizzle's `SQL`: for a test to read a statement's parameters. */
  executed: unknown[];
  /** The rows each statement it executed answered, as `executed`: for a test to see how many a bounded read took. */
  answered: unknown[][];
  /** The work coffre told the platform to keep the request alive for, oldest first: the request's own, and what outlives its response. */
  tracked: Promise<unknown>[];
  /**
   * What the app's connection sent: every statement, a transaction's own
   * BEGIN and COMMIT and what it ran between them included, and the rows
   * they answered. `statements` counts a transaction as one.
   */
  readonly sent: { readonly statements: number; readonly rows: number };
  /** A request, as a deployment's Start app answers one: coffre's middleware around coffre's route. */
  request(path: string, init?: RequestInit): Promise<Response>;
  /** A page's render for a request, with what coffre hands it. */
  render<T>(init: RequestInit, page: (context: PageContext) => Promise<T>): Promise<Response>;
  close(): Promise<void>;
};

/**
 * `database`: another than the suite's, by name, for the app's own connection. `auth`: another than coffre's own sign-in.
 * `transport`: what the app asks issuers through, in place of the network. `workloads`: the vault's, which takes none unless given.
 * `gates`: the workload gates, none unless given.
 */
/** A test's transport unless it brings its own: it asks no issuer anything. */
const FETCHES_NOTHING: WorkloadTransport = { json: (url) => Promise.reject(new FetchRefused(url, "this test fetches nothing")) };

export async function openApp({ database, auth = signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }), transport, workloads, gates = null }: { database?: string; auth?: Auth; transport?: WorkloadTransport; workloads?: { noReads?: boolean; useOnly?: boolean }; gates?: Gates | null } = {}): Promise<TestApp> {
  const { world, vault } = await openConfiguredVault({ kek: { id: 'app-test', key: Buffer.alloc(32, 9).toString('base64') }, owners: ['root@acme.example'], ...(workloads === undefined ? {} : { workloads }) });
  const url = new URL(APP_URL);
  if (database !== undefined) url.pathname = `/${database}`;
  checkDatabaseUrl(url.href);
  const sent = { statements: 0, rows: 0 };
  // As `openDatabase` opens it, watched.
  const client = watched(postgresClient(url.href, { max: 10, idle_timeout: 10 }), ({ rows }) => {
    sent.statements += 1;
    sent.rows += rows;
  });
  const app = { db: createDatabase(client), close: () => client.end() };
  const calls: string[] = [];
  const inputs: unknown[] = [];
  let statements = 0;
  const executed: unknown[] = [];
  const answered: unknown[][] = [];
  const counted = new Proxy(app.db, {
    get(target, name, receiver) {
      const member = Reflect.get(target, name, receiver) as unknown;
      if (typeof member !== 'function' || !['execute', 'select', 'insert', 'update', 'delete', 'transaction'].includes(String(name))) return member;
      return (...args: unknown[]) => {
        statements += 1;
        const result = (member as (...args: unknown[]) => unknown).apply(target, args);
        if (name !== 'execute') return result;
        executed.push(args[0]);
        const at = answered.push([]) - 1;
        return (result as Promise<Iterable<unknown>>).then((rows) => {
          answered[at] = [...rows];
          return rows;
        });
      };
    },
  }) as Database;
  const recorded = new Proxy(vault, {
    get: (target, name: keyof Vault) => (input: never) => {
      calls.push(name);
      inputs.push(input);
      return (target[name] as (input: never) => unknown)(input);
    },
  });
  const config = resolveConfig({
    publicUrl: PUBLIC_URL,
    vault: recorded,
    auth,
    auditChainKey: Buffer.alloc(32, 3).toString('base64'),
  });
  const tracked: Promise<unknown>[] = [];
  const scope = requestScope(createRuntime(config, counted, recorded, { transport: transport ?? FETCHES_NOTHING, gates }), () => '192.0.2.7', (work) => tracked.push(work));
  return {
    world,
    vault,
    calls,
    inputs,
    get statements() {
      return statements;
    },
    executed,
    answered,
    tracked,
    sent,
    request(path, init) {
      const request = new Request(`${PUBLIC_URL}${path}`, init);
      return scope.respond(request, () => scope.route(request));
    },
    render(init, page) {
      return scope.respond(new Request(`${PUBLIC_URL}/projects`, init), async (context) => Response.json(await page(context)));
    },
    close: async () => void (await Promise.all([app.close(), world.close()])),
  };
}
