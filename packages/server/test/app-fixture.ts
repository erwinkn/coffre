// The app on the 0.16 contract, in process, for the server's tests: the
// real vault over the suite's database, through JSON as over any transport,
// and the app's own login for what its pages list. `calls` and `statements`
// say what one request cost.
import { github, signin } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import { APP_URL, openConfiguredVault, type TestVault } from '@coffre/vault/testing';

import type { PageContext } from '../src/app.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime } from '../src/runtime.ts';
import { requestScope } from '../src/scope.ts';

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
  /** How many statements the app ran on its own connection. */
  readonly statements: number;
  /** A request, as a deployment's Start app answers one: coffre's middleware around coffre's route. */
  request(path: string, init?: RequestInit): Promise<Response>;
  /** A page's render for a request, with what coffre hands it. */
  render<T>(init: RequestInit, page: (context: PageContext) => Promise<T>): Promise<Response>;
  close(): Promise<void>;
};

/** `database`: another than the suite's, by name, for the app's own connection. */
export async function openApp({ database }: { database?: string } = {}): Promise<TestApp> {
  const { world, vault } = await openConfiguredVault({ kek: { id: 'app-test', key: Buffer.alloc(32, 9).toString('base64') }, owners: ['root@acme.example'] });
  const url = new URL(APP_URL);
  if (database !== undefined) url.pathname = `/${database}`;
  const app = await openDatabase(url.href);
  const calls: string[] = [];
  let statements = 0;
  const counted = new Proxy(app.db, {
    get(target, name, receiver) {
      const member = Reflect.get(target, name, receiver) as unknown;
      if (typeof member !== 'function' || !['execute', 'select', 'insert', 'update', 'delete', 'transaction'].includes(String(name))) return member;
      return (...args: unknown[]) => {
        statements += 1;
        return (member as (...args: unknown[]) => unknown).apply(target, args);
      };
    },
  }) as Database;
  const recorded = new Proxy(vault, {
    get: (target, name: keyof Vault) => (input: never) => {
      calls.push(name);
      return (target[name] as (input: never) => unknown)(input);
    },
  });
  const config = resolveConfig({
    publicUrl: PUBLIC_URL,
    vault: recorded,
    auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
    auditChainKey: Buffer.alloc(32, 3).toString('base64'),
  });
  const scope = requestScope(createRuntime(config, counted, recorded), () => '192.0.2.7');
  return {
    world,
    vault,
    calls,
    get statements() {
      return statements;
    },
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
