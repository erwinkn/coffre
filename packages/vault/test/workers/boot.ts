// The vault Worker (vault-worker.ts) booted in workerd, as a deployment runs
// it: its entrypoint, its signer's Durable Object, the app's side of a call
// over the service binding. workers.test.ts and adopt-upgraded.ts boot it.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Account, Peeked, Used } from '@coffre/core/vault';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';

export type Answer = { status: number; body: Used & { refused?: string; error?: string } };
type Written = { status: number; body: { answer?: { keys: Record<string, { version: number; nature: string }>; outcomes: Record<string, unknown> }; refused?: string; error?: string } };
/** `asked`: how often the vault asked it whether the database is adopted. */
type SignerStatus = { checked: number; standing: unknown[]; adopted: boolean; adoption: { at: number; error: string } | null; asked: number };

/** The vault's keys, as its configuration names them: a local KEK, and the signing key, derived from it unless given. */
export type WorkerKeys = { id: string; key: string; signingKey?: string };

export type VaultWorker = {
  reveal(bearer: string, path: string, keys: string[] | null): Promise<Answer>;
  peek(bearer: string, path: string, keys: string[] | null): Promise<{ status: number; body: Peeked }>;
  write(bearer: string, path: string, values: Record<string, string>): Promise<Written>;
  /** A sign-in, as the app makes one once it has verified the account: a browser session whose token is `bearer`. */
  signin(account: Account, bearer: string): Promise<{ status: number; body: { answer?: { principal: string }; refused?: string; error?: string } }>;
  /** What the signer's object says of itself (`status`). */
  status(): Promise<SignerStatus>;
  post(path: string): Promise<{ error?: string }>;
  get(path: string): Promise<unknown>;
  stop(): Promise<void>;
};

/** A fresh isolate of the vault Worker and its signer, whose storage is new, over `database` through the vault's login. */
export async function vaultWorker(database: string, keys: WorkerKeys, { signer = true } = {}): Promise<VaultWorker> {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-vault-worker-'));
  const name = 'coffre-vault-workers-test';
  writeFileSync(
    join(dir, 'wrangler.json'),
    JSON.stringify({
      name,
      compatibility_date: '2026-08-06',
      compatibility_flags: ['nodejs_compat'],
      vars: { VAULT_KEY_ID: keys.id, VAULT_KEY: keys.key, ...(keys.signingKey === undefined ? {} : { SIGNING_KEY: keys.signingKey }) },
      hyperdrive: [{ binding: 'VAULT_HYPERDRIVE', id: 'vault-workers-test', localConnectionString: database }],
      services: [{ binding: 'VAULT', service: name, entrypoint: 'Vault' }],
      // As a deployment's vault/wrangler.jsonc.
      durable_objects: { bindings: signer ? [{ name: 'SIGNER', class_name: 'CoffreSigner' }] : [] },
      migrations: [{ tag: 'signer', new_sqlite_classes: ['CoffreSigner'] }],
    }),
  );
  // Bundled from the packages' sources, as the tests read them.
  process.env.WRANGLER_BUILD_CONDITIONS = 'coffre:source,workerd,worker,browser';
  let worker: Unstable_DevWorker;
  try {
    worker = await unstable_dev(fileURLToPath(new URL('./vault-worker.ts', import.meta.url)), {
      config: join(dir, 'wrangler.json'),
      local: true, ip: '127.0.0.1', port: 0, inspectorPort: 0, persist: false, logLevel: 'error',
      experimental: { disableExperimentalWarning: true, disableDevRegistry: true },
    });
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  const call = async <T>(path: string, method: string, body: unknown, bearer?: string) => {
    const response = await worker.fetch(path, { method, headers: bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(20_000) });
    return { status: response.status, body: (await response.json()) as T };
  };
  return {
    reveal: (bearer, path, keys) => call('/reveals', 'POST', { path, keys }, bearer),
    peek: (bearer, path, keys) => call('/reveals', 'PUT', { path, keys }, bearer),
    write: (bearer, path, values) => call('/secrets', 'PATCH', { path, values }, bearer),
    signin: (account, bearer) => call('/signin', 'POST', { account }, bearer),
    status: async () => (await call<SignerStatus>('/signer', 'POST', {})).body,
    post: async (path) => (await call<{ error?: string }>(path, 'POST', {})).body,
    get: async (path) => (await worker.fetch(path, { signal: AbortSignal.timeout(20_000) })).json(),
    async stop() {
      await worker.stop();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
