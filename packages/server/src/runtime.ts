import { deriveKey } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ResolvedConfig } from './config.ts';
import type { Gates } from './gate.ts';
import type { WorkloadTransport } from './workloads/transport.ts';

/**
 * What a request is served with (docs/design/0.16.md, "The server"): the
 * app's database, for what its pages list, the vault, which decides every
 * use and change, and what the deployment's configuration says.
 */
export type CoffreRuntime = {
  db: Database;
  /** The vault Worker's binding, or a Node vault. */
  vault: Vault;
  auth: ResolvedConfig['auth'];
  publicUrl: string;
  rotateAfterDays: ResolvedConfig['rotateAfterDays'];
  /** What is known of the database's schema, for as long as the configuration lives: the isolate's, or the process's. */
  schema: { migrated: boolean };
  /**
   * The key a sign-in's pending state is sealed under, in its cookie while
   * the browser is at the provider: derived from the app key, 0.14's to the
   * byte, so a sign-in started before an upgrade finishes after it.
   */
  signinKey: Buffer;
  /**
   * How the app asks an issuer for its discovery document and its keys, for
   * a binding made and a CI run's token (`workloads/transport.ts`): the
   * public `fetch` on Workers.
   */
  transport: WorkloadTransport;
  /**
   * Each service's workload gate, which holds a session's proof to its
   * nonce and takes it once (`sessions.ts`): a Durable Object per service on
   * Workers, an object in the process on Node. Null for a deployment that
   * runs none, which takes no workload session.
   */
  gates: Gates | null;
};

/**
 * What a configuration knows of its database, for as long as it lives.
 * Settled values, never a pending read (AGENTS.md, "What an isolate keeps").
 */
const known = new WeakMap<ResolvedConfig, Pick<CoffreRuntime, 'schema' | 'signinKey'>>();

/**
 * The app around a database: once per invocation on Workers, whose
 * database clients belong to one request; once per process on Node.
 */
export function createRuntime(config: ResolvedConfig, db: Database, vault: Vault, platform: Pick<CoffreRuntime, 'transport' | 'gates'>): CoffreRuntime {
  let kept = known.get(config);
  if (kept === undefined) known.set(config, (kept = { schema: { migrated: false }, signinKey: deriveKey(config.auditChainKey, 'signin-state/v1') }));
  return { db, vault, auth: config.auth, publicUrl: config.publicUrl, rotateAfterDays: config.rotateAfterDays, transport: platform.transport, gates: platform.gates, ...kept };
}
