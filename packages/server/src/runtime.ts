import { AccessIdentityVerifier, type AccessVerifierConfig, type IdentityVerifier } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ApiContext } from './api/context.ts';
import { SigninService } from './api/signin.ts';
import { WorkloadService } from './api/workloads.ts';
import type { AuthenticatedIdentity } from './auth.ts';
import type { ResolvedConfig } from './config.ts';
import type { Gates } from './gate.ts';
import { auditAlerter } from './alerts.ts';
import { actorOf } from './db/audit.ts';
import { logged } from './logged.ts';
import { watchContext, watcherOf, type WatchActor, type WatchContext, type Watcher } from './watch.ts';
import { McpService } from './mcp/service.ts';
import type { WorkloadTransport } from './workloads/transport.ts';

export type CoffreRuntime = {
  db: Database;
  /** Keys, grants and members: the vault Worker's binding, or a Node vault. */
  vault: Vault;
  chainKey: Buffer;
  /** Present in signin mode only. */
  signin: SigninService | null;
  /** Trust bindings, when sign-in turns them on. */
  workloads: WorkloadService | null;
  /** MCP clients' OAuth and their connections, when sign-in turns them on. */
  mcp: McpService | null;
  auth: ResolvedConfig['auth'];
  publicUrl: string;
  verifier: IdentityVerifier;
  /** Background work that must outlive the response, that is explicitly scheduled. */
  waitUntil: (promise: Promise<unknown>) => void;
  /** Days a value may go unchanged before it is flagged for rotation, or null for no flag. */
  rotateAfterDays: number | null;
  /** What the deployment added, in its configuration's order (`plugins.ts`). */
  plugins: ResolvedConfig['plugins'];
  /** What is known of the database's schema, for as long as the configuration lives: the isolate's, or the process's. */
  schema: { migrated: boolean };
  /**
   * Each workload's gate (gate.ts): the process's on Node, the `GATES`
   * Durable Objects on Workers. Absent on Workers without that binding,
   * where no key-bound session is taken.
   */
  gates?: Gates;
};

/**
 * What a configuration knows of its database, for as long as it lives: the
 * isolate's, or the process's. Settled values, never a pending read
 * (AGENTS.md, "What an isolate keeps").
 */
type Known = { schema: { migrated: boolean }; scopes: { sealed: boolean } };
const known = new WeakMap<ResolvedConfig, Known>();

/**
 * The application's services around a database: once per invocation on
 * Workers, whose database clients belong to one request; once per process
 * on Node.
 */
export function createRuntime(
  config: ResolvedConfig,
  db: Database,
  vault: Vault,
  /** How an issuer's discovery and keys are fetched: the runtime's own (`workloads/transport.ts`). */
  transport: WorkloadTransport,
  waitUntil: CoffreRuntime['waitUntil'] = (promise) => {
    promise.catch((error: unknown) => console.error('background task failed', logged(error)));
  },
  /** Each workload's gate: none on Workers without a `GATES` binding. */
  gates?: Gates,
): CoffreRuntime {
  let signin: SigninService | null = null;
  let workloads: WorkloadService | null = null;
  let mcp: McpService | null = null;
  let verifier: IdentityVerifier;
  const { schema, scopes } = knownOf(config);
  if (config.auth.mode === 'signin') {
    signin = new SigninService({
      db,
      chainKey: config.auditChainKey,
      vault,
      signin: config.auth.signin,
      scopes,
    });
    verifier = signin;
    const trusted = config.auth.signin.workloads;
    if (trusted !== null) {
      workloads = new WorkloadService({ db, chainKey: config.auditChainKey, vault, config: trusted, transport, signin, publicUrl: config.publicUrl });
    }
    const connected = config.auth.signin.mcp;
    if (connected !== null) {
      mcp = new McpService({ db, chainKey: config.auditChainKey, vault, config: connected, signin: config.auth.signin, publicUrl: config.publicUrl, transport });
    }
  } else {
    verifier = accessVerifier(config.auth.access);
  }
  return {
    db,
    vault,
    chainKey: config.auditChainKey,
    signin,
    workloads,
    mcp,
    auth: config.auth,
    publicUrl: config.publicUrl,
    verifier,
    waitUntil,
    schema,
    rotateAfterDays: config.rotateAfterDays,
    plugins: config.plugins,
    gates,
  };
}

function knownOf(config: ResolvedConfig): Known {
  let kept = known.get(config);
  if (kept === undefined) {
    kept = { schema: { migrated: false }, scopes: { sealed: false } };
    known.set(config, kept);
  }
  return kept;
}

/**
 * The deployment's audit watch (plugins/audit-watch.ts), if it added one:
 * its hooks, and a context for them over this runtime, in `actor`'s name
 * when given, the scheduler's otherwise.
 */
export function watchOf(runtime: CoffreRuntime): { hooks: Watcher; context: (actor?: WatchActor) => WatchContext } | null {
  const hooks = runtime.plugins.map(watcherOf).find((found) => found !== undefined);
  if (hooks === undefined) return null;
  const alert = auditAlerter(runtime);
  return {
    hooks,
    context: (actor) =>
      watchContext({ db: runtime.db, chainKey: runtime.chainKey, vault: runtime.vault, alert: (text) => alert(text, actor && actorOf(actor.actorType, actor.actorId)), actor }),
  };
}

/** What a handler gets: the runtime's stores and the request's caller. */
export function apiContext(runtime: CoffreRuntime, identity: AuthenticatedIdentity): ApiContext {
  const watch = watchOf(runtime);
  const actor: WatchActor = { actorType: identity.caller.principal.type, actorId: identity.caller.principal.id, requestId: identity.requestId, sourceIp: identity.sourceIp };
  return {
    watch: watch === null ? null : { hooks: watch.hooks, context: (asCaller) => watch.context(asCaller ? actor : undefined) },
    db: runtime.db,
    chainKey: runtime.chainKey,
    vault: runtime.vault,
    waitUntil: runtime.waitUntil,
    signin: runtime.signin,
    workloads: runtime.workloads,
    mcp: runtime.mcp,
    caller: identity.caller,
    requestId: identity.requestId,
    sourceIp: identity.sourceIp,
    credentialId: identity.credentialId,
    bindingId: identity.bindingId ?? null,
    provenance: identity.provenance,
    via: identity.via,
    personalToken: identity.personalToken,
    credentialExpiresAt: identity.credentialExpiresAt,
    rotateAfterDays: runtime.rotateAfterDays,
  };
}

const accessVerifiers = new Map<string, AccessIdentityVerifier>();

/**
 * One verifier per Access application for the isolate's lifetime. On
 * Workers the runtime is rebuilt on every invocation; the verifier holds the JWKS cache,
 * and rebuilding it with the runtime would fetch Access's keys on every
 * request.
 */
function accessVerifier(config: AccessVerifierConfig): AccessIdentityVerifier {
  const key = JSON.stringify([config.issuer, config.jwksUrl, config.audience]);
  let verifier = accessVerifiers.get(key);
  if (verifier === undefined) {
    verifier = new AccessIdentityVerifier(config);
    accessVerifiers.set(key, verifier);
  }
  return verifier;
}
