import { AccessIdentityVerifier, type AccessVerifierConfig, type IdentityVerifier } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';
import type { Database } from '@coffre/db';

import type { ApiContext } from './api/context.ts';
import { SigninService } from './api/signin.ts';
import { WorkloadService } from './api/workloads.ts';
import type { AuthenticatedIdentity } from './auth.ts';
import type { ResolvedConfig } from './config.ts';
import { logged } from './logged.ts';
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
  auth: ResolvedConfig['auth'];
  publicUrl: string;
  verifier: IdentityVerifier;
  /** Background work that must outlive the response, that is explicitly scheduled. */
  waitUntil: (promise: Promise<unknown>) => void;
};

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
): CoffreRuntime {
  let signin: SigninService | null = null;
  let workloads: WorkloadService | null = null;
  let verifier: IdentityVerifier;
  if (config.auth.mode === 'signin') {
    signin = new SigninService({
      db,
      chainKey: config.auditChainKey,
      vault,
      signin: config.auth.signin,
    });
    verifier = signin;
    const trusted = config.auth.signin.workloads;
    if (trusted !== null) workloads = new WorkloadService({ db, chainKey: config.auditChainKey, vault, config: trusted, transport });
  } else {
    verifier = accessVerifier(config.auth.access);
  }
  return {
    db,
    vault,
    chainKey: config.auditChainKey,
    signin,
    workloads,
    auth: config.auth,
    publicUrl: config.publicUrl,
    verifier,
    waitUntil,
  };
}

/** What a handler gets: the runtime's stores and the request's caller. */
export function apiContext(runtime: CoffreRuntime, identity: AuthenticatedIdentity): ApiContext {
  return {
    db: runtime.db,
    chainKey: runtime.chainKey,
    vault: runtime.vault,
    waitUntil: runtime.waitUntil,
    signin: runtime.signin,
    workloads: runtime.workloads,
    caller: identity.caller,
    requestId: identity.requestId,
    sourceIp: identity.sourceIp,
    credentialId: identity.credentialId,
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
