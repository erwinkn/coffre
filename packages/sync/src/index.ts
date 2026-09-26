import { guard } from './guard.ts';
import { cloudflareWorkers } from './providers/cloudflare-workers.ts';
import { githubActions } from './providers/github-actions.ts';
import { railway } from './providers/railway.ts';
import { vercel } from './providers/vercel.ts';
import type { SyncProvider, SyncProviderKind } from './types.ts';

export * from './types.ts';
export type { CloudflareWorkersConfig } from './providers/cloudflare-workers.ts';
export type { GitHubActionsConfig } from './providers/github-actions.ts';
export type { RailwayConfig } from './providers/railway.ts';
export type { VercelConfig, VercelTarget } from './providers/vercel.ts';

// Every provider goes through guard(), which owns the invariants the engine
// relies on (rejected keys never sent, nothing secret in any error message).
export const providers: { [K in SyncProviderKind]: SyncProvider<any> } = {
  'github-actions': guard(githubActions),
  vercel: guard(vercel),
  railway: guard(railway),
  'cloudflare-workers': guard(cloudflareWorkers),
};

export function getProvider(kind: string): SyncProvider<unknown> | null {
  return Object.hasOwn(providers, kind) ? providers[kind as SyncProviderKind] : null;
}
