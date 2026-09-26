import { guard } from './guard.ts';
import { githubActions } from './providers/github-actions.ts';
import type { SyncProvider, SyncProviderKind } from './types.ts';

export * from './types.ts';
export type { GitHubActionsConfig } from './providers/github-actions.ts';

// Every provider goes through guard(), which owns the invariants the engine
// relies on (rejected keys never sent, nothing secret in any error message).
export const providers: { [K in SyncProviderKind]: SyncProvider<any> } = {
  'github-actions': guard(githubActions),
};

export function getProvider(kind: string): SyncProvider<unknown> | null {
  return Object.hasOwn(providers, kind) ? providers[kind as SyncProviderKind] : null;
}
