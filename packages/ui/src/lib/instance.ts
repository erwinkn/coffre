import type { InstanceState } from '@coffre/client';

/** Where an owner reads how to upgrade: update the CLI, deploy, then migrate. */
export const UPGRADE_DOC = 'https://github.com/erwinkn/coffre/blob/main/docs/deploy.md#upgrading';

/**
 * The migrations this instance's code ships and its database lacks. Only
 * owners and root admins are told an instance's state; for anyone else it
 * is null, and nothing is pending as far as they can tell.
 */
export function pendingMigrations(instance: InstanceState | null): string[] {
  return instance === null ? [] : instance.migrations.known.slice(instance.migrations.applied);
}
