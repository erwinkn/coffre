import * as schema from '@coffre/db/schema';

/** The tables, under the names schema.ts gives them. */
export const {
  projects,
  environments,
  secrets,
  secretVersions,
  vaultMembers,
  vaultGrants,
  vaultReleases,
  auditLog,
  auditChainHead,
  identities,
  credentials,
  enrollments,
  deviceAuthorizations,
  serviceBindings,
  consumedTokens,
  cappedAlerts,
  secretReferences,
  dismissedKeys,
  oauthClients,
  mcpConnections,
  mcpApprovals,
} = schema;
