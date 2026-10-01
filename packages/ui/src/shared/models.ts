import type {
  AuditEntryView,
  ImportAction,
  Me as ApiMe,
  Member,
  OffboardingReport,
  ProjectSummary as ApiProjectSummary,
  RemovedMember,
  RunOutcome as ApiRunOutcome,
  SecretKey as ApiSecretKey,
  SecretVersion as ApiSecretVersion,
  SyncView as ApiSyncView,
} from '@coffre/client';
import type { Permission as CorePermission } from '@coffre/core/access';

/** Browser-safe projections of what the API returns. */
export type Permission = CorePermission;
export type Me = ApiMe;
export type SecretKey = ApiSecretKey;
export type ProjectSummary = ApiProjectSummary;
export type SecretVersion = ApiSecretVersion;
export type SyncView = ApiSyncView;
export type RunOutcome = ApiRunOutcome;

/** One member's role at one place in a project, as the project page lists them. */
export type GrantRow = {
  id: string;
  principalType: 'user' | 'service';
  principalId: string;
  role: string;
  roleName: string;
  permissions: Permission[];
  scope: 'project' | 'environment';
  environmentSlug: string | null;
  expiresAt: string | null;
};

export type RoleRow = {
  slug: string;
  name: string;
  description: string;
  permissions: Permission[];
  /** False when the role contains a project-only permission. */
  assignableToEnvironment: boolean;
};

export type AuditRow = Pick<
  AuditEntryView,
  'seq' | 'occurredAt' | 'actorType' | 'actorId' | 'action' | 'decision' | 'project' | 'environment'
> & { subject: string };

export type DirectoryPrincipal = Pick<Member, 'principalType' | 'principalId' | 'instanceRole' | 'isRootAdmin'> &
  Partial<Pick<Member, 'tampered'>>;

export type ImportPlanEntry = { key: string; action: ImportAction; version: number | null };

/** What someone can still reach and what they have seen, with the syncs they set up. */
export type PrincipalReport = OffboardingReport;
export type RemovedPrincipal = RemovedMember;

export type ImportProblem = { line: number; text: string; reason: string };
