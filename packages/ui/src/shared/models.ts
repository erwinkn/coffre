import type {
  ImportAction,
  Me as ApiMe,
  Member,
  OffboardingReport,
  ProjectSummary as ApiProjectSummary,
  RemovedMember,
  SecretKey as ApiSecretKey,
  SecretVersion as ApiSecretVersion,
} from '@coffre/client';
import type { Permission as CorePermission } from '@coffre/core/access';

/** Browser-safe projections of what the API returns. */
export type Permission = CorePermission;
export type Me = ApiMe;
export type SecretKey = ApiSecretKey;
export type ProjectSummary = ApiProjectSummary;
export type SecretVersion = ApiSecretVersion;

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

export type DirectoryPrincipal = Pick<Member, 'principalType' | 'principalId' | 'instanceRole' | 'isRootAdmin'> &
  Partial<Pick<Member, 'tampered'>>;

export type ImportPlanEntry = { key: string; action: ImportAction; version: number | null };

/** What someone can still reach and what they have seen. */
export type PrincipalReport = OffboardingReport;
export type RemovedPrincipal = RemovedMember;

export type ImportProblem = { line: number; text: string; reason: string };
