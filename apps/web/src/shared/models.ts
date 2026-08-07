import type {
  GrantRow as ServiceGrantRow,
  InstancePrincipalRow,
  ProjectSummary as ServiceProjectSummary,
  RoleRow as ServiceRoleRow,
} from '../server/services/admin.ts';
import type { Permission as ServicePermission } from '../server/services/permissions.ts';
import type {
  SecretKey as ServiceSecretKey,
  SecretsService,
} from '../server/services/secrets.ts';

/** Browser-safe projections whose source types stay owned by the services. */
export type Permission = ServicePermission;

export type Me = {
  principal: { type: 'user' | 'service'; id: string };
  instanceRole: 'user' | 'owner' | 'root-admin';
  isRootAdmin: boolean;
  canReadAudit: boolean;
  environments: { project: string; environment: string; permissions: Permission[] }[];
};

export type SecretKey = ServiceSecretKey;
export type ProjectSummary = ServiceProjectSummary;
export type GrantRow = ServiceGrantRow;
export type RoleRow = ServiceRoleRow;

export type AuditRow = {
  seq: number;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  decision: 'allow' | 'deny';
  subject: string;
};

export type DirectoryPrincipal = InstancePrincipalRow;

export type SecretVersion = Awaited<
  ReturnType<SecretsService['listVersions']>
>['versions'][number];

export type ImportPlanEntry = Awaited<
  ReturnType<SecretsService['importSecrets']>
>['plan'][number];

export type ImportProblem = { line: number; text: string; reason: string };
