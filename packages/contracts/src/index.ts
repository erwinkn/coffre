import { z } from 'zod';

export const permissions = ['secret.list', 'secret.read', 'secret.write', 'secret.archive', 'project.manage', 'environment.manage', 'grant.manage', 'principal.manage', 'audit.read'] as const;
export type Permission = (typeof permissions)[number];
export const roles = {
  reader: ['secret.list', 'secret.read'],
  developer: ['secret.list', 'secret.read', 'secret.write'],
  maintainer: ['secret.list', 'secret.read', 'secret.write', 'secret.archive', 'environment.manage'],
  auditor: ['secret.list', 'audit.read'],
  owner: [...permissions],
} satisfies Record<string, Permission[]>;
const id = z.string().uuid();
const text = (max: number) => z.string().max(max).refine(v => !v.includes('\0'), 'NUL is not allowed');
const name = text(120).min(1);
const key = z.string().max(120).regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const value = text(65536).refine(v => new TextEncoder().encode(v).length <= 65536, 'Value exceeds 64 KiB');
const revision = z.number().int().positive();
const scopeSchema = z.object({ type: z.enum(['instance', 'project', 'environment']), id }).strict();
export type Scope = z.infer<typeof scopeSchema>;
const metadata = { key, note: text(1000).default(''), tag: text(80).default('Application'), category: z.enum(['Credential', 'Config']).default('Credential') };
export const commandSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('workspace.get') }).strict(),
  z.object({ type: z.literal('project.create'), name, description: text(1000).default('') }).strict(),
  z.object({ type: z.literal('project.update'), id, name, description: text(1000), archived: z.boolean() }).strict(),
  z.object({ type: z.literal('environment.create'), projectId: id, name, protected: z.boolean().default(false) }).strict(),
  z.object({ type: z.literal('environment.update'), id, name, protected: z.boolean(), archived: z.boolean() }).strict(),
  z.object({ type: z.literal('secret.list'), envId: id }).strict(),
  z.object({ type: z.literal('secret.create'), envId: id, ...metadata, value, confirmed: z.boolean().default(false) }).strict(),
  z.object({ type: z.literal('secret.read'), id, version: revision.optional(), purpose: z.enum(['reveal', 'edit', 'copy', 'cli']).default('reveal') }).strict(),
  z.object({ type: z.literal('secret.write'), id, expectedVersion: revision, value, confirmed: z.boolean().default(false) }).strict(),
  z.object({ type: z.literal('secret.metadata'), id, expectedRevision: revision, ...metadata }).strict(),
  z.object({ type: z.literal('secret.archive'), id, expectedRevision: revision, archived: z.boolean(), confirmed: z.boolean().default(false) }).strict(),
  z.object({ type: z.literal('secret.history'), id }).strict(),
  z.object({ type: z.literal('secret.restore'), id, version: revision, expectedVersion: revision, confirmed: z.boolean().default(false) }).strict(),
  z.object({ type: z.literal('environment.export'), envId: id }).strict(),
  z.object({ type: z.literal('audit.list'), before: revision.optional(), limit: z.number().int().min(1).max(200).default(50) }).strict(),
  z.object({ type: z.literal('principal.add'), subject: text(256).min(1), kind: z.enum(['human', 'access-service']), name }).strict(),
  z.object({ type: z.literal('principal.disable'), id, disabled: z.boolean() }).strict(),
  z.object({ type: z.literal('machine.create'), name, expiresAt: z.string().datetime() }).strict(),
  z.object({ type: z.literal('grant.put'), id: id.optional(), principalId: id, scope: scopeSchema, permissions: z.array(z.enum(permissions)).min(1), expiresAt: z.string().datetime().nullable().default(null) }).strict(),
  z.object({ type: z.literal('grant.revoke'), id }).strict(),
]);
export const invocationSchema = z.object({ requestId: id, command: commandSchema }).strict();
export type Command = z.infer<typeof commandSchema>;
export type Invocation = z.infer<typeof invocationSchema>;
export interface Credentials { accessJwt?: string; bearer?: string }
export interface Project { id: string; name: string; description: string; archived: boolean }
export interface Environment { id: string; projectId: string; name: string; protected: boolean; archived: boolean }
export interface Secret { id: string; envId: string; key: string; note: string; tag: string; category: 'Credential' | 'Config'; currentVersion: number; revision: number; archived: boolean; updatedAt: string; updatedBy: string }
export interface Principal { id: string; subject: string; kind: 'human' | 'access-service' | 'token'; name: string; disabled: boolean; expiresAt: string | null; tokenHash: string | null }
export type PublicPrincipal = Omit<Principal, 'tokenHash'>;
export interface Grant { id: string; principalId: string; scope: Scope; permissions: Permission[]; expiresAt: string | null }
export interface SecretContext { instanceId: string; projectId: string; envId: string; secretId: string; version: number }
export interface WrappedKey { keyRef: string; nonce?: string; data: string }
export interface Envelope { format: 1; algorithm: 'AES-256-GCM'; nonce: string; ciphertext: string; wrappedKey: WrappedKey }
export interface SecretVersion { secretId: string; version: number; envelope: Envelope; createdAt: string; createdBy: string }
export interface AuditEvent { seq: number; id: string; at: string; requestId: string; actorId: string | null; action: string; resourceId: string | null; projectId: string | null; envId: string | null; outcome: 'allowed' | 'denied'; detail: Record<string, string | number | boolean | string[]>; prevHash: string; hash: string }
export interface Receipt { requestId: string; actorId: string; fingerprint: string; scope: Scope; permission: Permission; oneTime?: boolean; result: unknown }
export interface Snapshot { instanceId: string; revision: number; auditSeq: number; auditHash: string; projects: Project[]; environments: Environment[]; secrets: Secret[]; principals: Principal[]; grants: Grant[]; versions: SecretVersion[]; events: AuditEvent[]; receipt: Receipt | null }
export type Mutation = { table: 'projects'; record: Project } | { table: 'environments'; record: Environment } | { table: 'secrets'; record: Secret } | { table: 'principals'; record: Principal } | { table: 'grants'; record: Grant } | { table: 'versions'; record: SecretVersion } | { table: 'revokeGrant'; id: string };
export interface CommitPlan { snapshot: Pick<Snapshot, 'revision' | 'auditSeq' | 'auditHash'>; events: AuditEvent[]; mutations: Mutation[]; receipt?: Receipt }
export interface StorageCapabilities { engine: 'postgres' | 'mysql' | 'd1'; databaseEnforcedAppendOnly: boolean }
export interface Storage {
  capabilities(): Promise<StorageCapabilities>;
  snapshot(command: Command, requestId: string): Promise<Snapshot>;
  commit(plan: CommitPlan): Promise<void>;
  pendingArchive(limit: number): Promise<AuditEvent[]>;
  acknowledgeArchive(event: AuditEvent): Promise<void>;
  close(): Promise<void>;
}
export type Identity = { kind: 'human' | 'access-service'; subject: string } | { kind: 'token'; id: string; digest: string };
export interface Authenticator { verify(credentials: Credentials): Promise<Identity> }
export interface KeyProvider { wrap(dek: Uint8Array, context: SecretContext): Promise<WrappedKey>; unwrap(key: WrappedKey, context: SecretContext): Promise<Uint8Array> }
export class VaultError extends Error {
  constructor(public readonly code: 'UNAUTHENTICATED' | 'FORBIDDEN' | 'NOT_FOUND' | 'CONFLICT' | 'INVALID' | 'PROTECTED' | 'UNAVAILABLE', message: string) { super(message); this.name = 'VaultError'; }
}
export class RetryConflict extends Error {}
export type RpcResult = { ok: true; data: unknown } | { ok: false; error: { code: string; message: string; requestId: string } };
export interface VaultBinding { execute(credentials: Credentials, invocation: unknown): Promise<RpcResult> }
