import { invocationSchema, permissions, RetryConflict, VaultError, type Authenticator, type Command, type Credentials, type Environment, type Identity, type KeyProvider, type Mutation, type Permission, type Principal, type Scope, type Secret, type SecretContext, type SecretVersion, type Snapshot, type Storage } from '../../contracts/src/index';
import { b64, fingerprint, open, random, seal, sha256 } from '../../crypto/src/index';
import { chainEvents, type EventInput } from './audit';
import { allows, requirePermission, validateScope } from './permissions';
import { sameDigest } from './auth';

interface Plan { mutations: Mutation[]; events: EventInput[]; result: unknown; scope: Scope; permission: Permission; oneTime?: boolean; receiptResult?: unknown }
export interface VaultOptions { auth: Authenticator; storage: Storage; keys: KeyProvider; requestKey: Uint8Array; bootstrapSubject?: string; requireAppendOnly?: boolean; instanceId: string }
const publicPrincipal = ({ tokenHash: _, ...principal }: Principal) => principal;
const conflict = () => { throw new VaultError('CONFLICT', 'This record changed. Reload before saving.'); };
const missing = (): never => { throw new VaultError('NOT_FOUND', 'Resource not found'); };
export class Vault {
  constructor(private readonly options: VaultOptions) { if (options.requestKey.length !== 32) throw new Error('A 256-bit request integrity key is required'); }
  async execute(credentials: Credentials, raw: unknown): Promise<unknown> {
    const parsed = invocationSchema.safeParse(raw);
    if (!parsed.success) throw new VaultError('INVALID', 'Invalid request');
    const { command, requestId } = parsed.data;
    const identity = await this.options.auth.verify(credentials);
    const capabilities = await this.options.storage.capabilities();
    if (this.options.requireAppendOnly && !capabilities.databaseEnforcedAppendOnly) throw new VaultError('UNAVAILABLE', 'Required audit database privileges are not configured');
    const digest = await fingerprint(this.options.requestKey, command);
    for (let attempt = 0; attempt < 12; attempt++) {
      const s = await this.options.storage.snapshot(command, requestId);
      if (s.instanceId !== this.options.instanceId) throw new VaultError('UNAVAILABLE', 'Instance configuration does not match the database');
      const instance: Scope = { type: 'instance', id: s.instanceId };
      try {
        if (!s.principals.length && identity.kind === 'human' && this.options.bootstrapSubject && identity.subject === this.options.bootstrapSubject) {
          const id = crypto.randomUUID();
          const principal: Principal = { id, kind: 'human', subject: identity.subject, name: 'Instance administrator', disabled: false, expiresAt: null, tokenHash: null };
          const events = await chainEvents(s, [{ actorId: id, requestId, action: 'instance.bootstrap', resourceId: s.instanceId, projectId: null, envId: null, outcome: 'allowed', detail: {} }]);
          await this.options.storage.commit({ snapshot: s, events, mutations: [{ table: 'principals', record: principal }, { table: 'grants', record: { id: crypto.randomUUID(), principalId: id, scope: instance, permissions: [...permissions], expiresAt: null } }] });
          continue;
        }
        const p = this.resolvePrincipal(s, identity);
        if (!p || p.disabled || (p.expiresAt && Date.parse(p.expiresAt) <= Date.now())) {
          await this.deny(s, requestId, command, p?.id ?? null);
          throw new VaultError('FORBIDDEN', 'Account is not enrolled or is inactive');
        }
        if (s.receipt) {
          const r = s.receipt;
          if (r.actorId !== p.id || r.fingerprint !== digest) throw new VaultError('CONFLICT', 'Request identifier was already used');
          requirePermission(s, p, r.permission, r.scope);
          if (r.oneTime) throw new VaultError('CONFLICT', 'This credential was issued once. Revoke it and create another if delivery failed.');
          return r.result;
        }
        let plan: Plan;
        try { plan = await this.plan(s, p, command, requestId); }
        catch (error) { if (error instanceof VaultError && error.code === 'FORBIDDEN') await this.deny(s, requestId, command, p.id); throw error; }
        if (!plan.events.length) return plan.result;
        const events = await chainEvents(s, plan.events);
        await this.options.storage.commit({ snapshot: s, events, mutations: plan.mutations, ...(plan.mutations.length ? { receipt: { requestId, actorId: p.id, fingerprint: digest, scope: plan.scope, permission: plan.permission, oneTime: plan.oneTime ?? false, result: plan.receiptResult ?? plan.result } } : {}) });
        return plan.result;
      } catch (error) { if (error instanceof RetryConflict) continue; throw error; }
    }
    throw new VaultError('CONFLICT', 'The vault is busy. Retry with the same request identifier.');
  }
  private resolvePrincipal(s: Snapshot, proof: Identity): Principal | undefined {
    if (proof.kind !== 'token') return s.principals.find(p => p.kind === proof.kind && p.subject === proof.subject);
    return s.principals.find(p => p.kind === 'token' && p.id === proof.id && p.tokenHash && sameDigest(p.tokenHash, proof.digest));
  }
  private async deny(s: Snapshot, requestId: string, command: Command, actorId: string | null) {
    const events = await chainEvents(s, [{ requestId, actorId, action: command.type, resourceId: 'id' in command ? command.id ?? null : null, projectId: null, envId: null, outcome: 'denied', detail: { reason: 'access_denied' } }]);
    await this.options.storage.commit({ snapshot: s, events, mutations: [] });
  }
  private async plan(s: Snapshot, p: Principal, command: Command, requestId: string): Promise<Plan> {
    const instance: Scope = { type: 'instance', id: s.instanceId };
    const result: Plan = { result: null, mutations: [], events: [], scope: instance, permission: 'secret.list' };
    const check = (permission: Permission, scope = instance) => { requirePermission(s, p, permission, scope); result.scope = scope; result.permission = permission; };
    const event = (action: string, resourceId: string | null, env: Environment | null = null, detail: EventInput['detail'] = {}) => result.events.push({ requestId, actorId: p.id, action, resourceId, projectId: env?.projectId ?? (result.scope.type === 'project' ? result.scope.id : null), envId: env?.id ?? null, outcome: 'allowed', detail });
    const environment = (id: string, includeArchived = false) => {
      const e = s.environments.find(e => e.id === id) ?? missing();
      const project = s.projects.find(x => x.id === e.projectId) ?? missing();
      if (!includeArchived && (e.archived || project.archived)) missing();
      return e;
    };
    const secret = (id: string, includeArchived = false) => { const x = s.secrets.find(x => x.id === id) ?? missing(); if (x.archived && !includeArchived) missing(); environment(x.envId); return x; };
    const envScope = (id: string): Scope => ({ type: 'environment', id });
    const context = (x: Secret, version: number): SecretContext => ({ instanceId: s.instanceId, projectId: environment(x.envId).projectId, envId: x.envId, secretId: x.id, version });
    const confirm = (e: Environment, acknowledged: boolean) => { if (e.protected && !acknowledged) throw new VaultError('PROTECTED', 'Confirm the change to this protected environment'); };
    const versionValue = async (x: Secret, version: number) => { const v = s.versions.find(v => v.secretId === x.id && v.version === version) ?? missing(); return open(v.envelope, context(x, version), this.options.keys); };
    const putVersion = async (x: Secret, value: string, version: number) => {
      const now = new Date().toISOString();
      const v: SecretVersion = { secretId: x.id, version, envelope: await seal(value, context(x, version), this.options.keys), createdAt: now, createdBy: p.id };
      const updated: Secret = { ...x, currentVersion: version, revision: x.revision + 1, updatedAt: now, updatedBy: p.id };
      result.mutations.push({ table: 'secrets', record: updated }, { table: 'versions', record: v });
      result.result = updated;
    };
    switch (command.type) {
      case 'workspace.get': {
        const readableEnvs = s.environments.filter(e => !e.archived && !s.projects.find(x => x.id === e.projectId)?.archived && permissions.some(permission => allows(s, p, permission, envScope(e.id))));
        const readableProjects = s.projects.filter(project => !project.archived && (readableEnvs.some(e => e.projectId === project.id) || permissions.some(permission => allows(s, p, permission, { type: 'project', id: project.id }))));
        result.result = { instanceId: s.instanceId, principal: publicPrincipal(p), projects: readableProjects, environments: readableEnvs.map(e => ({ ...e, permissions: permissions.filter(permission => allows(s, p, permission, envScope(e.id))) })), permissions: permissions.filter(permission => allows(s, p, permission, instance)), principals: allows(s, p, 'principal.manage', instance) ? s.principals.map(publicPrincipal) : [], grants: allows(s, p, 'grant.manage', instance) ? s.grants : s.grants.filter(g => g.principalId === p.id) };
        break;
      }
      case 'project.create': {
        check('project.manage');
        if (s.projects.some(x => x.name === command.name)) throw new VaultError('CONFLICT', 'A project with this name already exists');
        const project = { id: crypto.randomUUID(), name: command.name, description: command.description, archived: false };
        result.mutations.push({ table: 'projects', record: project }); result.result = project; event(command.type, project.id); break;
      }
      case 'project.update': {
        check('project.manage', { type: 'project', id: command.id });
        const project = s.projects.find(x => x.id === command.id) ?? missing();
        if (s.projects.some(x => x.id !== project.id && x.name === command.name)) throw new VaultError('CONFLICT', 'Project name already exists');
        const updated = { ...project, name: command.name, description: command.description, archived: command.archived };
        result.mutations.push({ table: 'projects', record: updated }); result.result = updated; event(command.type, project.id); break;
      }
      case 'environment.create': {
        const project = s.projects.find(x => x.id === command.projectId && !x.archived) ?? missing();
        check('environment.manage', { type: 'project', id: project.id });
        if (s.environments.some(e => e.projectId === project.id && e.name === command.name)) throw new VaultError('CONFLICT', 'Environment name already exists');
        const e = { id: crypto.randomUUID(), projectId: project.id, name: command.name, protected: command.protected, archived: false };
        result.mutations.push({ table: 'environments', record: e }); result.result = e; event(command.type, e.id, e); break;
      }
      case 'environment.update': {
        const e = environment(command.id, true); check('environment.manage', { type: 'project', id: e.projectId });
        if (s.environments.some(x => x.id !== e.id && x.projectId === e.projectId && x.name === command.name)) throw new VaultError('CONFLICT', 'Environment name already exists');
        const updated = { ...e, name: command.name, archived: command.archived, protected: command.protected };
        result.mutations.push({ table: 'environments', record: updated }); result.result = updated; event(command.type, e.id, e); break;
      }
      case 'secret.list': {
        environment(command.envId); check('secret.list', envScope(command.envId));
        result.result = s.secrets.filter(x => x.envId === command.envId && !x.archived).sort((a, b) => a.key.localeCompare(b.key)); break;
      }
      case 'secret.create': {
        const e = environment(command.envId); check('secret.write', envScope(e.id)); confirm(e, command.confirmed);
        if (s.secrets.some(x => x.envId === e.id && x.key === command.key)) throw new VaultError('CONFLICT', 'This key already exists, including archived keys');
        const x: Secret = { id: crypto.randomUUID(), envId: e.id, key: command.key, note: command.note, tag: command.tag, category: command.category, currentVersion: 1, revision: 0, archived: false, updatedAt: new Date().toISOString(), updatedBy: p.id };
        await putVersion(x, command.value, 1); event(command.type, x.id, e, { version: 1 }); break;
      }
      case 'secret.read': {
        const x = secret(command.id); const e = environment(x.envId); check('secret.read', envScope(e.id));
        const version = command.version ?? x.currentVersion;
        result.result = { id: x.id, version, value: await versionValue(x, version) };
        event('secret.read_authorized', x.id, e, { version, purpose: command.purpose }); break;
      }
      case 'secret.write': case 'secret.restore': {
        const x = secret(command.id); const e = environment(x.envId); check('secret.write', envScope(e.id)); confirm(e, command.confirmed);
        if (x.currentVersion !== command.expectedVersion) conflict();
        let value: string;
        if (command.type === 'secret.restore') {
          requirePermission(s, p, 'secret.read', envScope(e.id)); value = await versionValue(x, command.version);
          event('secret.read_authorized', x.id, e, { version: command.version, purpose: 'restore' });
        } else value = command.value;
        await putVersion(x, value, x.currentVersion + 1); event(command.type, x.id, e, { version: x.currentVersion + 1 }); break;
      }
      case 'secret.metadata': {
        const x = secret(command.id); const e = environment(x.envId); check('secret.write', envScope(e.id));
        if (x.revision !== command.expectedRevision) conflict();
        if (s.secrets.some(a => a.envId === e.id && a.id !== x.id && a.key === command.key)) throw new VaultError('CONFLICT', 'This key already exists');
        const updated = { ...x, key: command.key, note: command.note, tag: command.tag, category: command.category, revision: x.revision + 1, updatedAt: new Date().toISOString(), updatedBy: p.id };
        result.mutations.push({ table: 'secrets', record: updated }); result.result = updated; event(command.type, x.id, e, { fields: ['key', 'note', 'tag', 'category'] }); break;
      }
      case 'secret.archive': {
        const x = secret(command.id, true); const e = environment(x.envId); check('secret.archive', envScope(e.id)); confirm(e, command.confirmed);
        if (x.revision !== command.expectedRevision) conflict();
        const updated = { ...x, archived: command.archived, revision: x.revision + 1, updatedAt: new Date().toISOString(), updatedBy: p.id };
        result.mutations.push({ table: 'secrets', record: updated }); result.result = updated; event(command.type, x.id, e, { archived: command.archived }); break;
      }
      case 'secret.history': {
        const x = secret(command.id); check('secret.list', envScope(x.envId));
        result.result = s.versions.filter(v => v.secretId === x.id).map(({ envelope: _, ...v }) => v); break;
      }
      case 'environment.export': {
        const e = environment(command.envId); check('secret.read', envScope(e.id));
        const list = s.secrets.filter(x => x.envId === e.id && !x.archived);
        if (list.length > 100) throw new VaultError('INVALID', 'Exports are limited to 100 values per request in this release');
        const values = [];
        for (const x of list) { values.push({ key: x.key, value: await versionValue(x, x.currentVersion), version: x.currentVersion }); event('secret.read_authorized', x.id, e, { version: x.currentVersion, purpose: 'export' }); }
        // Empty exports still record the operation.
        if (!list.length) event(command.type, e.id, e, { count: 0 });
        result.result = { envId: e.id, values }; break;
      }
      case 'audit.list': {
        const anyAudit = s.grants.some(g => g.principalId === p.id && g.permissions.includes('audit.read') && (!g.expiresAt || Date.parse(g.expiresAt) > Date.now()));
        if (!anyAudit) throw new VaultError('FORBIDDEN', 'You do not have access to the audit log');
        result.result = { events: s.events.filter(e => allows(s, p, 'audit.read', e.envId ? envScope(e.envId) : e.projectId ? { type: 'project', id: e.projectId } : instance)), nextBefore: s.events.length === command.limit ? s.events.at(-1)!.seq : null, head: allows(s, p, 'audit.read', instance) ? { seq: s.auditSeq, hash: s.auditHash } : null }; break;
      }
      case 'principal.add': {
        check('principal.manage');
        if (s.principals.some(x => x.kind === command.kind && x.subject === command.subject)) throw new VaultError('CONFLICT', 'Principal already exists');
        const principal: Principal = { id: crypto.randomUUID(), kind: command.kind, subject: command.subject, name: command.name, disabled: false, tokenHash: null, expiresAt: null };
        result.mutations.push({ table: 'principals', record: principal }); result.result = publicPrincipal(principal); event(command.type, principal.id); break;
      }
      case 'principal.disable': {
        check('principal.manage'); const target = s.principals.find(x => x.id === command.id) ?? missing();
        if (target.id === p.id) throw new VaultError('INVALID', 'You cannot disable your own account');
        const updated = { ...target, disabled: command.disabled };
        result.mutations.push({ table: 'principals', record: updated }); result.result = publicPrincipal(updated); event(command.type, target.id, null, { disabled: command.disabled }); break;
      }
      case 'machine.create': {
        check('principal.manage');
        if (Date.parse(command.expiresAt) <= Date.now() || Date.parse(command.expiresAt) > Date.now() + 366 * 86400000) throw new VaultError('INVALID', 'Expiry must be in the next year');
        const id = crypto.randomUUID(); const token = `coffre_${id}.${b64(random(32))}`;
        const principal: Principal = { id, kind: 'token', subject: id, name: command.name, disabled: false, expiresAt: command.expiresAt, tokenHash: await sha256(token) };
        result.mutations.push({ table: 'principals', record: principal }); result.result = { principal: publicPrincipal(principal), token }; result.receiptResult = { principal: publicPrincipal(principal) }; result.oneTime = true; event(command.type, id); break;
      }
      case 'grant.put': {
        validateScope(s, command.scope); check('grant.manage', command.scope);
        const target = s.principals.find(x => x.id === command.principalId && !x.disabled) ?? missing();
        if (target.id === p.id) throw new VaultError('FORBIDDEN', 'Self-granting is not permitted');
        for (const permission of command.permissions) requirePermission(s, p, permission, command.scope);
        if (command.scope.type === 'environment' && command.permissions.some(x => ['project.manage', 'environment.manage', 'principal.manage'].includes(x))) throw new VaultError('INVALID', 'Project management cannot be scoped to one environment');
        if (command.permissions.includes('principal.manage') && command.scope.type !== 'instance') throw new VaultError('INVALID', 'Principal management is instance-scoped');
        if (command.expiresAt && Date.parse(command.expiresAt) <= Date.now()) throw new VaultError('INVALID', 'Grant expiry must be in the future');
        if (command.id) { const existing = s.grants.find(g => g.id === command.id) ?? missing(); requirePermission(s, p, 'grant.manage', existing.scope); if (existing.principalId === p.id) throw new VaultError('FORBIDDEN', 'Self-granting is not permitted'); }
        const grant = { id: command.id ?? crypto.randomUUID(), principalId: target.id, scope: command.scope, permissions: [...new Set(command.permissions)], expiresAt: command.expiresAt };
        result.mutations.push({ table: 'grants', record: grant }); result.result = grant; event(command.type, grant.id); break;
      }
      case 'grant.revoke': {
        const grant = s.grants.find(g => g.id === command.id) ?? missing(); check('grant.manage', grant.scope);
        if (grant.principalId === p.id) throw new VaultError('INVALID', 'You cannot revoke your own grants');
        result.mutations.push({ table: 'revokeGrant', id: grant.id }); result.result = { revoked: true }; event(command.type, grant.id); break;
      }
    }
    return result;
  }
}
