import { createArchive } from '../../../packages/archive/src/factory';
import { WorkerEntrypoint } from 'cloudflare:workers';
import type { Credentials, RpcResult } from '../../../packages/contracts/src/index';
import { failure } from '../../../packages/core/src/http';
import { R2AuditArchive, archivePending } from '../../../packages/archive/src/index';
import { createStorage, createVault, validateEnvironment, type VaultEnvironment } from './runtime';
export class VaultWorker extends WorkerEntrypoint<VaultEnvironment> {
  async execute(credentials: Credentials, invocation: unknown): Promise<RpcResult> {
    let storage;
    const requestId = crypto.randomUUID();
    try { validateEnvironment(this.env); storage = createStorage(this.env); const data = await createVault(this.env, storage).execute(credentials, invocation); return { ok: true, data }; }
    catch (error) { const result = failure(error, requestId); console.warn(JSON.stringify({ event: 'operation_failed', requestId, code: result.ok ? '' : result.error.code })); return result; }
    finally { await storage?.close(); }
  }
}
export default {
  fetch() { return new Response('Not found', { status: 404 }); },
  async scheduled(_event: ScheduledController, env: VaultEnvironment) {
    validateEnvironment(env); const storage = createStorage(env);
    try { const result = await archivePending(storage, createArchive(env), env.INSTANCE_ID); console.log(JSON.stringify({ event: 'audit_archive', ...result })); }
    catch { console.error(JSON.stringify({ event: 'audit_archive_failed' })); throw new Error('Audit archive failed'); }
    finally { await storage.close(); }
  },
};
