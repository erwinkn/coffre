import { b64, canonical, kmsRequestSchema, unb64 } from '../../../packages/crypto/src/index';
import type { KeyProvider, SecretContext, WrappedKey } from '../../../packages/contracts/src/index';
import type { AuditArchive } from '../../../packages/archive/src/index';
export class KeyBroker {
  constructor(private readonly provider: KeyProvider, private readonly journal: AuditArchive, private readonly instanceId: string) {}
  async invoke(raw: unknown, caller: string): Promise<WrappedKey | string> {
    const request = kmsRequestSchema.parse(raw);
    if (request.context.instanceId !== this.instanceId) throw new Error('Incorrect key service instance');
    let output: WrappedKey | string;
    if (request.operation === 'wrap') { const dek = unb64(request.data); try { output = await this.provider.wrap(dek, request.context); } finally { dek.fill(0); } }
    else { const dek = await this.provider.unwrap(request.key, request.context); try { output = b64(dek); } finally { dek.fill(0); } }
    const event = { id: crypto.randomUUID(), requestId: request.requestId, at: new Date().toISOString(), caller, operation: request.operation, context: request.context, keyRef: request.operation === 'unwrap' ? request.key.keyRef : (output as WrappedKey).keyRef };
    // Key material cannot be released until its separate journal write succeeds.
    await this.journal.putIfAbsent(`${this.instanceId}/key-operations/${event.id}.json`, canonical(event));
    return output;
  }
  async wrap(request: { data: string; context: SecretContext; requestId: string }) { return await this.invoke({ ...request, operation: 'wrap' }, 'service-binding') as WrappedKey; }
  async unwrap(request: { key: WrappedKey; context: SecretContext; requestId: string }) { return await this.invoke({ ...request, operation: 'unwrap' }, 'service-binding') as string; }
}
