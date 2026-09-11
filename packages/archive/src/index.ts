import { canonical } from '../../crypto/src/index';
import type { Storage } from '../../contracts/src/index';
export interface AuditArchive { putIfAbsent(key: string, data: string): Promise<void> }
export class R2AuditArchive implements AuditArchive {
  constructor(private readonly bucket: R2Bucket) {}
  async putIfAbsent(key: string, data: string) {
    const object = await this.bucket.put(key, data, { onlyIf: { etagDoesNotMatch: '*' }, httpMetadata: { contentType: 'application/json' } });
    if (!object) {
      const existing = await this.bucket.get(key);
      if (!existing || await existing.text() !== data) throw new Error('Audit archive collision or corruption');
    }
  }
}
export async function archivePending(storage: Storage, archive: AuditArchive, instanceId: string, limit = 100) {
  const events = await storage.pendingArchive(limit);
  for (const event of events) {
    const key = `${instanceId}/audit/${String(event.seq).padStart(16, '0')}-${event.hash}.json`;
    await archive.putIfAbsent(key, canonical(event));
    // A failed archive write must never acknowledge the outbox entry.
    await storage.acknowledgeArchive(event);
  }
  return { archived: events.length, remaining: (await storage.pendingArchive(1)).length > 0 };
}
