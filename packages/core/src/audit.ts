import { canonical, sha256 } from '../../crypto/src/index';
import type { AuditEvent, Snapshot } from '../../contracts/src/index';
export const GENESIS_HASH = 'GENESIS';
export type EventInput = Omit<AuditEvent, 'seq' | 'prevHash' | 'hash' | 'id' | 'at'>;
export async function chainEvents(snapshot: Pick<Snapshot, 'auditSeq' | 'auditHash'>, inputs: EventInput[]): Promise<AuditEvent[]> {
  let seq = snapshot.auditSeq, prevHash = snapshot.auditHash;
  const events: AuditEvent[] = [];
  for (const input of inputs) {
    const event = { ...input, id: crypto.randomUUID(), at: new Date().toISOString(), seq: ++seq, prevHash };
    const hash = await sha256(canonical(event));
    events.push({ ...event, hash }); prevHash = hash;
  }
  return events;
}
export async function verifyChain(events: AuditEvent[], checkpoint = { seq: 0, hash: GENESIS_HASH }): Promise<{ seq: number; hash: string }> {
  let { seq, hash } = checkpoint;
  for (const event of events) {
    const { hash: actual, ...unsigned } = event;
    if (event.seq !== seq + 1 || event.prevHash !== hash || actual !== await sha256(canonical(unsigned))) throw new Error(`Invalid audit chain at sequence ${event.seq}`);
    seq = event.seq; hash = actual;
  }
  return { seq, hash };
}
