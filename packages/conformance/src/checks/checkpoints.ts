// A holder of both log keys can chain again. Every checkpoint must still
// pin the prefix it signed, even if a later checkpoint is valid.
import { createHash, createHmac, createPrivateKey, hkdfSync, sign } from 'node:crypto';

import { using } from '../database.ts';
import { KEYS } from '../fixtures.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import type { People } from './people.ts';
import { appendOnlyLifted, entryFields, restoreRow, transaction } from './storage.ts';

/** Leave one old signature invalid, reseal the chain, and make later checkpoints valid. */
export async function earlierCheckpoint(deployment: Deployment, { admin }: People): Promise<string> {
  expect((await admin.api.audit.verify()).ok, 'the log does not verify before checkpoint tampering');
  await using(deployment.database(), (sql) => appendOnlyLifted(sql, async () => {
    const rows = await sql.query('SELECT * FROM audit_log ORDER BY seq');
    const signed = rows.filter((row) => row.author === 'vault' && row.action === 'audit.checkpoint' && row.decision === 'allow');
    expect(signed.length >= 2, 'two checkpoints are needed');
    const [head] = await sql.query('SELECT * FROM audit_chain_head');
    const seed = Buffer.from(KEYS.SIGNING_KEY, 'base64');
    const signingKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const keys = {
      app: Buffer.from(hkdfSync('sha256', Buffer.from(KEYS.AUDIT_CHAIN_KEY, 'base64'), Buffer.alloc(0), 'coffre.audit.app.v2', 32)),
      vault: Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), 'coffre.audit.vault.v2', 32)),
    };
    const hashes = new Map<bigint, string>();
    let previous = Buffer.alloc(32);
    try {
      await transaction(sql, async () => {
        for (const original of rows) {
          const row = { ...original };
          if (row.author === 'vault' && row.action === 'audit.checkpoint' && row.decision === 'allow') {
            const checkpoint = JSON.parse(String(row.metadata)) as { seq: number; hash: string; signedAt: string; signature: string };
            if (row.seq === signed[0].seq) checkpoint.signature = Buffer.alloc(64).toString('base64');
            else {
              checkpoint.hash = hashes.get(BigInt(checkpoint.seq))!;
              checkpoint.signature = sign(null, Buffer.from(`coffre.checkpoint.v3|${checkpoint.seq}|${checkpoint.hash}|${checkpoint.signedAt}`), signingKey).toString('base64');
            }
            row.metadata = JSON.stringify(checkpoint);
          }
          const fields = entryFields(row);
          row.prev_hash = previous;
          row.mac = createHmac('sha256', keys[row.author as 'app' | 'vault']).update('coffre.audit.mac.v2').update(previous).update(fields).digest();
          previous = createHash('sha256').update('coffre.audit.chain.v2').update(previous).update(fields).update(row.mac as Buffer).digest();
          row.hash = previous;
          hashes.set(BigInt(String(row.seq)), previous.toString('hex'));
          await restoreRow(sql, 'audit_log', row, 'seq');
        }
        await restoreRow(sql, 'audit_chain_head', { ...head, head_hash: previous }, 'only_row');
      });
      const result = await admin.api.audit.verify();
      expect(!result.ok && result.author === 'vault' && result.failedAtSeq === Number(signed[0].seq)
        && result.reason === 'a checkpoint the vault did not sign', 'a valid later checkpoint hid an invalid earlier one', result);
    } finally {
      await transaction(sql, async () => {
        for (const row of rows) await restoreRow(sql, 'audit_log', row, 'seq');
        await restoreRow(sql, 'audit_chain_head', head, 'only_row');
      });
      keys.app.fill(0); keys.vault.fill(0); seed.fill(0);
    }
  }));
  expect((await admin.api.audit.verify()).ok, 'restoring the signed prefixes did not restore verification');
  return 'an invalid earlier checkpoint was caught despite valid MACs and a valid later checkpoint';
}
