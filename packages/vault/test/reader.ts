// A second process reading through a vault of its own, over the same SQLite
// file: what vault.test.ts runs beside itself. It prints how each read came out.
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { UnwrapInput } from '@coffre/core/vault';
import { openDatabase } from '@coffre/db/connect';

import { openVault, prepareVault } from '../src/vault.ts';

const { url, kek, signingKey, bulkLimit, input, reads } = JSON.parse(process.argv[2]!) as {
  url: string;
  kek: string;
  signingKey: string;
  bulkLimit: { count: number; windowMs: number };
  input: UnwrapInput;
  reads: number;
};
const { db, close } = await openDatabase(url);
const vault = openVault(
  db,
  await prepareVault({
    keks: new KekRegistry(new LocalKekProvider(Buffer.from(kek, 'base64'), 'test-kek-1')),
    rootAdmins: ['root@acme.example'],
    signingKeys: [Buffer.from(signingKey, 'base64')],
    bulkLimit,
  }),
);
const outcomes = await Promise.all(Array.from({ length: reads }, () => vault.unwrap(input)));
process.stdout.write(JSON.stringify(outcomes.map((outcome) => (outcome.ok ? 'ok' : outcome.refusal.code))));
await close();
