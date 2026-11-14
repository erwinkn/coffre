// The vault Worker of the load rig, as a deployment's: its entrypoint, the
// default export the app's `VAULT` binding calls, and its signer. `Control`
// is the rig's own door to the signer, on a socket of its own: tell it of an
// entry the log feeder wrote (grow.ts), and ask how far behind it is.
import { WorkerEntrypoint } from 'cloudflare:workers';

import { postgres, vault } from '@coffre/vault/cloudflare';

export { CoffreSigner } from '@coffre/vault/cloudflare';

/** The signer's binding, as the vault calls it: always the object named `signer` (cloudflare-signer.ts). */
type SignerNamespace = { idFromName(name: string): unknown; get(id: unknown): { wake(hash: Uint8Array): Promise<void>; status(): Promise<unknown> } };

type Env = { VAULT_HYPERDRIVE: { connectionString: string }; VAULT_KEY: string; MEMORY_SECONDS: string; OUTAGE_SECONDS?: string; WORKLOADS?: string; DEADLINE_MS?: string; SIGNER: SignerNamespace };

export default vault((env: Env) => {
  // The overload-bound measurement's deadline (hyperdrive.ts, bench only): none unless set.
  (globalThis as { COFFRE_BENCH_DEADLINE_MS?: number }).COFFRE_BENCH_DEADLINE_MS = Number(env.DEADLINE_MS ?? 0);
  return {
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: 'bench', key: env.VAULT_KEY },
  owners: ['root@acme.example'],
  memorySeconds: Number(env.MEMORY_SECONDS),
  // The proxy run's: workload sessions, and how long a proxied use is answered through an outage of the database.
  ...(env.WORKLOADS === '1' ? { workloads: {} } : {}),
  ...(env.OUTAGE_SECONDS === undefined ? {} : { outageSeconds: Number(env.OUTAGE_SECONDS) }),
  };
});

export class Control extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const signer = this.env.SIGNER.get(this.env.SIGNER.idFromName('signer'));
    if (url.pathname === '/wake') {
      await signer.wake(Uint8Array.from(Buffer.from(url.searchParams.get('hash')!, 'hex')));
      return Response.json({ ok: true });
    }
    if (url.pathname === '/status') return Response.json(await signer.status());
    return new Response('not found', { status: 404 });
  }
}
