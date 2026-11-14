// The signer's Durable Object in workerd, as the vault Worker exports it,
// with a fetch that calls it as the vault does, through its binding.
import { postgres } from '@coffre/db/hyperdrive';

import { signerObject, signerOf, type SignerNamespace } from '../../src/cloudflare-signer.ts';
import { storeOf } from '../../src/signer-host.ts';

type Env = { HYPERDRIVE: { connectionString: string }; SIGNING_KEY: string; ALERT_URL: string; SIGNER: SignerNamespace };

export class CoffreSigner extends signerObject((env: Env) => ({
  database: postgres(env.HYPERDRIVE),
  signingKeys: [Buffer.from(env.SIGNING_KEY, 'base64')],
  keepUsesDays: 90,
  // A deployment's own: a webhook.
  alert: async (alert) => {
    const response = await fetch(env.ALERT_URL, { method: 'POST', body: JSON.stringify(alert) });
    if (!response.ok) throw new Error(`the alert was answered ${response.status}`);
  },
})) {
  /**
   * A step's changes on the object's own storage, one of which it cannot
   * store (a function has no clone): what is kept after, of the keys the
   * step set and the one it removed. Under keys the signer reads past.
   */
  async refusedStep(): Promise<unknown> {
    const store = storeOf(this.ctx.storage);
    await store.write(new Map([['probe was', 1]]));
    const refused = await store.write(new Map<string, unknown>([['probe was', undefined], ['probe new', 2], ['probe never', () => {}]])).then(() => false, () => true);
    const kept = await store.read();
    await store.write(new Map([['probe was', undefined]]));
    return { refused, was: kept.get('probe was') ?? null, new: kept.get('probe new') ?? null };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { method, hash } = (await request.json()) as { method: 'wake' | 'status' | 'refusedStep'; hash?: string };
    try {
      const signer = signerOf(env.SIGNER);
      if (method === 'status') return Response.json({ ok: true, result: await signer.status() });
      if (method === 'refusedStep') return Response.json({ ok: true, result: await (signer as unknown as CoffreSigner).refusedStep() });
      await signer.wake(Buffer.from(hash!, 'hex'));
      return Response.json({ ok: true });
    } catch (error) {
      return Response.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, { status: 500 });
    }
  },
};
