// The vault Worker as a deployment writes it: its entrypoint, its signer,
// and the binding between them. Its fetch plays the app's side of a reveal
// (POST), a peek (PUT), a write (PATCH), a sign-in (`/signin`) and `about`
// (GET /about), as the app's routes do them: the token hashed, never looked
// up, and the vault called over a service binding. `/signer` asks the signer
// how it stands.
import type { Account, Vault as Contract } from '@coffre/core/vault';

import { createDatabase } from '@coffre/db';
import { HyperdrivePool } from '@coffre/db/hyperdrive';
import { sql } from 'drizzle-orm';

import { CoffreSigner as Signer, postgres, vault } from '../../src/cloudflare.ts';
import { signerOf, type SignerNamespace } from '../../src/cloudflare-signer.ts';

/** The vault's signer, as it exports it, counting how often the vault asked whether the database is adopted. */
export class CoffreSigner extends Signer {
  #asked = 0;
  override adopt(): Promise<boolean> {
    this.#asked += 1;
    return super.adopt();
  }
  asked(): number {
    return this.#asked;
  }
}

type Env = { VAULT_HYPERDRIVE: { connectionString: string }; VAULT_KEY_ID: string; VAULT_KEY: string; SIGNING_KEY?: string; VAULT: Contract; SIGNER: SignerNamespace };

export const Vault = vault((env: Env) => ({
  database: postgres(env.VAULT_HYPERDRIVE),
  kek: { id: env.VAULT_KEY_ID, key: env.VAULT_KEY },
  ...(env.SIGNING_KEY === undefined ? {} : { signingKey: env.SIGNING_KEY }),
  owners: ['root@acme.example'],
}));

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // A query on the database inside its own transaction, as no code may make: refused at once, here in workerd too.
    if (new URL(request.url).pathname === '/query-outside-transaction') {
      const pool = new HyperdrivePool(env.VAULT_HYPERDRIVE.connectionString);
      const db = createDatabase(pool);
      try {
        await db.transaction(async () => db.execute(sql`select 1`));
        return Response.json({ error: 'the query ran' });
      } catch (error) {
        return Response.json({ error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) });
      } finally {
        await pool.end();
      }
    }
    // The vault's configuration, as GET /audit/keys asks it: no token, and nothing read.
    if (new URL(request.url).pathname === '/about') return Response.json(await env.VAULT.about());
    if (new URL(request.url).pathname === '/signer') {
      const signer = signerOf(env.SIGNER);
      return Response.json({ ...(await signer.status()), asked: await (signer as unknown as CoffreSigner).asked() });
    }
    const bearer = /^Bearer (\S+)$/.exec(request.headers.get('authorization') ?? '')?.[1];
    if (bearer === undefined) return Response.json({ refused: 'unauthenticated' }, { status: 401 });
    const { path, keys, values, account } = (await request.json()) as { path: string; keys?: string[] | null; values?: Record<string, string>; account?: Account };
    const [project, environment] = (path ?? '/').split('/') as [string, string];
    // `sha256:<hex>`: a token known by its hash alone, as a fixture of 0.14's rows knows it.
    const hash = bearer.startsWith('sha256:') ? bearer.slice('sha256:'.length) : Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bearer))).toString('hex');
    const shown = { token: hash, proof: null, request: crypto.randomUUID(), ip: request.headers.get('cf-connecting-ip') };
    try {
      const answer = account !== undefined
        ? await env.VAULT.change({ op: 'signin', request: shown.request, ip: shown.ip, account, session: { token: shown.token, minutes: 60, label: null }, replaces: null })
        : request.method === 'PATCH'
        ? await env.VAULT.change({ ...shown, op: 'secret.write', project, environment, keys: Object.entries(values!).map(([key, value]) => ({ key, value })) })
        : request.method === 'PUT'
          ? await env.VAULT.peek({ ...shown, project, environment, mine: false, keys: keys ?? null, purpose: 'reveal', upstream: null })
          : await env.VAULT.use({ ...shown, project, environment, mine: false, keys: keys ?? null, purpose: 'reveal', upstream: null });
      return Response.json(answer, { status: !('refused' in answer) ? 200 : answer.refused === 'unauthenticated' ? 401 : answer.refused === 'adopting' ? 503 : 403 });
    } catch (error) {
      // Its code too, as the app reads it on the other side of the binding (`isUnavailable`).
      const code = (error as { code?: unknown }).code;
      return Response.json({ error: error instanceof Error ? error.message : String(error), ...(typeof code === 'string' ? { code } : {}) }, { status: 500 });
    }
  },
};
