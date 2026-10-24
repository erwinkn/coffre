// coffre on Workers as a deployment runs it for its workloads: the app's
// `createCoffre(…)`, its `Workload` entrypoint (docs/design/workload-access.md,
// section 9.2) and the vault as an entrypoint of the same Worker, each over
// Hyperdrive to the suite's database. Another Worker of the harness binds
// `CoffreWorkload` with props (workload-caller-worker.ts), as an app Worker
// of the account would.
//
// Until the proxy takes a workload caller (PR 1d), a probe answers `/use`
// as it will: who the call is, from `workload`, and with `?key=`, the value
// `use` opens for it.
import { github, signin } from '@coffre/core/identity';
import { postgres as vaultDatabase, vault } from '@coffre/vault/cloudflare';

import { createCoffre, postgres, type PluginContext, type Vault as VaultBinding } from '../../src/cloudflare.ts';
import { WorkloadRefused } from '../../src/plugins.ts';

type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT_HYPERDRIVE: { connectionString: string };
  APP_KEY: string;
  VAULT_KEY: string;
  VAULT: VaultBinding;
};

export const Vault = vault((env: Env) => ({
  database: vaultDatabase(env.VAULT_HYPERDRIVE as never),
  kek: { id: 'test-kek-1', key: env.VAULT_KEY },
  owners: ['admin@acme.example'],
}));

const unlimited = { limit: async () => ({ success: true }) };

const probe = {
  name: 'probe',
  routes: {
    prefix: '/use',
    fetch: async (request: Request, coffre: PluginContext) => {
      const url = new URL(request.url);
      try {
        const caller = await coffre.workload(request, { place: null, credential: url.searchParams.get('credential') });
        if (caller === null) return Response.json({ caller: null });
        const key = url.searchParams.get('key');
        const used = key === null ? null : await coffre.use(caller, { path: 'market/prod', keys: [key], purpose: 'use', logged: { credential: 'probe' } });
        const body = request.method === 'POST' ? await request.json() : null;
        return Response.json({ caller: { principal: caller.principal, credentialId: caller.credentialId, profile: caller.profile, hdr: caller.hdr, sourceIp: caller.sourceIp }, value: used?.values[key!] ?? null, body });
      } catch (error) {
        if (error instanceof WorkloadRefused) return error.response;
        throw error;
      }
    },
  },
};

const coffre = createCoffre((env: Env) => ({
  publicUrl: 'https://secrets.acme.example',
  database: postgres(env.HYPERDRIVE as never),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], workloads: { limits: { perSource: unlimited, total: unlimited } } }),
  auditChainKey: env.APP_KEY,
  plugins: [probe],
}));

export default {
  fetch: () => new Response('coffre answers its workloads through CoffreWorkload', { status: 404 }),
};

export const CoffreWorkload = coffre.Workload;
