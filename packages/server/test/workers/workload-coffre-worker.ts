// coffre on Workers as a deployment runs it for its workloads: the app's
// `createCoffre(…)` with the credential proxy, its `Workload` entrypoint
// (docs/design/workload-access.md, section 9.2) and the vault as an
// entrypoint of the same Worker, each over Hyperdrive to the suite's
// database. Another Worker of the harness binds `CoffreWorkload` with props
// (workload-caller-worker.ts), as an app Worker of the account would.
import { github, signin } from '@coffre/core/identity';
import { postgres as vaultDatabase, vault } from '@coffre/vault/cloudflare';

import { createCoffre, postgres, type Vault as VaultBinding } from '../../src/cloudflare.ts';
import { credentialProxy, header, privateKey, sigv4 } from '../../src/plugins/credential-proxy.ts';

type Env = {
  HYPERDRIVE: { connectionString: string };
  VAULT_HYPERDRIVE: { connectionString: string };
  APP_KEY: string;
  VAULT_KEY: string;
  /** The suite's upstream, on loopback: where `echo` forwards. */
  UPSTREAM: string;
  VAULT: VaultBinding;
};

export const Vault = vault((env: Env) => ({
  database: vaultDatabase(env.VAULT_HYPERDRIVE as never),
  kek: { id: 'test-kek-1', key: env.VAULT_KEY },
  owners: ['admin@acme.example'],
}));

const coffre = createCoffre((env: Env) => ({
  publicUrl: 'https://secrets.acme.example',
  database: postgres(env.HYPERDRIVE as never),
  vault: env.VAULT,
  auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] }),
  auditChainKey: env.APP_KEY,
  plugins: [
    credentialProxy({
      credentials: {
        echo: { upstream: env.UPSTREAM, inject: header('authorization', 'Bearer {ECHO_KEY}') },
        s3: { upstream: 'https://s3.eu-west-3.amazonaws.com', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
      },
      signers: { 'dfns-key': privateKey('DFNS_PRIVATE_KEY') },
      insecureUpstreams: true,
    }),
  ],
}));

export default {
  fetch: () => new Response('coffre answers its workloads through CoffreWorkload', { status: 404 }),
};

export const CoffreWorkload = coffre.Workload;
