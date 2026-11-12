// The coffre the Terraform provider's acceptance tests write to
// (terraform-provider/, docs/design/terraform-provider.md, section 8): a
// deployment booted as `pnpm conformance:node` boots it, the Node example
// on a database of its own on the local Postgres (`scripts/ensure-database.mjs`
// makes its logins), on ports of its own, seeded through the API. It prints one line, `TERRAFORM_FIXTURE <json>`, with the origin and
// the credentials the tests use, and runs until its stdin closes.
//
//   node --conditions=coffre:source packages/conformance/scripts/terraform-fixture.ts examples/node --port 3482
//
// Workspace only: the package ships no `scripts/`.
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import type { CoffreClient } from '@coffre/client';

import { signInAdmin } from '../src/checks/people.ts';
import { boot } from '../src/harness.ts';
import { GITHUB_RUN } from '../src/idp/index.ts';

const { values, positionals } = parseArgs({ allowPositionals: true, options: { port: { type: 'string', default: '3482' } } });
const port = Number(values.port);
if (!Number.isInteger(port) || positionals.length !== 1) {
  console.error('usage: terraform-fixture.ts <deployment dir> [--port <n>]');
  process.exit(2);
}

/** The service account Terraform signs in as, `contributor` on more places than any credential it is given (section 8). */
const TERRAFORM = 'token:terraform-infra';
/** What each Terraform credential holds: `infra/prod` and its fork, never `market/prod`. */
const SCOPE = { 'infra/prod': 'contributor', 'infra/prod-eu': 'contributor' };

const local = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/postgres`;
const deployment = await boot('node', resolve(positionals[0]!), {
  port,
  postgres: local('coffre_owner:local-dev-only'),
  runtime: local('coffre_runtime:local-runtime-only'),
  vaultRuntime: local('coffre_vault_runtime:local-vault-only'),
  hotRuntime: local('coffre_vault_hot:local-hot-only'),
});
let stopping = false;
const stop = async () => {
  if (stopping) return;
  stopping = true;
  await deployment.stop();
  process.exit(0);
};
process.on('SIGTERM', () => void stop());
process.on('SIGINT', () => void stop());

try {
  const admin = (await signInAdmin(deployment)).value;
  const fixture = await seed(admin.api, deployment.idp.workloads.issuer);
  const ownerCookie = admin.browser.cookies().map(([name, value]) => `${name}=${value}`).join('; ');
  console.log(`TERRAFORM_FIXTURE ${JSON.stringify({
    origin: deployment.origin,
    owner: { cookie: ownerCookie, email: admin.email },
    ...fixture,
    workloads: {
      service: TERRAFORM.slice('token:'.length),
      // A GitHub job's ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN, as the dev IdP answers them.
      requestUrl: deployment.idp.workloads.requestUrl,
      requestToken: deployment.idp.workloads.requestToken,
      // `POST` with `aud=<origin>`: an ID token of the same run, for the provider's id_token.
      mintUrl: `${deployment.idp.workloads.issuer}/token`,
    },
  })}`);
} catch (error) {
  console.error(`the fixture did not seed: ${error instanceof Error ? error.stack : String(error)}\n${deployment.output(4000)}`);
  await deployment.stop();
  process.exit(1);
}
process.stdin.resume();
process.stdin.on('end', () => void stop());
process.stdin.on('close', () => void stop());

async function seed(api: CoffreClient, issuer: string) {
  await api.projects.create('infra', { name: 'Infra' });
  await api.projects.create('market', { name: 'Market' });
  await api.environments.create('infra/prod', { name: 'Production' });
  await api.environments.create('market/prod', { name: 'Production' });
  await api.environments.create('infra/prod-eu', { from: 'prod', inherit: true });

  const issue = async (member: string, scope: Record<string, string>) => {
    const issued = await api.tokens.issue(member, { expiresInDays: 1, scope, label: 'terraform acceptance' });
    if (!('token' in issued)) throw new Error(`no token issued for ${member}`);
    return issued.token;
  };

  await api.members.add(TERRAFORM);
  await api.access.set(TERRAFORM, { ...SCOPE, 'market/prod': 'contributor' });
  // GitHub's claims for a push of deploy.yml to main of acme/api, as the dev IdP mints them.
  await api.bindings.create(TERRAFORM, {
    profile: 'github',
    issuer,
    claims: {
      repository_owner_id: GITHUB_RUN.repository_owner_id,
      repository_id: GITHUB_RUN.repository_id,
      workflow_ref: GITHUB_RUN.workflow_ref,
      ref: GITHUB_RUN.ref,
      event_name: GITHUB_RUN.event_name,
    },
    scope: SCOPE,
    label: 'terraform acceptance',
  });

  // Who writes by hand, beside Terraform; who reads a value back to check it (issued by the instance's Owner, R32).
  for (const member of ['token:rotator', 'token:verifier']) await api.members.add(member);
  await api.access.set('token:rotator', SCOPE);
  await api.access.set('token:verifier', { 'infra/prod': 'viewer', 'infra/prod-eu': 'viewer' });

  // A role an Owner makes on purpose for archiving (section 6), on an account of its own.
  const archiver = { name: 'Terraform archiver', description: 'Writes, uses and archives keys', permissions: ['secret.use', 'secret.write', 'secret.archive'] as const, protected: [] };
  const preview = await api.roles.preview('terraform-archiver', { ...archiver, permissions: [...archiver.permissions] });
  await api.roles.set('terraform-archiver', { ...archiver, permissions: [...archiver.permissions] }, { revision: preview.revision });
  await api.members.add('token:terraform-archive');
  await api.access.set('token:terraform-archive', { 'infra/prod': 'terraform-archiver', 'infra/prod-eu': 'terraform-archiver' });

  return {
    tokens: {
      terraform: await issue(TERRAFORM, SCOPE),
      fork: await issue(TERRAFORM, { 'infra/prod-eu': 'contributor' }),
      hand: await issue('token:rotator', SCOPE),
      verifier: await issue('token:verifier', { 'infra/prod': 'viewer', 'infra/prod-eu': 'viewer' }),
      archiver: await issue('token:terraform-archive', { 'infra/prod': 'terraform-archiver', 'infra/prod-eu': 'terraform-archiver' }),
    },
  };
}
