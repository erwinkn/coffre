// A deployment for the Terraform provider's acceptance tests
// (terraform-provider/internal/provider/acceptance_test.go), which are Go's:
// the Workers example booted as `pnpm conformance:workers` boots it, on a
// database of its own, and seeded. It prints one line, `fixture <JSON>`,
// once it serves, and serves until its stdin closes or it is stopped.
//
//   node --conditions=coffre:source packages/conformance/scripts/terraform-fixture.ts [--port <n>]
//
// Postgres is the local one, `COFFRE_POSTGRES_PORT` (55432 unless set), with
// the logins scripts/ensure-database.mjs makes; coffre takes the port, the dev
// IdP the next and wrangler's inspector the one after.
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { boot } from '/home/erwin/.bb/plugins/environment-git-worktree/host-data/worktrees/thr_gkt2iijk8g-1/coffre/packages/conformance/src/harness.ts';
import { signInAdmin } from '/home/erwin/.bb/plugins/environment-git-worktree/host-data/worktrees/thr_gkt2iijk8g-1/coffre/packages/conformance/src/checks/people.ts';

const { values } = parseArgs({ options: { port: { type: 'string', default: '3482' } } });
const port = Number(values.port);
if (!Number.isInteger(port) || port < 1 || port > 65_533) throw new Error('--port takes a port, with the two after it free');

const local = (login: string) => `postgresql://${login}@127.0.0.1:${process.env.COFFRE_POSTGRES_PORT ?? '55432'}/postgres`;
const deployment = await boot('workers', fileURLToPath(new URL('file:///home/erwin/.bb/plugins/environment-git-worktree/host-data/worktrees/thr_gkt2iijk8g-1/coffre/examples/workers')), {
  port,
  postgres: local('coffre_owner:local-dev-only'),
  runtime: local('coffre_runtime:local-runtime-only'),
  vaultRuntime: local('coffre_vault_runtime:local-vault-only'),
});
const stopped = new Promise<void>((resolve) => {
  process.once('SIGTERM', resolve);
  process.once('SIGINT', resolve);
  process.stdin.once('end', resolve);
  process.stdin.once('close', resolve);
  process.stdin.resume();
});
try {
  const { value: admin } = await signInAdmin(deployment);
  // `tf/prod`, and `tf/staging`, a fork that inherits it: a key Terraform writes in staging over one prod passes down is an override.
  await admin.api.projects.create('tf', { name: 'Terraform' });
  await admin.api.environments.create('tf/prod', { name: 'Production' });
  await admin.api.environments.create('tf/staging', { name: 'Staging', from: 'prod', inherit: true });
  // Terraform's service account writes, reads and archives keys in tf (maintainer), by a token or a CI run's ID token.
  const service = 'token:terraform';
  await admin.api.members.add(service);
  await admin.api.access.set(service, { tf: 'maintainer' });
  const { token } = await admin.api.tokens.issue(service, { label: 'Terraform acceptance', expiresInDays: 1 });
  await admin.api.bindings.create(service, {
    profile: 'github',
    issuer: deployment.idp.workloads.issuer,
    claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' },
    label: 'Terraform acceptance',
  });
  // Someone else who writes there, outside Terraform: the drift and stale plans' other writer.
  const other = 'token:someone';
  await admin.api.members.add(other);
  await admin.api.access.set(other, { tf: 'developer' });
  const { token: otherToken } = await admin.api.tokens.issue(other, { label: 'Terraform acceptance, outside', expiresInDays: 1 });
  console.log(`fixture ${JSON.stringify({
    url: deployment.origin,
    service,
    token,
    other: { member: other, token: otherToken },
    // What GitHub's runner gives a job with `permissions: id-token: write`, played by the dev IdP.
    actions: { url: `${deployment.idp.origin}/workloads/actions`, token: deployment.idp.workloads.requestToken },
  })}`);
  await stopped;
} catch (error) {
  console.error(error);
  console.error(deployment.output(4000));
  process.exitCode = 1;
} finally {
  await deployment.stop();
}
