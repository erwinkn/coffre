// coffre-conformance: check a coffre deployment from outside, for what it
// must never do whatever code it runs. It boots the deployment itself, as
// `coffre init` made it or however it was changed since, signs people in
// through a stand-in GitHub, and takes them through the checks.
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { end } from './end.ts';
import { boot, type Kind } from './harness.ts';
import { Failure } from './report.ts';
import { conform } from './suite.ts';

const USAGE = `usage:
  coffre-conformance workers|node [<dir>] --postgres <owner URL> --runtime <coffre_runtime URL>
                    --vault-runtime <coffre_vault_runtime URL> --hot-runtime <coffre_vault_hot URL> [options]

  <dir>             the deployment, as \`coffre init\` wrote it (default: here)
  --port <n>        coffre's port; the IdP gets the next, wrangler's inspector the one after (3082)
  --bulk-limit <n>  the vault's bulkLimit count, when not the default (1000)
  --browser <path>  Chrome or Chromium, to load the pages in (default: one found here;
                    without one, that check is skipped)
  --postgres <url>  a Postgres login that may create databases; one is made for the run
  --runtime <url>   the same server as coffre_runtime, the login the app runs as
  --vault-runtime <url>
                    the same server as coffre_vault_runtime, the login the vault runs as
  --hot-runtime <url>
                    the same server as coffre_vault_hot, the login 0.15's uses run as

To check an instance that is running already, from outside, use the CLI:
\`coffre verify instance\`.`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    port: { type: 'string', default: '3082' },
    'bulk-limit': { type: 'string', default: '1000' },
    browser: { type: 'string' },
    postgres: { type: 'string' },
    runtime: { type: 'string' },
    'vault-runtime': { type: 'string' },
    'hot-runtime': { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});
const [command, target] = positionals;
const { code, message } = await run();
await end(code, message);

async function run(): Promise<{ code: number; message: string }> {
  if (values.help || command === undefined) return { code: values.help ? 0 : 2, message: USAGE };
  if (command === 'probe') {
    return { code: 2, message: 'coffre-conformance probe is now `coffre verify instance`, in the coffre CLI: npx @coffre/cli verify instance' };
  }
  if (command !== 'workers' && command !== 'node') return { code: 2, message: USAGE };
  const kind: Kind = command;
  const dir = resolve(target ?? '.');
  const port = Number(values.port);
  const bulkLimit = Number(values['bulk-limit']);
  if (!Number.isInteger(port) || !Number.isInteger(bulkLimit) || bulkLimit < 1) return { code: 2, message: USAGE };

  console.log(`coffre-conformance: ${kind} from ${dir}`);
  let deployment;
  try {
    deployment = await boot(kind, dir, {
      port,
      postgres: values.postgres,
      runtime: values.runtime,
      vaultRuntime: values['vault-runtime'],
      hotRuntime: values['hot-runtime'],
    });
  } catch (error) {
    const detail = error instanceof Failure && error.detail !== undefined ? `\n${String(error.detail)}` : '';
    return { code: 1, message: `the deployment did not start: ${error instanceof Error ? error.message : String(error)}${detail}` };
  }
  console.log(`  up on ${deployment.origin}`);
  let ran: Awaited<ReturnType<typeof conform>>;
  try {
    ran = await conform(deployment, { bulkLimit, browser: values.browser || null });
  } finally {
    await deployment.stop();
  }
  // Once the processes have stopped: what they wrote late is in, and every request has ended.
  const { failed } = ran;
  const afterwards = await ran.afterwards(deployment.output());
  if (afterwards !== undefined) console.error(`\n${afterwards}`);
  return failed.length === 0 ? { code: 0, message: 'conformant' } : { code: 1, message: `NOT conformant: ${failed.join(', ')}` };
}
