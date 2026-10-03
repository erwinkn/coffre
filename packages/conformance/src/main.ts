// coffre-conformance: check a coffre deployment from outside, for what it
// must never do whatever code it runs. It boots the deployment itself, as
// `coffre init` made it or however it was changed since, signs people in
// through a stand-in GitHub, and takes them through the checks.
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { boot, type Kind } from './harness.ts';
import { Failure } from './report.ts';
import { conform } from './suite.ts';

const USAGE = `usage:
  coffre-conformance workers [<dir>] --postgres <owner URL> --runtime <coffre_runtime URL>
                    --vault-runtime <coffre_vault_runtime URL> [options]
  coffre-conformance node [<dir>] [options]

  <dir>             the deployment, as \`coffre init\` wrote it (default: here)
  --port <n>        coffre's port; the IdP gets the next, wrangler's inspector the one after (3082)
  --bulk-limit <n>  the vault's bulkLimit count, when not the default (1000)
  --postgres <url>  workers: a Postgres login that may create databases; one is made for the run
  --runtime <url>   workers: the same server as coffre_runtime, the login the app runs as
  --vault-runtime <url>
                    workers: the same server as coffre_vault_runtime, the login the vault runs as

To check an instance that is running already, from outside, use the CLI:
\`coffre verify instance\`.`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    port: { type: 'string', default: '3082' },
    'bulk-limit': { type: 'string', default: '1000' },
    postgres: { type: 'string' },
    runtime: { type: 'string' },
    'vault-runtime': { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});
const [command, target] = positionals;
if (values.help || command === undefined) exit(values.help ? 0 : 2, USAGE);

if (command === 'probe') exit(2, 'coffre-conformance probe is now `coffre verify instance`, in the coffre CLI: npx @coffre/cli verify instance');
if (command !== 'workers' && command !== 'node') exit(2, USAGE);
const kind: Kind = command;
const dir = resolve(target ?? '.');
const port = Number(values.port);
const bulkLimit = Number(values['bulk-limit']);
if (!Number.isInteger(port) || !Number.isInteger(bulkLimit) || bulkLimit < 1) exit(2, USAGE);

console.log(`coffre-conformance: ${kind} from ${dir}`);
let deployment;
try {
  deployment = await boot(kind, dir, {
    port,
    postgres: values.postgres,
    runtime: values.runtime,
    vaultRuntime: values['vault-runtime'],
  });
} catch (error) {
  const detail = error instanceof Failure && error.detail !== undefined ? `\n${String(error.detail)}` : '';
  exit(1, `the deployment did not start: ${error instanceof Error ? error.message : String(error)}${detail}`);
}
console.log(`  up on ${deployment.origin}`);
let failed: string[];
try {
  failed = await conform(deployment, { bulkLimit });
  if (failed.length > 0) console.error(`\nThe processes' output, last lines:\n${deployment.output(4000)}`);
} finally {
  await deployment.stop();
}
exit(failed.length === 0 ? 0 : 1, summary(failed));

function summary(failed: string[]): string {
  return failed.length === 0 ? 'conformant' : `NOT conformant: ${failed.join(', ')}`;
}

function exit(code: number, message: string): never {
  (code === 0 ? console.log : console.error)(message);
  process.exit(code);
}
