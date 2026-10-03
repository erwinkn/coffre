// coffre-conformance: check a coffre deployment from outside, for what it
// must never do whatever code it runs. It boots the deployment itself, as
// `coffre init` made it or however it was changed since, signs people in
// through a stand-in GitHub, and takes them through the checks.
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { parseCanary, type Canary } from './checks/live.ts';
import { openBrowser, PROBE } from './checks/probe.ts';
import { boot, type Kind } from './harness.ts';
import { Failure } from './report.ts';
import { conform, probe } from './suite.ts';

const USAGE = `usage:
  coffre-conformance workers [<dir>] --postgres <owner URL> --runtime <coffre_runtime URL>
                    --vault-runtime <coffre_vault_runtime URL> [options]
  coffre-conformance node [<dir>] [options]
  coffre-conformance probe <url> [--token <service token> --canary <project>/<env>/<KEY>[=<value>]]
  coffre-conformance probe <url> --sign-in

  <dir>             the deployment, as \`coffre init\` wrote it (default: here)
  --port <n>        coffre's port; the IdP gets the next, wrangler's inspector the one after (3082)
  --bulk-limit <n>  the vault's bulkLimit count, when not the default (1000)
  --postgres <url>  workers: a Postgres login that may create databases; one is made for the run
  --runtime <url>   workers: the same server as coffre_runtime, the login the app runs as
  --vault-runtime <url>
                    workers: the same server as coffre_vault_runtime, the login the vault runs as

probe checks a running instance from outside:
  as no one        health, headers, every route refusing no one, changes from
                   another site refused, /api/auth, nothing like a value shown
  with --token     a service token that reads the canary's environment and
                   holds auditor on its project: its value nowhere but its
                   reveal, the reveal audited, nothing else in reach
  --token          or COFFRE_TOKEN
  --canary         the value after =, or in COFFRE_CONFORMANCE_CANARY, or on
                   stdin, so it stays out of the shell's history
  with --sign-in   an owner approves a device login in the browser, as for
                   \`coffre login\`; the probe finds or makes conformance/live
                   and token:conformance-probe, issues it a credential, writes
                   a fresh canary, runs the token's checks, then verifies the
                   whole audit log as the owner. The credential is revoked and
                   the session ended however the run ends; neither it nor the
                   canary is ever shown

Each run with a token adds a few entries to the instance's audit log, which
is append-only, so they stay: the canary's read, and the reads it was refused.
It changes nothing else. A run with --sign-in leaves its project, environment
and service for the next, and writes its canary and its grants.`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    port: { type: 'string', default: '3082' },
    'bulk-limit': { type: 'string', default: '1000' },
    postgres: { type: 'string' },
    runtime: { type: 'string' },
    'vault-runtime': { type: 'string' },
    token: { type: 'string' },
    canary: { type: 'string' },
    'sign-in': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h' },
  },
});
const [command, target] = positionals;
if (values.help || command === undefined) exit(values.help ? 0 : 2, USAGE);

if (command === 'probe') {
  if (target === undefined) exit(2, USAGE);
  const origin = new URL(target).origin;
  if (values['sign-in']) {
    if (values.token !== undefined || values.canary !== undefined) exit(2, '--sign-in sets up its own token and canary: no --token or --canary with it');
    console.log(`coffre-conformance: probing ${origin}, as no one and signed in`);
    console.log(`  (it keeps ${PROBE.project}/${PROBE.environment} and ${PROBE.service} for the next run, and its reads stay in the audit log, for good)`);
    const failed = await probe(origin, {
      signIn: ({ url, code }) => {
        console.log(`\n  Approve the probe's sign-in, as an owner, at\n\n      ${url}\n\n  and check that it shows the code ${code}. Waiting for you…\n`);
        // On a terminal, as `coffre login`: from a script or CI, the printed address serves.
        if (process.stdout.isTTY) openBrowser(url);
      },
    });
    exit(failed.length === 0 ? 0 : 1, summary(failed));
  }
  const token = values.token ?? process.env.COFFRE_TOKEN;
  let canary: Canary | undefined;
  if (token !== undefined) {
    if (values.canary === undefined) exit(2, 'with a token, name its canary: --canary <project>/<environment>/<KEY>[=<value>]');
    try {
      canary = parseCanary(values.canary, values.canary.includes('=') ? undefined : await canaryValue());
    } catch (error) {
      exit(2, error instanceof Error ? error.message : String(error));
    }
  }
  console.log(`coffre-conformance: probing ${origin}${token === undefined ? ', as no one' : ', as no one and with a token'}`);
  if (token !== undefined) console.log("  (the token's reads add a few entries to the instance's audit log, for good)");
  const failed = await probe(origin, { token, canary });
  exit(failed.length === 0 ? 0 : 1, summary(failed));
}

/** The canary's value from the environment, or the first line of stdin when it is piped. */
async function canaryValue(): Promise<string | undefined> {
  const given = process.env.COFFRE_CONFORMANCE_CANARY;
  if (given !== undefined && given !== '') return given;
  if (process.stdin.isTTY) return undefined;
  let text = '';
  for await (const chunk of process.stdin) text += String(chunk);
  return text.split(/\r?\n/)[0];
}

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
