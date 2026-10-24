// `coffre serve` (docs/design/workload-access.md, section 9.3): a
// workload's sidecar, for any language in any container. It signs in once
// with the platform's proof, holds the session and its key in memory, and
// forwards what the app sends its local listener, signed; each `--tunnel`
// is a Postgres listener of its own. The app's config names those URLs:
//
//   coffre serve --url https://secrets.acme.example --service api-prod \
//     --proof kubernetes:/var/run/secrets/coffre/token --listen 127.0.0.1:7300 --tunnel db=127.0.0.1:7432
//
//   OPENAI_BASE_URL=http://127.0.0.1:7300/use/openai
//   DATABASE_URL=postgres://app@127.0.0.1:7432/app?sslmode=disable
//
// Anything that can reach the listener uses the session, as anything in a
// process can use the SDK's key: its boundary is the pod's network
// namespace, or, on a shared machine, a Unix socket only its owner opens.
import { workload, type Workload } from '@coffre/client/workload';

import { parse, UsageError } from './manage.ts';
import { listen } from './tunnels.ts';
import { addressOf, forwarder, proofOf, PROOFS } from './workload.ts';

/** `coffre serve --url <url> --service <name> --proof <proof> [--listen <address>] [--tunnel <name>=<address>]…`; `url`, the session flag's, if given before the command. */
export async function serve(args: string[], sessionUrl?: string): Promise<void> {
  const { values } = parse(args, { url: { type: 'string' }, service: { type: 'string' }, proof: { type: 'string' }, listen: { type: 'string' }, tunnel: { type: 'string', multiple: true } }, []);
  const given = values.url ?? sessionUrl;
  if (given === undefined || values.service === undefined) throw new UsageError(`coffre serve --url <url> --service <name> --proof <proof>: which instance, as which service, proved how (${PROOFS})`);
  const origin = new URL(given).origin;
  const address = addressOf(values.listen ?? '127.0.0.1:7300', '--listen');
  const tunnels = (values.tunnel ?? []).map((spec) => {
    const [name, at] = spec.split(/=(.*)/s);
    if (!name || at === undefined) throw new UsageError(`--tunnel ${spec}: a tunnel is <name>=<host>:<port>, as db=127.0.0.1:7432`);
    const where = addressOf(at, '--tunnel');
    if ('path' in where) throw new UsageError(`--tunnel ${spec}: a tunnel listens on a host and port`);
    return { name, where };
  });
  const proof = await proofOf(values.proof, process.env);
  const say = (line: string) => process.stderr.write(`${line}\n`);

  const coffre: Workload = await workload({ url: origin, service: values.service, proof, log: say, sigterm: false });
  const opened: { url: string; close: () => void }[] = [];
  const stop = async (code: number) => {
    for (const each of opened) each.close();
    await coffre.close();
    process.exit(code);
  };
  // A sidecar stops with its pod: it logs out first, so the session ends with it.
  for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => void stop(0));
  try {
    const local = await forwarder(coffre, origin, address);
    opened.push(local);
    const lines = [`coffre: ${values.service} in ${coffre.places.join(', ')}, key-bound: ${local.url}/use/<credential>/… forwards to ${origin}, signed`];
    for (const { name, where } of tunnels) {
      // Coffre's end of a tunnel, as the plan names it: a database by name, under the session's environment.
      const listener = await listen({ key: name, url: coffre.url(name).replace(/^http/, 'ws') }, coffre, { address: where });
      opened.push(listener);
      lines.push(`coffre: ${name} on ${listener.url}`);
    }
    say(lines.join('\n'));
  } catch (error) {
    say(`coffre: ${error instanceof Error ? error.message : String(error)}`);
    await stop(1);
  }
}
