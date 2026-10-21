// The probe as `pnpm smoke` runs it under `wrangler dev`: the same Worker and
// Durable Object, with cloudflare:sockets' connect() standing in for the VPC
// Network binding, which only exists on Cloudflare.
import { connect } from 'cloudflare:sockets';
import worker, { Probe, type Env } from '../src/index.ts';

const local = (env: Env): Env => ({ ...env, VPC: { connect: (address) => connect(address) } });

export default {
  fetch: (request, env) => worker.fetch(request, local(env)),
} satisfies ExportedHandler<Env>;

export class LocalProbe extends Probe {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, local(env));
  }
}
