import { WorkerEntrypoint } from 'cloudflare:workers';
import { z } from 'zod';
import { createKeyProvider, type KeyEnvironment } from '../../../packages/crypto/src/factory';
import { R2AuditArchive } from '../../../packages/archive/src/index';
import { AccessAuthenticator } from '../../../packages/core/src/auth';
import { limitedJson, securityHeaders } from '../../../packages/core/src/http';
import { KeyBroker } from './broker';
interface Environment extends KeyEnvironment { INSTANCE_ID: string; KEY_AUDIT: R2Bucket; HTTP_ENABLED?: string; ACCESS_ISSUER?: string; ACCESS_AUDIENCE?: string; ALLOWED_ACCESS_SERVICES?: string }
function broker(env: Environment) { z.string().uuid().parse(env.INSTANCE_ID); if (!env.KEY_AUDIT || !['local', 'scaleway'].includes(env.KEY_PROVIDER)) throw new Error('KMS requires an independent journal and an integrated provider'); return new KeyBroker(createKeyProvider(env), new R2AuditArchive(env.KEY_AUDIT), env.INSTANCE_ID); }
export class KmsWorker extends WorkerEntrypoint<Environment> {
  wrap(request: Parameters<KeyBroker['wrap']>[0]) { return broker(this.env).wrap(request); }
  unwrap(request: Parameters<KeyBroker['unwrap']>[0]) { return broker(this.env).unwrap(request); }
}
export default {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (env.HTTP_ENABLED !== 'true' || request.method !== 'POST' || !['/v1/wrap', '/v1/unwrap'].includes(path)) return new Response('Not found', { status: 404 });
    try {
      const identity = await new AccessAuthenticator(env.ACCESS_ISSUER ?? '', env.ACCESS_AUDIENCE ?? '').verify({ accessJwt: request.headers.get('Cf-Access-Jwt-Assertion') ?? undefined });
      const allowed = z.array(z.string()).parse(JSON.parse(env.ALLOWED_ACCESS_SERVICES ?? '[]'));
      if (identity.kind !== 'access-service' || !allowed.includes(identity.subject)) return new Response('Forbidden', { status: 403, headers: securityHeaders });
      const body = await limitedJson(request, 16384);
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid request');
      const operation = path === '/v1/wrap' ? 'wrap' : 'unwrap';
      const output = await broker(env).invoke({ ...body, operation }, identity.subject);
      return Response.json(operation === 'unwrap' ? { data: output } : output, { headers: securityHeaders });
    } catch { return Response.json({ error: 'Key operation failed' }, { status: 503, headers: securityHeaders }); }
  },
};
