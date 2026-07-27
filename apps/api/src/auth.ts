import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { IdentityVerifier, Principal } from '../../../packages/core/src/identity/types.ts';
import { ACCESS_JWT_HEADER } from '../../../packages/core/src/identity/types.ts';

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal;
  }
}

export type AuthOptions = {
  verifier: IdentityVerifier;
  /**
   * Paths served without authentication. Kept to an explicit allowlist so the
   * default for any new route is "protected"; forgetting to add a route here
   * fails closed.
   */
  publicPaths?: readonly string[];
};

/**
 * The authentication boundary.
 *
 * This lives in Fastify, not in Next.js middleware. CVE-2025-29927 was an
 * authorization bypass in exactly that position: Next.js trusted an internal
 * `x-middleware-subrequest` header, so an attacker who set it skipped
 * middleware entirely. The admin UI therefore calls this API and never reads
 * the database itself -- a UI that queried Postgres directly would also be
 * reading secrets without writing an audit row.
 */
export function registerAuth(app: FastifyInstance, options: AuthOptions): void {
  const publicPaths = new Set(options.publicPaths ?? []);

  app.decorateRequest('principal', null);

  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    if (publicPaths.has(request.routeOptions.url ?? request.url)) return;

    // Strip anything a client might have sent that could be mistaken for an
    // internal trust signal. We do not use such headers, and saying so
    // explicitly is cheaper than discovering a framework that does.
    if ('x-middleware-subrequest' in request.headers) {
      request.log.warn(
        { path: request.url },
        'request carried x-middleware-subrequest; rejecting',
      );
      return reply.code(400).send({ error: 'bad_request' });
    }

    const token = request.headers[ACCESS_JWT_HEADER];

    if (typeof token !== 'string' || token.length === 0) {
      // No Access assertion means the request did not come through the
      // Cloudflare Access proxy. Reaching the origin directly must not be a
      // way to skip authentication.
      request.log.warn(
        { path: request.url, ip: request.ip },
        'request without an Access assertion; possible direct-to-origin access',
      );
      return reply.code(401).send({ error: 'unauthenticated' });
    }

    try {
      request.principal = await options.verifier.verify(token);
    } catch (error) {
      request.log.warn(
        { path: request.url, ip: request.ip, err: (error as Error).message },
        'Access token verification failed',
      );
      // Deliberately opaque: the caller learns that it failed, not why.
      return reply.code(401).send({ error: 'unauthenticated' });
    }
  });
}
