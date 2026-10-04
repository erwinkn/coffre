import { BindingInvalid, checkFetchUrl } from '@coffre/core/identity';

import { FetchRefused, type WorkloadTransport } from './transport.ts';

/**
 * Where an issuer keeps its keys, from its discovery document: read once,
 * when a binding is made, and kept in the binding under its MAC. An
 * exchange fetches only that URL, never one a token names, and never a
 * discovery document that may have changed since an owner looked.
 *
 * The document must name the issuer exactly as the binding does, and its
 * `jwks_uri` must pass the same checks as the issuer.
 */
export async function discoverKeys(transport: WorkloadTransport, issuer: string, options: { allowLoopback: boolean }): Promise<string> {
  const url = new URL(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
  let document: unknown;
  try {
    document = await transport.json(url);
  } catch (error) {
    if (error instanceof FetchRefused) throw new DiscoveryFailed(`the issuer's discovery document: ${error.message}`, { cause: error });
    throw error;
  }
  const { issuer: named, jwks_uri: keys } = (typeof document === 'object' && document !== null ? document : {}) as Record<string, unknown>;
  if (named !== issuer) {
    throw new DiscoveryFailed(`the issuer's discovery document names ${typeof named === 'string' ? `"${named}"` : 'no issuer'}, not "${issuer}"`);
  }
  if (typeof keys !== 'string') throw new DiscoveryFailed("the issuer's discovery document names no jwks_uri");
  try {
    checkFetchUrl(keys, "the issuer's jwks_uri", { allowLoopback: options.allowLoopback, path: true, query: true });
  } catch (error) {
    if (error instanceof BindingInvalid) throw new DiscoveryFailed(error.message);
    throw error;
  }
  return keys;
}

/** The issuer could not be asked, or did not answer as an OpenID Connect issuer does. */
export class DiscoveryFailed extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'DiscoveryFailed';
  }
}
