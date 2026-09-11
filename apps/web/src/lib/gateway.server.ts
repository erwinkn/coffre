import { env } from 'cloudflare:workers';
import type { RpcResult, VaultBinding } from '../../../../packages/contracts/src/index';
import { credentialsFrom, failure, validateOrigin } from '../../../../packages/core/src/http';
interface WebEnvironment { VAULT: VaultBinding; PUBLIC_ORIGIN: string; STAGE: string; LOCAL_ACCESS_TOKEN?: string }
export async function dispatch(request: Request, invocation: unknown): Promise<RpcResult> {
  const bindings = env as unknown as WebEnvironment;
  const requestId = crypto.randomUUID();
  try {
    validateOrigin(request, bindings.PUBLIC_ORIGIN);
    const credentials = credentialsFrom(request);
    if (import.meta.env.DEV && bindings.STAGE === 'local' && new URL(request.url).hostname === '127.0.0.1' && !credentials.accessJwt && !credentials.bearer) credentials.accessJwt = bindings.LOCAL_ACCESS_TOKEN;
    if (!bindings.VAULT) throw new Error('Vault binding is not configured');
    return await bindings.VAULT.execute(credentials, invocation);
  } catch (error) { return failure(error, requestId); }
}
