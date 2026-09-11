import { z } from 'zod';
import type { KmsBinding } from './index';
export class HttpKmsBinding implements KmsBinding {
  private readonly origin: string;
  constructor(url: string, private readonly clientId: string, private readonly clientSecret: string, private readonly fetcher: typeof fetch = fetch) {
    const u = new URL(url);
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.pathname !== '/' || !clientId || !clientSecret) throw new Error('A dedicated HTTPS KMS origin and Access service credentials are required');
    this.origin = u.origin;
  }
  private async call(operation: string, request: object): Promise<unknown> {
    const response = await this.fetcher(`${this.origin}/v1/${operation}`, { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10000), headers: { 'Content-Type': 'application/json', 'CF-Access-Client-Id': this.clientId, 'CF-Access-Client-Secret': this.clientSecret }, body: JSON.stringify(request) });
    if (!response.ok) throw new Error('Key service operation failed');
    return response.json();
  }
  async wrap(request: Parameters<KmsBinding['wrap']>[0]) { return z.object({ keyRef: z.string().max(256), nonce: z.string().max(64).optional(), data: z.string().max(8192) }).strict().parse(await this.call('wrap', request)); }
  async unwrap(request: Parameters<KmsBinding['unwrap']>[0]) { return z.object({ data: z.string().max(64) }).strict().parse(await this.call('unwrap', request)).data; }
}
