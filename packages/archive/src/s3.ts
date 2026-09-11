import { AwsClient } from 'aws4fetch';
import type { AuditArchive } from './index';
// Path-style HTTPS S3 endpoint. Credentials are supplied to the vault, never the browser.
export class S3AuditArchive implements AuditArchive {
  private readonly client: AwsClient;
  private readonly origin: string;
  constructor(endpoint: string, private readonly bucket: string, region: string, accessKeyId: string, secretAccessKey: string) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) throw new Error('Invalid S3 archive endpoint');
    this.origin = url.origin; this.client = new AwsClient({ region, service: 's3', accessKeyId, secretAccessKey, retries: 2 });
  }
  async putIfAbsent(key: string, data: string) {
    const url = `${this.origin}/${this.bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
    const response = await this.client.fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'If-None-Match': '*' }, body: data, redirect: 'manual', signal: AbortSignal.timeout(15000) });
    if (response.ok) return;
    if (response.status === 412) {
      const existing = await this.client.fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
      if (existing.ok && Number(existing.headers.get('Content-Length') ?? 0) < 1048576 && await existing.text() === data) return;
    }
    throw new Error('S3 audit write failed or conflicted');
  }
}
