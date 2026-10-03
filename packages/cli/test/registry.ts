// A stand-in npm registry, for pnpm to resolve from: each package's versions
// with their own publish times, so that minimumReleaseAge has something to
// hold back.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type Published = { version: string; daysAgo: number; dependencies?: Record<string, string> };

export async function registry(packages: Record<string, Published[]>): Promise<{ origin: string; close(): void }> {
  const work = mkdtempSync(join(tmpdir(), 'coffre-registry-'));
  const tarballs = new Map<string, Buffer>();
  const packuments = new Map<string, (origin: string) => unknown>();
  for (const [name, versions] of Object.entries(packages)) {
    const built = versions.map(({ version, daysAgo, dependencies = {} }) => {
      const root = join(work, `${name}-${version}`);
      mkdirSync(join(root, 'package'), { recursive: true });
      const manifest = { name, version, dependencies };
      writeFileSync(join(root, 'package', 'package.json'), JSON.stringify(manifest));
      execFileSync('tar', ['czf', `${root}.tgz`, '-C', root, 'package']);
      const body = readFileSync(`${root}.tgz`);
      const path = `/${name}/-/${name}-${version}.tgz`;
      tarballs.set(path, body);
      const integrity = `sha512-${createHash('sha512').update(body).digest('base64')}`;
      return { manifest, path, integrity, time: new Date(Date.now() - daysAgo * 86_400_000).toISOString() };
    });
    packuments.set(name, (origin) => ({
      name,
      'dist-tags': { latest: built.at(-1)!.manifest.version },
      versions: Object.fromEntries(
        built.map(({ manifest, path, integrity }) => [manifest.version, { ...manifest, dist: { tarball: `${origin}${path}`, integrity } }]),
      ),
      time: Object.fromEntries(built.map(({ manifest, time }) => [manifest.version, time])),
    }));
  }
  let origin = '';
  const server = createServer((request, response) => {
    const path = decodeURIComponent((request.url ?? '/').split('?')[0]!);
    const tarball = tarballs.get(path);
    if (tarball !== undefined) {
      response.writeHead(200, { 'content-type': 'application/octet-stream' });
      return response.end(tarball);
    }
    const packument = packuments.get(path.slice(1));
    if (packument === undefined) return response.writeHead(404, { 'content-type': 'application/json' }).end('{}');
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(packument(origin)));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return {
    origin,
    close: () => {
      server.close();
      rmSync(work, { recursive: true, force: true });
    },
  };
}
