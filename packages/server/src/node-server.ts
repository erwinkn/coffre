// The Node server behind `serve()`, with the pages passed in: tests bring a
// stand-in UI and no static files.
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { Readable } from 'node:stream';

import { openDatabase } from './db/connect.ts';
import { handleRequest, runScheduled } from './app.ts';
import { resolveConfig, type CoffreConfig } from './config.ts';
import { createRuntime } from './runtime.ts';
import type { Ui } from './ui.ts';

export type ServeOptions = CoffreConfig & {
  /** `postgres://…`, `mysql://…`, or `file:coffre.db` for SQLite. */
  database: string;
  /** 3000 unless set. */
  port?: number;
  /** Where to listen; 127.0.0.1 unless set, for a proxy in front to terminate TLS. */
  host?: string;
  /** How often the heartbeat and due syncs run; every 5 minutes unless set, `false` for never (tests). */
  schedule?: { everyMinutes: number } | false;
};

export type Server = {
  /** Where it listens, e.g. `http://127.0.0.1:3000`. */
  url: string;
  close(): Promise<void>;
};

const SCHEDULE_MINUTES = 5;

/** Serve coffre with these pages until `close()`. */
export async function serveWith(options: ServeOptions, ui: Ui, staticFiles: string | null): Promise<Server> {
  const config = resolveConfig(options);
  if (typeof options.database !== 'string' || options.database.length === 0) {
    throw new Error('database must be a URL: postgres://…, mysql://… or file:…');
  }
  const database = await openDatabase(options.database);
  const runtime = createRuntime(config, database.db, options.vault);
  const origin = config.publicUrl;

  const server = createServer((req, res) => {
    void respond(req, res).catch((error: unknown) => {
      console.error('request failed', error);
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
      res.end();
    });
  });

  async function respond(req: IncomingMessage, res: ServerResponse) {
    const path = req.url ?? '/';
    const url = URL.parse(path, origin);
    // Node accepts absolute and network-path targets. They cannot choose the
    // origin that the app uses for callbacks and browser mutations.
    if (!path.startsWith('/') || /^[/\\]{2}/.test(path) || url === null || url.origin !== origin) {
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Invalid request target');
      return;
    }
    if (staticFiles !== null && (req.method === 'GET' || req.method === 'HEAD') && path.startsWith('/_coffre/')) {
      if (await sendStatic(staticFiles, path, req, res)) return;
    }
    const aborted = new AbortController();
    res.once('close', () => aborted.abort());
    const request = toRequest(req, url, aborted.signal);
    const response = await handleRequest(request, runtime, ui, peerAddress(req));
    await send(response, req, res);
  }

  const schedule = options.schedule ?? { everyMinutes: SCHEDULE_MINUTES };
  let timer: NodeJS.Timeout | null = null;
  if (schedule !== false) {
    if (!(schedule.everyMinutes >= 1)) throw new Error('schedule.everyMinutes must be at least 1');
    const tick = () =>
      runScheduled(runtime).catch((error: unknown) => console.error('scheduled job failed', error));
    void tick();
    timer = setInterval(tick, schedule.everyMinutes * 60_000);
    timer.unref();
  }

  const port = options.port ?? 3000;
  const host = options.host ?? '127.0.0.1';
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  const listening = typeof address === 'object' && address !== null ? address.port : port;

  return {
    url: `http://${host.includes(':') ? `[${host}]` : host}:${listening}`,
    async close() {
      if (timer !== null) clearInterval(timer);
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
      await database.close();
    },
  };
}

/**
 * The request as the app sees it. Its URL is built on the public URL, not
 * the Host header, which the client chooses: sign-in callbacks and the
 * same-origin check both depend on it.
 */
function toRequest(req: IncomingMessage, url: URL, signal: AbortSignal): Request {
  const headers = new Headers();
  for (const [name, values] of Object.entries(req.headersDistinct)) {
    for (const value of values ?? []) headers.append(name, value);
  }
  const bodyless = req.method === 'GET' || req.method === 'HEAD';
  return new Request(url, {
    method: req.method,
    headers,
    body: bodyless ? null : (Readable.toWeb(req) as ReadableStream<Uint8Array>),
    duplex: 'half',
    signal,
  } as RequestInit);
}

/**
 * The caller's address is the socket's. A proxy in front makes that the
 * proxy's; coffre does not trust a forwarded-for header anyone could send.
 */
function peerAddress(req: IncomingMessage): string | null {
  const address = req.socket.remoteAddress;
  if (address === undefined) return null;
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

async function send(response: Response, req: IncomingMessage, res: ServerResponse) {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => {
    if (name !== 'set-cookie') headers[name] = value;
  });
  // Joined into one header, cookies would read as one.
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) headers['set-cookie'] = cookies;
  res.writeHead(response.status, response.statusText, headers);

  if (response.body === null || req.method === 'HEAD') {
    await response.body?.cancel();
    res.end();
    return;
  }
  // Streamed, so a page's HTML reaches the browser as it renders.
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(value)) await new Promise((resolve) => res.once('drain', resolve));
      if (res.destroyed) break;
    }
  } finally {
    reader.releaseLock();
    res.end();
  }
}

const CONTENT_TYPES: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.map': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

/** A file under `/_coffre/`, from the UI's build. Names are content-hashed, so they keep forever. */
async function sendStatic(root: string, path: string, req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  let pathname: string;
  try {
    pathname = decodeURIComponent(new URL(path, 'http://x').pathname);
  } catch {
    return false;
  }
  // Only what the UI's build put under `_coffre/`, however the path is spelt.
  const file = normalize(join(root, pathname));
  if (!file.startsWith(join(root, '_coffre') + sep)) return false;
  const info = await stat(file).catch(() => null);
  if (info === null || !info.isFile()) return false;

  res.writeHead(200, {
    'content-type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream',
    'content-length': info.size,
    'cache-control': 'public, max-age=31536000, immutable',
    'x-content-type-options': 'nosniff',
    'cross-origin-resource-policy': 'same-origin',
  });
  if (req.method === 'HEAD') {
    res.end();
    return true;
  }
  await new Promise<void>((resolve, reject) => {
    createReadStream(file).on('error', reject).on('end', resolve).pipe(res);
  });
  return true;
}
