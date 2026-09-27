import { readFile, stat } from 'node:fs/promises';
import { createServer, type IncomingMessage } from 'node:http';
import { dirname, extname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import uiWorker, {
  type UiBindings,
  type UiExecutionContext,
} from '@coffre/ui-spike';

const port = Number.parseInt(process.env.PORT ?? '3062', 10);
const here = dirname(fileURLToPath(import.meta.url));
const clientDirectory = resolve(here, '../node_modules/@coffre/ui-spike/dist/client');

const bindings: UiBindings = {
  HYPERDRIVE: {
    connectionString:
      'postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432/coffre_spike_ssr',
  },
  COFFRE_AUTH_MODE: 'dev',
  COFFRE_ACCESS_ISSUER: 'http://127.0.0.1:8081',
  COFFRE_ACCESS_JWKS_URL: 'http://127.0.0.1:8081/cdn-cgi/access/certs',
  COFFRE_ACCESS_AUD: 'coffre-ssr-ui-spike',
  COFFRE_KEK_LOCAL: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  COFFRE_KEK_ID: 'ssr-ui-spike',
  COFFRE_AUDIT_CHAIN_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  COFFRE_DEV_IDP_URL: 'http://127.0.0.1:8081',
};

const context: UiExecutionContext = {
  waitUntil(promise) {
    promise.catch((error: unknown) => console.error('background task failed', error));
  },
};

function cspNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

const contentTypes: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

async function requestBody(request: IncomingMessage): Promise<BodyInit | undefined> {
  if (request.method === 'GET' || request.method === 'HEAD') return undefined;
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks) as unknown as BodyInit;
}

async function staticResponse(pathname: string): Promise<Response | null> {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return new Response('Bad request', { status: 400 });
  }

  const filename = resolve(clientDirectory, `.${decoded}`);
  const pathWithinClient = relative(clientDirectory, filename);
  if (pathWithinClient.startsWith('..') || pathWithinClient === '') return null;

  try {
    if (!(await stat(filename)).isFile()) return null;
    return new Response(await readFile(filename), {
      headers: {
        'content-type': contentTypes[extname(filename)] ?? 'application/octet-stream',
        'cache-control': 'public, max-age=31536000, immutable',
      },
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

const server = createServer(async (incoming, outgoing) => {
  try {
    const origin = `http://${incoming.headers.host ?? `127.0.0.1:${port}`}`;
    const url = new URL(incoming.url ?? '/', origin);
    let response: Response;

    if (url.pathname === '/api/spike') {
      response = Response.json({ ok: true, owner: 'consumer', runtime: 'node' });
    } else {
      const asset = await staticResponse(url.pathname);
      if (asset !== null) {
        response = asset;
      } else {
        const nonce = cspNonce();
        const rendered = await uiWorker.fetch(
          new Request(url, {
            method: incoming.method,
            headers: incoming.headers as HeadersInit,
            body: await requestBody(incoming),
          }),
          bindings,
          context,
          { context: { cspNonce: nonce } },
        );
        response = new Response(rendered.body, rendered);
        response.headers.set('x-ssr-spike-request-nonce', nonce);
      }
    }

    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    console.error(error);
    outgoing.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    outgoing.end('Internal server error');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Node adapter listening on http://127.0.0.1:${port}`);
});
