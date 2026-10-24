// A fake coffre for the workload SDK and sidecar, speaking
// docs/design/workload-access.md's wire format: the exchange, renew, logout
// and narrow; a gate whose nonces are epochs, which remembers each epoch's
// `jti`s; and `/use/`, where every proof is checked by core's `verifyProof`,
// as the server checks it, and only the headers `hdr` names are forwarded.
// Its tunnel carries a WebSocket's bytes to a database: a tiny Postgres of
// its own (`fakePostgres`), enough for node-postgres to sign in and query.
import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { connect as connectTcp, createServer as createTcpServer, type Socket } from 'node:net';
import { once } from 'node:events';

import { WebSocketServer, type WebSocket } from 'ws';

import { bodyDigest, UNSIGNED_BODY, type PublicJwk } from '@coffre/client/dpop';
import { thumbprint, verifyProof } from '@coffre/core/identity';

export type Answer = { status: number; body?: unknown; headers?: Record<string, string> };

/** What `/use/` forwarded upstream: the request as the proof signs it, with only the headers `hdr` names. */
export type Forwarded = { method: string; path: string; query: string; headers: Record<string, string>; body: string; session: string };

export type Session = { id: string; token: string; jkt: string; expiresAt: number; notAfter: number; places: string[]; revoked: boolean; parent?: string };

export type FakeOptions = {
  places?: string[];
  /** How long a session lasts from its exchange or its last renewal, and its hard end. */
  lifetimeMs?: number;
  notAfterMs?: number;
  /** An answer of the test's own to an exchange, in place of a session: `null` makes one. */
  exchange?: (proof: Record<string, unknown>, jkt: string, attempt: number) => Answer | null;
  /** An answer of the test's own to a renewal: `null` renews. */
  renew?: (session: Session) => Answer | null;
  /** The upstream's answer to what `/use/` forwards: an echo of it unless set. */
  upstream?: (forwarded: Forwarded) => Answer;
  /** Credentials injected by SigV4, whose body line is the declared digest. */
  sigv4?: string[];
  /** The plan's answer, at `GET /use/<project>/<env>`. */
  plan?: Record<string, unknown>;
  /** Whether the tunnel paces by credit, as a coffre on Workers does, or not, as one on Node. */
  paced?: boolean;
  /** Where the tunnel's bytes go. */
  database?: { port: number };
  /** A logout that never answers; one that asks for a fresh nonce every time. */
  stallLogout?: boolean;
  nonceLogout?: boolean;
};

const WINDOW = 1024 * 1024;

export async function fakeCoffre(options: FakeOptions = {}) {
  const places = options.places ?? ['market/prod'];
  const lifetimeMs = options.lifetimeMs ?? 3_600_000;
  const notAfterMs = options.notAfterMs ?? 24 * 3_600_000;
  const sessions = new Map<string, Session>();
  const forwarded: Forwarded[] = [];
  /** Every request, as `METHOD path outcome`: what the SDK asked, in order. */
  const log: string[] = [];
  let exchanges = 0;

  // The gate: its epochs, each with the `jti`s seen under it; a restart forgets them all.
  let rotation = 0;
  let epochs: { nonce: string; seen: Set<string> }[] = [];
  const rotate = () => {
    rotation += 1;
    epochs = [{ nonce: `g${rotation}.${randomBytes(16).toString('base64url')}`, seen: new Set<string>() }, ...epochs].slice(0, 2);
  };
  rotate();
  const nonce = () => epochs[0]!.nonce;

  let publicUrl = '';
  const answer = (res: ServerResponse, { status, body, headers = {} }: Answer) => {
    res.writeHead(status, { 'content-type': 'application/json', 'dpop-nonce': nonce(), ...headers }).end(body === undefined ? undefined : JSON.stringify(body));
  };
  const refuse = (res: ServerResponse, reason: string, status = 401) =>
    answer(res, { status, body: { error: 'unauthorized', reason, message: `refused: ${reason}` }, headers: { 'www-authenticate': `DPoP error="invalid_dpop_proof"` } });

  const read = async (req: IncomingMessage) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks);
  };

  /** A session request's proof, checked as the server checks it, then by the gate: the session, or the refusal sent. */
  const authenticate = async (req: IncomingMessage, res: ServerResponse | null, content?: { headers: Headers; body: string }): Promise<Session | string> => {
    const token = /^DPoP (\S+)$/.exec(req.headers.authorization ?? '')?.[1];
    const session = token === undefined ? undefined : sessions.get(token);
    if (session === undefined || session.revoked || Date.now() >= session.expiresAt || Date.now() >= session.notAfter) return 'expired';
    if (session.parent !== undefined) {
      const parent = [...sessions.values()].find((each) => each.id === session.parent);
      if (parent === undefined || parent.revoked) return 'revoked';
    }
    const proof = req.headers.dpop;
    if (typeof proof !== 'string') return 'dpop';
    const verified = await verifyProof(proof, { method: req.method!, url: `${publicUrl}${req.url}`, jkt: session.jkt, token, content });
    if (!verified.ok) return verified.reason;
    const epoch = epochs.find((each) => each.nonce === verified.nonce);
    if (epoch === undefined) {
      if (res !== null) answer(res, { status: 401, body: { error: 'unauthorized', reason: 'use_dpop_nonce' }, headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"' } });
      return 'use_dpop_nonce';
    }
    if (epoch.seen.has(verified.jti)) return 'replayed';
    epoch.seen.add(verified.jti);
    return session;
  };

  const issue = (jkt: string, sessionPlaces: string[], notAfter: number, parent?: string): Session => {
    const session: Session = {
      id: randomBytes(8).toString('hex'),
      token: `coffre_wl_${randomBytes(32).toString('base64url')}`,
      jkt,
      expiresAt: Math.min(Date.now() + lifetimeMs, notAfter),
      notAfter,
      places: sessionPlaces,
      revoked: false,
      parent,
    };
    sessions.set(session.token, session);
    return session;
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url!, publicUrl);
    const body = await read(req);
    const record = (outcome: string) => log.push(`${req.method} ${url.pathname} ${outcome}`);

    if (req.method === 'POST' && url.pathname === '/api/auth/workload') {
      const proof = req.headers.dpop;
      const verified = typeof proof === 'string' ? await verifyProof(proof, { method: 'POST', url: url.href, skewSeconds: 60 }) : null;
      if (verified === null || !verified.ok) return record('dpop'), refuse(res, 'dpop');
      const asked = JSON.parse(body.toString()) as { service: string; proof: Record<string, unknown> };
      const own = options.exchange?.(asked.proof, verified.jkt, ++exchanges) ?? null;
      if (own !== null) return record(String(own.status)), answer(res, own);
      const session = issue(verified.jkt, places, Date.now() + notAfterMs);
      record('200');
      return answer(res, {
        status: 200,
        body: { token: session.token, tokenType: 'DPoP', expiresAt: new Date(session.expiresAt).toISOString(), notAfter: new Date(session.notAfter).toISOString(), places },
        headers: { 'cache-control': 'no-store' },
      });
    }
    if (req.method === 'POST' && (url.pathname === '/api/auth/workload/renew' || url.pathname === '/api/auth/logout' || url.pathname === '/api/auth/workload/narrow')) {
      const session = await authenticate(req, res);
      if (session === 'use_dpop_nonce') return record('use_dpop_nonce');
      if (typeof session === 'string') return record(session), refuse(res, session);
      if (url.pathname === '/api/auth/logout') {
        if (options.stallLogout) return record('stalled');
        if (options.nonceLogout) {
          record('use_dpop_nonce');
          return answer(res, { status: 401, body: { error: 'unauthorized', reason: 'use_dpop_nonce' }, headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"' } });
        }
        session.revoked = true;
        return record('200'), answer(res, { status: 200, body: { revoked: true } });
      }
      if (url.pathname === '/api/auth/workload/narrow') {
        const { key, constraints } = JSON.parse(body.toString()) as { key: PublicJwk; constraints: { places?: string[] } };
        const child = issue(await thumbprint(key), constraints.places ?? session.places, session.notAfter, session.id);
        return record('200'), answer(res, { status: 200, body: { token: child.token, expiresAt: new Date(child.expiresAt).toISOString() } });
      }
      const own = options.renew?.(session) ?? null;
      if (own !== null) return record(String(own.status)), answer(res, own);
      session.expiresAt = Math.min(Date.now() + lifetimeMs, session.notAfter);
      return record('200'), answer(res, { status: 200, body: { expiresAt: new Date(session.expiresAt).toISOString() } });
    }
    if (url.pathname.startsWith('/use/')) {
      const segments = url.pathname.split('/').slice(2).map(decodeURIComponent);
      const credential = places.includes(segments.slice(0, 2).join('/')) ? segments[2] : segments[0];
      const headers = new Headers();
      for (let i = 0; i < req.rawHeaders.length; i += 2) headers.append(req.rawHeaders[i]!, req.rawHeaders[i + 1]!);
      const declared = headers.get('x-amz-content-sha256');
      const line = options.sigv4?.includes(credential ?? '') && declared !== null ? (/^[0-9a-f]{64}$/.test(declared) ? declared : UNSIGNED_BODY) : await bodyDigest(body);
      const session = await authenticate(req, res, { headers, body: line });
      if (session === 'use_dpop_nonce') return record('use_dpop_nonce');
      if (typeof session === 'string') return record(session), refuse(res, session);
      const hdr = JSON.parse(Buffer.from(String(req.headers.dpop).split('.')[1]!, 'base64url').toString()).hdr as string;
      const sent: Forwarded = {
        method: req.method!,
        path: url.pathname,
        query: url.search.slice(1),
        headers: Object.fromEntries(hdr === '' ? [] : hdr.split(' ').map((name) => [name, headers.get(name)!])),
        body: body.toString(),
        session: session.id,
      };
      record('200');
      // The environment's own URL: the plan, or what coffre makes with its values.
      const place = segments.join('/');
      if (places.includes(place)) {
        if (req.method === 'GET') return answer(res, { status: 200, body: options.plan ?? { environment: place, values: {}, credentials: [], tunnels: {} } });
        forwarded.push(sent);
        return answer(res, options.upstream?.(sent) ?? { status: 200, body: { computed: JSON.parse(sent.body) } });
      }
      forwarded.push(sent);
      return answer(res, options.upstream?.(sent) ?? { status: 200, body: sent });
    }
    record('404');
    answer(res, { status: 404, body: { error: 'not_found' } });
  };

  const server = createServer((req, res) => void handle(req, res).catch((error: unknown) => answer(res, { status: 500, body: { error: String(error) } })));
  const sockets = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    void (async () => {
      const session = await authenticate(req, null);
      log.push(`GET ${new URL(req.url!, publicUrl).pathname} ${typeof session === 'string' ? session : 'upgrade'}`);
      if (typeof session === 'string' || req.headers['coffre-tunnel-flow'] !== 'credit' || options.database === undefined) {
        socket.end(`HTTP/1.1 401 Unauthorized\r\ndpop-nonce: ${nonce()}\r\ncontent-length: 0\r\n\r\n`);
        return;
      }
      sockets.handleUpgrade(req, socket, head, (ws) => tunnel(ws, connectTcp(options.database!.port, '127.0.0.1'), options.paced !== false));
    })();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  publicUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

  return {
    url: publicUrl,
    sessions,
    forwarded,
    log,
    gate: {
      rotate,
      /** A new epoch and no memory: every nonce given before is unknown. */
      restart: () => {
        epochs = [];
        rotate();
      },
    },
    close: async () => {
      for (const client of sockets.clients) client.terminate();
      server.closeAllConnections();
      server.close();
    },
  };
}

/** The tunnel's coffre end: bytes both ways, by credit when it paces, as cloudflare-sockets.ts does, ending a client that sends past two windows. */
function tunnel(ws: WebSocket, database: Socket, paced: boolean): void {
  let uncounted = 0;
  let held = 0;
  if (paced) ws.send('0');
  database.on('data', (chunk: Buffer) => {
    ws.send(chunk);
    uncounted += chunk.length;
    if (paced && uncounted >= WINDOW) database.pause();
  });
  ws.on('message', (data: Buffer, binary: boolean) => {
    if (!binary) {
      uncounted -= Number(String(data));
      if (uncounted < WINDOW) database.resume();
      return;
    }
    held += data.length;
    if (paced && held > 2 * WINDOW) return ws.terminate();
    database.write(data, () => {
      held -= data.length;
      if (paced) ws.send(String(data.length));
    });
  });
  ws.on('close', () => database.destroy());
  database.on('close', () => ws.close());
  database.on('error', () => ws.terminate());
}

/**
 * Enough of Postgres's wire protocol for node-postgres: trust sign-in, and
 * simple queries, each answered with one text column, `n` rows of `size`
 * characters for `select <n> <size>`, or one row of the query for any other.
 */
export async function fakePostgres() {
  const server = createTcpServer((socket) => {
    let buffer = Buffer.alloc(0);
    let started = false;
    const message = (type: string, payload: Buffer) => {
      const head = Buffer.alloc(5);
      head.write(type, 0);
      head.writeInt32BE(payload.length + 4, 1);
      return Buffer.concat([head, payload]);
    };
    const cstring = (text: string) => Buffer.from(`${text}\0`);
    const int16 = (n: number) => Buffer.from([n >> 8, n & 255]);
    const int32 = (n: number) => {
      const b = Buffer.alloc(4);
      b.writeInt32BE(n);
      return b;
    };
    const ready = message('Z', Buffer.from('I'));
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (!started) {
          if (buffer.length < 4 || buffer.length < buffer.readInt32BE(0)) return;
          buffer = buffer.subarray(buffer.readInt32BE(0));
          started = true;
          socket.write(Buffer.concat([message('R', int32(0)), message('S', Buffer.concat([cstring('server_version'), cstring('17.0')])), message('K', Buffer.concat([int32(1), int32(2)])), ready]));
          continue;
        }
        if (buffer.length < 5 || buffer.length < 1 + buffer.readInt32BE(1)) return;
        const type = String.fromCharCode(buffer[0]!);
        const payload = buffer.subarray(5, 1 + buffer.readInt32BE(1));
        buffer = buffer.subarray(1 + buffer.readInt32BE(1));
        if (type === 'X') return void socket.end();
        if (type !== 'Q') continue;
        const query = payload.subarray(0, -1).toString();
        const many = /^select (\d+) (\d+)$/.exec(query);
        const rows = many === null ? [query] : Array.from({ length: Number(many[1]) }, () => 'x'.repeat(Number(many[2])));
        const column = Buffer.concat([cstring('value'), int32(0), int16(0), int32(25), int16(-1 & 0xffff), int32(-1), int16(0)]);
        socket.write(Buffer.concat([
          message('T', Buffer.concat([int16(1), column])),
          ...rows.map((row) => message('D', Buffer.concat([int16(1), int32(Buffer.byteLength(row)), Buffer.from(row)]))),
          message('C', cstring(`SELECT ${rows.length}`)),
          ready,
        ]));
      }
    });
    socket.on('error', () => undefined);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { port: (server.address() as { port: number }).port, close: () => server.close() };
}
