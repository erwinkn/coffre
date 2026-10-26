// The proof API over the log, as a vault would serve it (W209), for Go's
// independent verifier (go/verify.go) and the benches:
//
//   GET /audit/checkpoint[?size=N]          the newest signed checkpoint (of at most N leaves)
//   GET /audit/proof?number=N[&size=S]      { index, size, leaf, proof[], checkpoint }
//   GET /audit/consistency?from=M&to=N      { proof[] }
//   GET /audit/tile/8/<L>/<N>[.p/<W>]       tile bytes, as Go's sumdb and C2SP tlog-tiles serve them
//   GET /audit/numbers?count=K              K random entry numbers (for the verifier to pick from)
//
//   node experiments/merkle/src/server.ts --url postgresql://… [--port 8209]
import { createServer } from 'node:http';
import { parseArgs } from 'node:util';

import pg from 'pg';

import { leafData, proveConsistency, proveNumber, readTiles } from './log.ts';
import { parseTilePath } from './tiles.ts';

const { values } = parseArgs({ options: { url: { type: 'string' }, port: { type: 'string', default: '8209' } } });
const pool = new pg.Pool({ connectionString: values.url, max: 8 });

const b64 = (hashes: Buffer[]) => hashes.map((h) => h.toString('base64'));

createServer(async (req, res) => {
  const url = new URL(req.url!, 'http://local');
  const send = (status: number, body: string | Buffer, type = 'application/json') => {
    res.writeHead(status, { 'content-type': type });
    res.end(body);
  };
  try {
    const q = url.searchParams;
    if (url.pathname === '/audit/checkpoint') {
      const { rows: [c] } = await pool.query('SELECT note FROM checkpoints WHERE $1::bigint IS NULL OR size <= $1 ORDER BY upto DESC LIMIT 1', [q.get('size')]);
      return c === undefined ? send(404, 'none') : send(200, c.note, 'text/plain; charset=utf-8');
    }
    if (url.pathname === '/audit/proof') {
      const size = q.get('size');
      const p = await proveNumber(pool, q.get('number')!, size === null ? undefined : Number(size));
      if (p === null) return send(404, JSON.stringify({ error: 'not sealed, or no such entry' }));
      return send(200, JSON.stringify({ number: p.number, index: p.index, size: p.size, leaf: leafData(p.entry).toString('base64'), proof: b64(p.proof), checkpoint: p.checkpoint }));
    }
    if (url.pathname === '/audit/consistency') {
      return send(200, JSON.stringify({ proof: b64(await proveConsistency(pool, Number(q.get('from')), Number(q.get('to')))) }));
    }
    if (url.pathname.startsWith('/audit/tile/')) {
      const t = parseTilePath(url.pathname.slice('/audit/'.length));
      if (t === null) return send(400, 'bad tile path');
      const [tile] = await readTiles(pool, [t]);
      if (tile === undefined || tile.hashes.length < t.width * 32) return send(404, 'no such tile');
      return send(200, tile.hashes.subarray(0, t.width * 32), 'application/octet-stream');
    }
    if (url.pathname === '/audit/numbers') {
      const { rows } = await pool.query(
        'SELECT a.number::text FROM audit a WHERE a.number <= (SELECT max(upto) FROM checkpoints) ORDER BY random() LIMIT $1', [Number(q.get('count') ?? 20)]);
      return send(200, JSON.stringify(rows.map((r) => r.number)));
    }
    send(404, 'not found', 'text/plain');
  } catch (error) {
    send(500, JSON.stringify({ error: (error as Error).message }));
  }
}).listen(Number(values.port), '127.0.0.1', () => console.log(`proof server on http://127.0.0.1:${values.port}`));
