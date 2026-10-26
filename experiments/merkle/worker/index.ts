// W209's Worker, deployed only to a personal account for the experiment and
// deleted after. Synthetic keys (from SEED, not a secret) and data.
//
//   POST /witness            { note, from, proof[] }  the Durable Object witness: cosigns a head that extends the one it holds
//   GET  /witness            the head it holds
//   PUT  /archive            a signed head, into R2 under a bucket lock, keyed by the place it seals; checks the signature only
//   GET  /archive            the archive's keys, newest last; ?key= one head
//   DELETE /archive?key=…    tries to delete one (the lock must refuse)
//   GET  /receipt?k=&alg=    k receipts for one use each (alg ed25519 | hmac | none), or ?batch=k: k receipts under one signature
import { DurableObject } from 'cloudflare:workers';

import { checkpointBody, openNote, parseCheckpoint, signerFrom, verifierFrom, type Signer, type Verifier } from '../src/note.ts';
import { inclusionProof, leafHash, nodeHash, type Hash } from '../src/tree.ts';
import { witnessAdd, type WitnessState } from '../src/witness.ts';

type Env = { SEED: string; LOG_KEY: string; ORIGIN: string; WITNESS: DurableObjectNamespace<Witness>; ARCHIVE: R2Bucket };

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

async function digest(label: string, seed: string): Promise<Buffer> {
  return Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`w209.${label}${seed}`)));
}

// Settled values only, never a pending promise (AGENTS.md, "What an isolate keeps").
let keys: { log: Verifier; witness: Signer; receipts: Signer; hmac: CryptoKey } | null = null;
async function keysOf(env: Env) {
  if (keys === null) {
    keys = {
      log: await verifierFrom(env.LOG_KEY),
      witness: await signerFrom('witness.example', await digest('witness', env.SEED)),
      receipts: await signerFrom(env.ORIGIN, await digest('signer', env.SEED)),
      hmac: await crypto.subtle.importKey('raw', await digest('mac', env.SEED), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    };
  }
  return keys;
}

export class Witness extends DurableObject<Env> {
  async add(note: string, from: number, proof: string[]): Promise<{ status: number; body: unknown }> {
    const k = await keysOf(this.env);
    const held = (await this.ctx.storage.get<{ note: string }>('held')) ?? null;
    let state: WitnessState = null;
    if (held !== null) state = { note: held.note, checkpoint: parseCheckpoint((await openNote(held.note, k.log))!) };
    if (state !== null && from !== state.checkpoint.size) return { status: 409, body: { size: state.checkpoint.size } };
    const r = await witnessAdd(state, note, proof.map((p) => Buffer.from(p, 'base64')), k.log, k.witness);
    if (!r.answer.ok) return { status: 422, body: { reason: r.answer.reason } };
    await this.ctx.storage.put('held', { note });
    return { status: 200, body: { cosigned: r.answer.cosigned } };
  }

  async held(): Promise<string | null> {
    return (await this.ctx.storage.get<{ note: string }>('held'))?.note ?? null;
  }
}

/** A receipt: the vault's signed promise that the use's entry, this leaf at this number, is sealed by `deadline`. */
function receiptText(origin: string, number: number, leaf: Hash, deadline: number): string {
  return `coffre.receipt.v1\n${origin}\n${number}\n${leaf.toString('base64')}\n${deadline}\n`;
}

async function receipts(env: Env, k: number, alg: string, batch: number): Promise<string> {
  const keys = await keysOf(env);
  let last = '';
  const leaves: Hash[] = [];
  for (let i = 0; i < Math.max(k, batch); i += 1) {
    // The entry as the use wrote it: its leaf from the fields, the number the append returned and the MAC.
    const entry = JSON.stringify(['coffre.audit.v1', String(1_000_000_000_000 + i), Date.now(), 'svc-1', 'cred-1', 'use', `r${i}`, '{"secret":"DFNS_KEY"}', 'AAAA']);
    const leaf = leafHash(new TextEncoder().encode(entry));
    if (batch > 0) {
      leaves.push(leaf);
      continue;
    }
    const text = receiptText(env.ORIGIN, i, leaf, Date.now() + 5000);
    if (alg === 'ed25519') last = (await keys.receipts.sign(new TextEncoder().encode(text))).toString('base64');
    else if (alg === 'hmac') last = Buffer.from(await crypto.subtle.sign('HMAC', keys.hmac, new TextEncoder().encode(text))).toString('base64');
    else last = text;
  }
  if (batch > 0) {
    // Batched: one signature over the root of the batch's receipts; each receipt carries its path.
    const levels: Hash[][] = [leaves];
    while (levels.at(-1)!.length > 1) {
      const below = levels.at(-1)!;
      const up: Hash[] = [];
      for (let i = 0; i < below.length; i += 2) up.push(i + 1 < below.length ? nodeHash(below[i]!, below[i + 1]!) : below[i]!);
      levels.push(up);
    }
    const signature = await keys.receipts.sign(new TextEncoder().encode(receiptText(env.ORIGIN, 0, levels.at(-1)![0]!, Date.now() + 5000)));
    // Each receipt's path, read off the levels (a power-of-two batch, as the bench sends).
    const size = leaves.length;
    if ((size & (size - 1)) === 0) for (let i = 0; i < size; i += 1) inclusionProof((level, index) => levels[level]![index]!, i, size);
    last = signature.toString('base64');
  }
  return last;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const k = await keysOf(env);
    if (url.pathname === '/witness') {
      // ?log=: a witness of its own per run (the benches start fresh logs).
      const stub = env.WITNESS.get(env.WITNESS.idFromName(url.searchParams.get('log') ?? env.ORIGIN));
      if (request.method === 'GET') return new Response(await stub.held());
      const { note, from, proof } = (await request.json()) as { note: string; from: number; proof: string[] };
      // ?delay=ms: a slow witness, for the change-latency bench.
      const delay = Number(url.searchParams.get('delay') ?? 0);
      if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
      const r = await stub.add(note, from, proof);
      return json(r.status, r.body);
    }
    if (url.pathname === '/archive') {
      if (request.method === 'PUT') {
        const note = await request.text();
        const text = await openNote(note, k.log);
        if (text === null) return json(422, { reason: 'not signed by the log' });
        const c = parseCheckpoint(text);
        const key = `checkpoints/${c.upto.padStart(20, '0')}`;
        // Never overwrite: a second head for the same place is refused here, and the bucket lock refuses it again.
        const put = await env.ARCHIVE.put(key, note, { onlyIf: { etagDoesNotMatch: '*' } }).catch((e: Error) => e);
        if (put instanceof Error) return json(409, { reason: `R2 refused: ${put.message}` });
        if (put === null) return json(409, { reason: `a head is already archived at ${c.upto}` });
        return json(200, { key });
      }
      if (request.method === 'DELETE') {
        const r = await env.ARCHIVE.delete(url.searchParams.get('key')!).then(() => 'deleted', (e: Error) => `refused: ${e.message}`);
        return json(200, { result: r });
      }
      const one = url.searchParams.get('key');
      if (one !== null) {
        if (url.searchParams.get('overwrite') !== null) {
          // Overwrite without the precondition: only the bucket lock stands in the way.
          const r = await env.ARCHIVE.put(one, 'overwritten').then(() => 'overwritten', (e: Error) => `refused: ${e.message}`);
          return json(200, { result: r });
        }
        return new Response((await env.ARCHIVE.get(one))?.body ?? null);
      }
      const keys: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await env.ARCHIVE.list({ prefix: 'checkpoints/', cursor });
        keys.push(...page.objects.map((o) => o.key));
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor !== undefined);
      return json(200, { keys });
    }
    if (url.pathname === '/receipt') {
      const last = await receipts(env, Number(url.searchParams.get('k') ?? 1), url.searchParams.get('alg') ?? 'ed25519', Number(url.searchParams.get('batch') ?? 0));
      return new Response(last);
    }
    void checkpointBody;
    return new Response('not found', { status: 404 });
  },
};
