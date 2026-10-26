import type { Witness, WitnessAnswer } from './log.ts';
import { cosignNote, openCheckpoint, parseCheckpoint, type Checkpoint, type Signer, type Verifier } from './note.ts';
import { verifyConsistency, type Hash } from './tree.ts';

/**
 * A witness, as transparency-dev's and Sigsum's work: it holds the newest head
 * of a log it has seen, and cosigns a new one only if the log proves the new
 * one extends it. So a log cannot show two parties two histories (a split
 * view) and get both witnessed. The same function runs in the Worker's Durable
 * Object (worker/index.ts) and in-process for the attack demos.
 */
export type WitnessState = { checkpoint: Checkpoint; note: string } | null;

export async function witnessAdd(
  state: WitnessState, note: string, proof: readonly Hash[], log: Verifier, self: Signer,
): Promise<{ state: WitnessState; answer: WitnessAnswer }> {
  const c = await openCheckpoint(note, log);
  if (c === null) return { state, answer: { ok: false, reason: 'not signed by the log' } };
  if (state !== null) {
    const held = state.checkpoint;
    if (BigInt(c.upto) < BigInt(held.upto)) return { state, answer: { ok: false, reason: `older than the head held (${held.upto})` } };
    if (c.upto === held.upto && !(c.size === held.size && c.root.equals(held.root))) {
      return { state, answer: { ok: false, reason: `split view: a second head at ${c.upto}` } };
    }
    if (!verifyConsistency(held.size, c.size, held.root, c.root, proof)) {
      return { state, answer: { ok: false, reason: `split view: ${c.size} leaves at ${c.upto} does not extend ${held.size} at ${held.upto}` } };
    }
  }
  return { state: { checkpoint: c, note }, answer: { ok: true, cosigned: await cosignNote(note, self) } };
}

/** An in-process witness, for the demos: what the Durable Object does, minus the network. */
export function localWitness(name: string, log: Verifier, self: Signer): Witness & { held(): WitnessState; alarms: string[] } {
  let state: WitnessState = null;
  const alarms: string[] = [];
  return {
    name,
    held: () => state,
    alarms,
    async publish(note, proofFrom) {
      const proof = state === null ? [] : await proofFrom(state.checkpoint.size);
      const r = await witnessAdd(state, note, proof, log, self);
      state = r.state;
      if (!r.answer.ok) alarms.push(r.answer.reason);
      return r.answer;
    },
  };
}

/** A witness over HTTP (the Worker's Durable Object): sends the head and a proof from the size it last held. */
export function httpWitness(name: string, url: string, headers: Record<string, string> = {}): Witness {
  let held = 0;
  return {
    name,
    async publish(note, proofFrom) {
      for (let tries = 0; tries < 2; tries += 1) {
        const proof = held === 0 ? [] : await proofFrom(held);
        const res = await fetch(url, {
          method: 'POST', headers: { 'content-type': 'application/json', ...headers },
          body: JSON.stringify({ note, from: held, proof: proof.map((h) => h.toString('base64')) }),
        });
        const body = (await res.json()) as { size?: number; cosigned?: string; reason?: string };
        if (res.status === 409 && body.size !== undefined) {
          // The witness holds another size than we thought: prove from that one.
          held = body.size;
          continue;
        }
        if (!res.ok) return { ok: false, reason: body.reason ?? `HTTP ${res.status}` };
        held = parseCheckpoint(note.slice(0, note.indexOf('\n\n') + 1)).size;
        return { ok: true, cosigned: body.cosigned };
      }
      return { ok: false, reason: 'witness size kept moving' };
    },
  };
}

/** An append-only archive over HTTP (the Worker's R2 bucket under a lock): stores every head it is sent, checks nothing. */
export function httpArchive(name: string, url: string, headers: Record<string, string> = {}): Witness {
  return {
    name,
    async publish(note) {
      const res = await fetch(url, { method: 'PUT', headers: { 'content-type': 'text/plain', ...headers }, body: note });
      return res.ok ? { ok: true } : { ok: false, reason: `archive: HTTP ${res.status} ${await res.text()}` };
    },
  };
}
