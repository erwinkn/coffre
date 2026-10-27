// Witnesses on Workers for 0.15's log (docs/design/audit-tree.md,
// "Witnesses"; R40: the deployment opts in). The checkpointer hands each
// pair it signs to every witness the vault's config lists:
//
// - `durableWitness(env.WITNESS)`: a Durable Object of its own that holds
//   the newest pair it cosigned and cosigns a new one only if both trees
//   extend it (`witnessPair`), so the log cannot show two histories and get
//   both witnessed. Its own key cosigns; deployments that want a witness
//   outside their Cloudflare account point a C2SP witness at each tree.
// - `r2Archive(env.ARCHIVE)`: the pairs it is sent kept in an R2 bucket (the pump sends the newest one, so a pair a
//   slow put skipped over is not kept; the next one, which extends it, is). It checks
//   nothing: the verifier holds the rows to it later. Under a bucket lock
//   rule a Worker or a database writer cannot overwrite or delete what it
//   holds; an admin of the Cloudflare account can lift the rule (R54).
import { encodePair, noteSigner, openPair, pairVerifiers, witnessPair, type PairNotes, type TreeName, type WitnessAnswer, type WitnessState } from '@coffre/core/merkle';

import type { Witness } from './checkpointer.ts';
import type { ObjectNamespace, ObjectState } from './checkpointer-workers.ts';

export type WitnessSettings = {
  /** The witness's own name, its cosignatures' key name: `witness.acme.example`, say. */
  name: string;
  /** Its own Ed25519 seed, 32 bytes, base64. */
  key: string;
  /** The log's two verifier keys, as the vault's checkpointer signs them. */
  log: Record<TreeName, string>;
};

type Publication = { notes: PairNotes; from: Record<TreeName, number>; proofs: Record<TreeName, string[]> };

/** The witness's Durable Object class. A new name for it is a new witness, which takes the next pair it is sent as given. */
export function witnessObject<Env>(settings: (env: Env) => WitnessSettings | Promise<WitnessSettings>) {
  return class CoffreWitness {
    readonly #state: ObjectState;
    readonly #env: Env;

    constructor(state: ObjectState, env: Env) {
      this.#state = state;
      this.#env = env;
    }

    async fetch(request: Request): Promise<Response> {
      // Read, check and write as one, nothing else delivered meanwhile: a Durable Object's handlers interleave at every
      // await but storage's, so two forks sent at once would each be checked against the pair held, and both cosigned.
      try {
        const body = request.method === 'GET' ? null : ((await request.json()) as Publication);
        return await this.#state.blockConcurrencyWhile(() => this.#answer(body));
      } catch (error) {
        return Response.json({ ok: false, reason: `the witness failed: ${(error as Error).message}` }, { status: 500 });
      }
    }

    async #answer(p: Publication | null): Promise<Response> {
      const s = await settings(this.#env);
      const log = await pairVerifiers(s.log);
      const self = await noteSigner(s.name, Buffer.from(s.key, 'base64'));
      const stored = await this.#state.storage.get<string>('pair');
      const notes = stored === undefined ? null : JSON.parse(stored) as PairNotes;
      const pair = notes === null ? null : await openPair(notes, log);
      const held: WitnessState = pair === null ? null : { pair, notes: notes! };
      const sizes = { changes: held?.pair.changes.size ?? 0, uses: held?.pair.uses.size ?? 0 };
      if (p === null) return Response.json({ held: sizes });
      // Proofs from other sizes than the ones held prove nothing here: the sender asks again, from these.
      if (p.from.changes !== sizes.changes || p.from.uses !== sizes.uses) return Response.json({ held: sizes }, { status: 409 });
      const proofs = { changes: p.proofs.changes.map((h) => Buffer.from(h, 'base64')), uses: p.proofs.uses.map((h) => Buffer.from(h, 'base64')) };
      const r = await witnessPair(held, p.notes, proofs, log, self);
      if (!r.answer.ok) return Response.json(r.answer, { status: 422 });
      await this.#state.storage.put('pair', encodePair(p.notes));
      return Response.json(r.answer);
    }
  };
}

/** The witness's object as the checkpointer's `Witness`: the pair and each tree's proof from the sizes the object holds. */
export function durableWitness(namespace: ObjectNamespace, options: { name?: string } = {}): Witness {
  const name = options.name ?? 'witness';
  let held: Record<TreeName, number> | null = null;
  return {
    name,
    async publish(notes, proofs, signal) {
      if (typeof namespace?.idFromName !== 'function') return { ok: false, reason: 'there is no WITNESS binding' };
      const object = namespace.get(namespace.idFromName(name));
      for (let tries = 0; tries < 2; tries += 1) {
        if (held === null) {
          const response = await object.fetch(new Request('https://witness/', { method: 'GET', signal }));
          held = ((await response.json()) as { held: Record<TreeName, number> }).held;
        }
        const from = held;
        const p = await proofs(from);
        const body: Publication = { notes, from, proofs: { changes: p.changes.map((h) => h.toString('base64')), uses: p.uses.map((h) => h.toString('base64')) } };
        const response = await object.fetch(new Request('https://witness/', { method: 'POST', body: JSON.stringify(body), signal }));
        const answer = (await response.json()) as WitnessAnswer & { held?: Record<TreeName, number> };
        if (response.status === 409 && answer.held !== undefined) {
          held = answer.held;
          continue;
        }
        if (!answer.ok) return { ok: false, reason: answer.reason ?? `the witness answered ${response.status}` };
        held = sizesOf(notes);
        return { ok: true, cosigned: answer.cosigned };
      }
      return { ok: false, reason: 'the witness kept holding other sizes' };
    },
  };
}

/** Each tree's size, read from its note (the checkpointer's own, just signed). */
const sizesOf = (notes: PairNotes): Record<TreeName, number> => ({ changes: Number(notes.changes.split('\n')[1]), uses: Number(notes.uses.split('\n')[1]) });

/** The part of an R2 bucket binding the archive uses. */
export type ArchiveBucket = {
  put(key: string, value: string, options?: { onlyIf?: { etagDoesNotMatch?: string } }): Promise<unknown | null>;
  get(key: string): Promise<{ text(): Promise<string> } | null>;
};

/**
 * Each pair it is sent, kept in an R2 bucket under `<prefix><upto, 20 digits>.json`.
 * A place already archived with the same pair is fine (a pair sent again);
 * one archived with another is refused, and said.
 */
export function r2Archive(bucket: ArchiveBucket, options: { prefix?: string } = {}): Witness {
  const prefix = options.prefix ?? 'audit/';
  return {
    name: 'r2-archive',
    async publish(notes) {
      const upto = notes.changes.split('\n')[3]?.slice(5) ?? '';
      if (!/^\d{1,19}$/.test(upto)) return { ok: false, reason: 'not a checkpoint pair' };
      const key = `${prefix}${upto.padStart(20, '0')}.json`;
      const record = encodePair(notes);
      if ((await bucket.put(key, record, { onlyIf: { etagDoesNotMatch: '*' } })) !== null) return { ok: true };
      const kept = await (await bucket.get(key))?.text();
      return kept === record ? { ok: true } : { ok: false, reason: `the archive holds another pair up to ${upto}` };
    },
  };
}
