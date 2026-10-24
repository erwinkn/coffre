// The workload gate on Workers (docs/design/workload-access.md, section
// 5.2): a Durable Object per workload, `gate:<principal>`, around the same
// `GateState` a Node process holds (gate.ts). The deployment binds it as
// `GATES`, hands it to coffre as `gates: env.GATES`, and exports it,
// `export const CoffreGates = coffre.Gates`.
//
// Its epochs and `jti`s live in its memory alone: an eviction starts it
// with a new epoch, which no proof carries yet. Its counts over an hour or
// more, a day's included, are written to its storage by an alarm, at most
// `FLUSH_MS` after they change, and read back when it starts again.
//
// The object is asked with `fetch`, not RPC: RPC needs the class to extend
// `DurableObject` from `cloudflare:workers`, which Node, where the server's
// tests load this module, cannot resolve. Either way a call is one
// round trip with its arguments serialized.
import type { GateAdmission, GateCount } from '@coffre/core/identity';

import { FLUSH_MS, GateState, type Count, type Gates } from './gate.ts';

/** The Durable Object binding the deployment hands coffre: `gates: env.GATES`. */
export type GatesNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
};

/** What the object is given by the runtime: the part of a Durable Object's state it uses. */
type GateObjectState = {
  storage: {
    list<T>(options: { prefix: string }): Promise<Map<string, T>>;
    put<T>(entries: Record<string, T>): Promise<void>;
    setAlarm(scheduledTime: number): Promise<void>;
  };
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
};

/** What the Worker asks the object. */
type GateCall = { op: 'nonce' } | { op: 'admit'; replay?: { jti: string; nonce: string }; counts?: GateCount[] };

/** Where a durable count is stored: this, then its id in the gate. */
const COUNT = 'count:';

/** Each workload's gate, its Durable Object named by its principal. */
export function workersGates(namespace: GatesNamespace): Gates {
  return (principal) => {
    const gate = namespace.get(namespace.idFromName(`gate:${principal}`));
    const ask = async <T>(call: GateCall): Promise<T> => {
      const response = await gate.fetch(new Request('https://gate/', { method: 'POST', body: JSON.stringify(call) }));
      if (!response.ok) throw new Error(`the workload gate failed: ${response.status} ${await response.text()}`);
      return (await response.json()) as T;
    };
    return {
      nonce: async () => (await ask<{ nonce: string }>({ op: 'nonce' })).nonce,
      admit: ({ replay, counts }) => ask<GateAdmission>({ op: 'admit', replay: replay && { jti: replay.jti, nonce: replay.nonce }, counts: counts && [...counts] }),
    };
  };
}

/** The Durable Object class `GATES` binds. */
export class CoffreGates {
  readonly #storage: GateObjectState['storage'];
  readonly #gate = new GateState(Date.now(), { durable: true });
  /** Whether an alarm is set to write the durable counts. */
  #flushing = false;

  constructor(state: GateObjectState, _env: unknown) {
    this.#storage = state.storage;
    void state.blockConcurrencyWhile(async () => {
      const stored = await this.#storage.list<Count>({ prefix: COUNT });
      this.#gate.restore([...stored].map(([name, count]) => [name.slice(COUNT.length), count]));
    });
  }

  async fetch(request: Request): Promise<Response> {
    const call = (await request.json()) as GateCall;
    const now = Date.now();
    const answer = call.op === 'nonce' ? { nonce: this.#gate.nonce(now) } : this.#gate.admit(call, now);
    if (this.#gate.dirty && !this.#flushing) {
      await this.#storage.setAlarm(now + FLUSH_MS);
      this.#flushing = true;
    }
    return Response.json(answer);
  }

  /** Writes the durable counts; a write that fails gives them back, and the alarm, retried, writes them again. */
  async alarm(): Promise<void> {
    this.#flushing = false;
    const changed = this.#gate.flush();
    if (changed.length === 0) return;
    try {
      await this.#storage.put(Object.fromEntries(changed.map(([id, count]) => [COUNT + id, count])));
    } catch (error) {
      this.#gate.unwritten(changed.map(([id]) => id));
      throw error;
    }
  }
}
