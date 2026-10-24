// The audit watch's anchor on Workers (anchor.ts, plugins/audit-watch.ts):
// one Durable Object for the instance, named `anchor` unless the deployment
// names another. The deployment binds it as `ANCHOR`, hands it to the watch
// as `auditWatch({ anchor: durableAnchor(env.ANCHOR) })`, and exports it,
// `export const CoffreAnchor = coffre.Anchor`.
//
// Not Workers KV: a KV read may be a minute stale, and KV has no
// compare-and-set, so two beats could each write over the other, and a
// record put back could go unseen for as long. A Durable Object is one
// instance, strongly consistent: its storage reads its own writes, and its
// input gate keeps another request from running between this one's read
// and its write, so the compare-and-set below is one.
//
// A backlog, the whole log once its store is found empty, is walked between
// beats by the object's alarm, a walk an alarm, over its own storage, until
// none is left (`walkOn`).
//
// Asked with `fetch`, not RPC, as the gates are (cloudflare-gates.ts).
import { admits, walking, type AnchorStore, type AuditAnchor } from './anchor.ts';

/** The Durable Object binding the deployment hands the watch: `durableAnchor(env.ANCHOR)`. */
export type AnchorNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
};

/** What the object is given by the runtime: the part of a Durable Object's state it uses. */
type AnchorObjectState = {
  storage: {
    get<T>(key: string): Promise<T | undefined>;
    put<T>(key: string, value: T): Promise<void>;
    getAlarm(): Promise<number | null>;
    setAlarm(scheduledTime: number): Promise<void>;
  };
};

type AnchorCall = { op: 'read' } | { op: 'write'; prev: AuditAnchor | null; next: AuditAnchor };

const KEY = 'anchor';

/** Between one walk of a backlog and the next. */
const WALK_EVERY_MS = 1000;

/**
 * The instance's anchor, its Durable Object. `name` picks the object: a new
 * name is a new, empty store, which the next beat re-anchors, the way to
 * empty it on Workers.
 */
export function durableAnchor(namespace: AnchorNamespace, options: { name?: string } = {}): AnchorStore {
  const name = options.name ?? KEY;
  const ask = async <T>(call: AnchorCall): Promise<T> => {
    if (typeof namespace?.idFromName !== 'function') {
      throw new Error('there is no ANCHOR binding: add the CoffreAnchor Durable Object, its binding and its migration to app/wrangler.jsonc (docs/deploy.md, "The audit watch")');
    }
    const object = namespace.get(namespace.idFromName(name));
    const response = await object.fetch(new Request('https://anchor/', { method: 'POST', body: JSON.stringify(call) }));
    if (!response.ok) throw new Error(`the audit anchor failed: ${response.status} ${await response.text()}`);
    return (await response.json()) as T;
  };
  return {
    read: async () => (await ask<{ anchor: AuditAnchor | null }>({ op: 'read' })).anchor,
    write: async (prev, next) => (await ask<{ written: boolean }>({ op: 'write', prev, next })).written,
  };
}

/**
 * The Durable Object class `ANCHOR` binds. `walkOn` walks one more of a
 * backlog over the store it is given, the object's own: the audit watch's,
 * as the deployment configured it for `env`; null without one.
 */
export function anchorObject<Env>(walkOn: (env: Env) => ((store: AnchorStore) => Promise<boolean>) | null = () => null) {
  return class CoffreAnchor {
    readonly #storage: AnchorObjectState['storage'];
    readonly #env: Env;
    readonly #store: AnchorStore;

    constructor(state: AnchorObjectState, env: Env) {
      this.#storage = state.storage;
      this.#env = env;
      this.#store = {
        read: async () => (await this.#storage.get<AuditAnchor>(KEY)) ?? null,
        write: async (prev, next) => {
          if (!admits(await this.#store.read(), prev, next)) return false;
          await this.#storage.put(KEY, next);
          // A backlog left: the alarm walks it, without waiting for the next beat.
          if (walking(next) && (await this.#storage.getAlarm()) === null) await this.#storage.setAlarm(Date.now() + WALK_EVERY_MS);
          return true;
        },
      };
    }

    async fetch(request: Request): Promise<Response> {
      const call = (await request.json()) as AnchorCall;
      if (call.op === 'read') return Response.json({ anchor: await this.#store.read() });
      return Response.json({ written: await this.#store.write(call.prev, call.next) });
    }

    /** One walk of the backlog; another alarm while some is left. A walk that throws is retried by the runtime. */
    async alarm(): Promise<void> {
      const walk = walkOn(this.#env);
      if (walk === null) return;
      if ((await walk(this.#store)) && (await this.#storage.getAlarm()) === null) await this.#storage.setAlarm(Date.now() + WALK_EVERY_MS);
    }
  };
}
