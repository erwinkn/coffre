import type { SyncProviderKind } from '@coffre/client';

export type { SyncProviderKind };

export type SyncVariable = { key: string; value: string };

export type SyncContext = {
  /** The target's API credential. Never log it, never put it in an error message. */
  token: string;
  /** Injected so tests (and the Worker runtime) control the network. Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  signal?: AbortSignal;
};

export type SyncPlan = {
  /** Create or overwrite. */
  upsert: SyncVariable[];
  /** Remove. The engine only ever lists keys coffre itself created. */
  delete: string[];
};

export type SyncApplyResult = {
  upserted: string[];
  deleted: string[];
  /** Per-key failures; one bad key never aborts the rest. Messages must not contain values or tokens. */
  failed: { key: string; operation: 'upsert' | 'delete'; message: string }[];
};

export type SyncProvider<Config> = {
  kind: SyncProviderKind;
  /** Human name for the UI, e.g. "GitHub Actions". */
  label: string;
  /** Validate untrusted JSON into Config, throwing SyncConfigError with a readable message. */
  parseConfig(input: unknown): Config;
  /** One line naming the destination, e.g. "erwinkn/app · environment production". */
  describe(config: Config): string;
  /** Returns the key, or a reason it cannot exist at this target. */
  checkKey(key: string): { ok: true } | { ok: false; reason: string };
  /** Keys currently present at the target (values are write-only at most targets). */
  listKeys(ctx: SyncContext, config: Config): Promise<string[]>;
  apply(ctx: SyncContext, config: Config, plan: SyncPlan): Promise<SyncApplyResult>;
};

export class SyncConfigError extends Error {
  override name = 'SyncConfigError';
}

export type SyncProviderErrorCode =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'rate_limited'
  | 'upstream'
  | 'network';

/** A whole-call failure (auth, target missing, rate limited, upstream down). */
export class SyncProviderError extends Error {
  override name = 'SyncProviderError';
  // Declared as fields rather than constructor parameter properties: Node's
  // strip-only TypeScript support rejects parameter properties.
  readonly code: SyncProviderErrorCode;
  readonly status: number | undefined;

  constructor(message: string, code: SyncProviderErrorCode, status?: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
