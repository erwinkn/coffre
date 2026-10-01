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

/** The mark beside a provider in the pages; `other` gets a generic one. */
export type SyncBrand = 'github' | 'vercel' | 'railway' | 'cloudflare' | 'other';

/**
 * One key of a provider's config, as the pages' form and `coffre sync add`
 * ask for it. Neither checks more than that a required field is filled in:
 * `parseConfig` is the judge.
 */
export type SyncField =
  | {
      type: 'text';
      /** The config's key. */
      name: string;
      label: string;
      placeholder: string;
      optional?: boolean;
      hint?: string;
      /** Asked only while an options field has exactly these picked. */
      when?: { field: string; is: string[] };
    }
  | {
      type: 'options';
      name: string;
      label: string;
      options: { value: string; label: string }[];
      /** Several may be picked (checkboxes), or exactly one (a segmented control). */
      multiple: boolean;
      /** Picked to begin with, and what `coffre sync add` sends when the field is left out. */
      initial: string[];
      hint?: string;
    };

/**
 * A service a sync can push to. The pages and the CLI learn of it from its
 * description (`id` to `credential`); the engine runs the rest.
 */
export type SyncProvider<Config = unknown> = {
  /** Stable: stored with every sync to it, and how `coffre sync add` names it. */
  id: string;
  /** Human name for the pages, e.g. "GitHub Actions". */
  label: string;
  brand: SyncBrand;
  /** What to ask for; `parseConfig` gets the answers, by field name. */
  fields: SyncField[];
  /** The token coffre writes with, which a coffre secret holds. */
  credential: {
    /** Where one could be kept, as `project/environment/KEY`: the form's placeholder. */
    placeholder: string;
    /** Which token to create, and with what permissions, in a sentence or two. */
    hint: string;
  };
  /** Validate untrusted JSON into Config, throwing SyncConfigError with a readable message. */
  parseConfig(input: unknown): Config;
  /** One line naming the destination, e.g. "acme/app · environment production". */
  describe(config: Config): string;
  /** Returns the key, or a reason it cannot exist at this target. */
  checkKey(key: string): { ok: true } | { ok: false; reason: string };
  /** Keys currently present at the target (values are write-only at most targets). */
  listKeys(ctx: SyncContext, config: Config): Promise<string[]>;
  apply(ctx: SyncContext, config: Config, plan: SyncPlan): Promise<SyncApplyResult>;
};

/** What the pages and the CLI learn of a provider: everything but its code. */
export type SyncProviderInfo = Pick<SyncProvider, 'id' | 'label' | 'brand' | 'fields' | 'credential'>;

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
