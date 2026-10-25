import type { Access, Vault } from '@coffre/core/vault';

/**
 * The vault's last answer about each principal (`Vault.access`), kept for
 * as long as the configuration lives: the isolate's, or the process's.
 * Settled answers only, never a pending call (AGENTS.md, "What an isolate
 * keeps").
 *
 * A request that reads values may decide on the kept answer instead of
 * asking (`accessFor`), and so make one vault call, not two: the vault
 * checks the answer when it opens the values, under the reader's row and
 * the head (`UnwrapInput.accessRevision`). A request that answers or
 * refuses without opening any asks first (`Recalled.confirm`). Either
 * way, it answers only on an answer the vault gave it, or vouched for,
 * during the request; one that is not the vault's now starts over, asking
 * (`AccessChanged`).
 *
 *   Ada's export, her answer kept from her last request    unwrap, naming it: the vault checks it   one call
 *   her role changed meanwhile                              access_changed, no read                 asked again: access, unwrap
 */
export class Accesses {
  readonly #kept = new Map<string, Access>();

  /**
   * The answer kept about `principal`, an active member's from a vault that
   * names its answers, at `generation` when the request's credential names
   * one: an answer of another generation is no answer about it.
   */
  recall(principal: string, generation?: number): Access | undefined {
    const kept = this.#kept.get(principal);
    return kept === undefined || (generation !== undefined && kept.generation !== generation) ? undefined : kept;
  }

  /** Keep an answer, the newest about its principal; any other is forgotten. */
  remember(access: Access): void {
    this.#kept.delete(access.principal);
    if (access.status !== 'active' || access.revision === undefined) return;
    // The oldest goes first: a few hundred principals is far more than an isolate serves between deploys.
    if (this.#kept.size >= KEPT) this.#kept.delete(this.#kept.keys().next().value!);
    this.#kept.set(access.principal, access);
  }
}

const KEPT = 1000;

/**
 * A request decided on an answer that was not the vault's now: nothing was
 * read, logged or answered, and the request starts over, asking.
 */
export class AccessChanged extends Error {
  constructor() {
    super("the vault's answer about the caller changed since it was kept");
    this.name = 'AccessChanged';
  }
}

/**
 * A caller built from a kept answer, until the vault vouches for it this
 * request: by opening values on it (`vouched`), or by answering the same
 * when asked (`confirm`).
 */
export class Recalled {
  readonly revision: string;
  readonly #ask: () => Promise<Access>;
  #confirmed = false;

  constructor(revision: string, ask: () => Promise<Access>) {
    this.revision = revision;
    this.#ask = ask;
  }

  /** Whether the vault has vouched for the answer this request. */
  get confirmed(): boolean {
    return this.#confirmed;
  }

  /** The vault opened values on the answer, having checked it. */
  vouched(): void {
    this.#confirmed = true;
  }

  /** Ask the vault, unless it vouched already: throws `AccessChanged` unless it answers the same. */
  async confirm(): Promise<void> {
    if (this.#confirmed) return;
    if ((await this.#ask()).revision !== this.revision) throw new AccessChanged();
    this.#confirmed = true;
  }
}

/**
 * The vault's answer about `principal`: asked, and kept. Or, when `recall`
 * says the request reads values and checks a kept answer before it
 * answers, the kept one, if any, at the generation its credential names,
 * with its `Recalled`.
 */
export async function accessFor(
  deps: { vault: Vault; accesses?: Accesses },
  principal: string,
  recall: boolean | { generation: number } = false,
): Promise<{ access: Access; recalled: Recalled | null }> {
  const ask = async () => {
    const access = await deps.vault.access(principal);
    deps.accesses?.remember(access);
    return access;
  };
  const kept = recall === false ? undefined : deps.accesses?.recall(principal, recall === true ? undefined : recall.generation);
  if (kept === undefined) return { access: await ask(), recalled: null };
  return { access: kept, recalled: new Recalled(kept.revision!, ask) };
}
