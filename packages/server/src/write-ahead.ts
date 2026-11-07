import { randomUUID } from 'node:crypto';

import { freshDek } from '@coffre/core/envelope';
import { hashToken, tokenKind, type TokenKind } from '@coffre/core/identity';
import { personalOf } from '@coffre/core/schemas';
import type { WriteKeysOutcome } from '@coffre/core/vault';

import { authenticateRequest, endedCredential, refusedByKind, unauthenticated, type AuthenticatedIdentity } from './auth.ts';
import { vaultWrites } from './api/changes.ts';
import { PARAMS, routeParts } from './api/router.ts';
import { secretPatch } from './api/routes.ts';
import type { Touch } from './api/signin.ts';
import type { SecretValue } from './api/secrets.ts';
import { findCredential, type ResolvedPath } from './db/queries.ts';
import { check, parseJsonBody } from './http.ts';
import { namedAhead } from './db/read-ahead.ts';
import { acceptance } from './named-use.ts';
import { RefusalRecord } from './refused.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * A key write in five round trips (T179 PR 3; docs/design/two-trips.md, "A key write"; formal/Writing.tla), the app's
 * front door. Served before `authenticate` and the router, as a named use is: the vault's one call reads everything its
 * decision weighs, the caller's rows among them, decides, wraps each data key and prepares each key's change; the app
 * checks the caller's rows' `auth_mac` on what it answered (`authenticateRequest`, reading nothing), and the route then
 * writes in one transaction of two round trips that holds the vault's read again before it commits (`heldWrite` in
 * api/secrets.ts).
 *
 *   PATCH /secrets/market/dev { API_KEY: "sk-…" }, Ada's session    vault 1 + 2 (0.14's key.wrap)   app 2   5 round trips
 *   the same, with `{ ref: … }`, `null`, `{ sensitivity }`, `?dryRun`  today's path, as ever
 *   the same at market/dev-ada (a fork) or market/dev@me               today's path, until the read holds the chain
 *
 * Null wherever this path does not serve the request: another route or shape, a token of another kind or refused for
 * its kind alone, a vault that does not serve it (older, mid-deploy; SQLite's; a key service's), or the vault's own
 * `served: false`. The request then goes as ever, and is answered as ever. A refusal of the vault's decision (PR 6) is
 * served: the caller checked on its rows as a served try's, the route answers it as ever, and the vault records it
 * where that answer would append a 0.14 entry (refused.ts): two round trips.
 */

/** The kinds of token whose writes this path serves: a person's session, CLI login and personal token, and a service's token. */
const WRITE_KINDS: readonly TokenKind[] = ['browser', 'cli', 'personal', 'service'];

/** A version's id, as the vault takes a regenerate's `replaces` (`validateWriteKeys`). */
const VERSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A write as the front door read it: its place's slugs, its patch as the route parses it, and its keys' names, in order. */
export type WriteAsked = { project: string; environment: string; patch: Record<string, SecretValue>; names: string[] };

/**
 * The request's write, if it is one this path serves: `PATCH /secrets/:project/:environment` with no query, its body a
 * patch the route takes (`secretPatch`), every entry a value, given or generated (no key pair), saying nothing of who
 * sees it, at an environment of its own name (no `@me`). Anything else is null, the route's to answer.
 */
export function writeAsked(request: Request, body: Uint8Array): WriteAsked | null {
  if (request.method !== 'PATCH') return null;
  const url = new URL(request.url);
  if (url.search !== '') return null;
  let parts: string[];
  try {
    parts = routeParts(url.pathname);
  } catch {
    return null;
  }
  const [route, project, environment] = parts;
  if (parts.length !== 3 || route !== 'secrets' || project === undefined || environment === undefined) return null;
  if (!PARAMS.project!.safeParse(project).success || !PARAMS.environment!.safeParse(environment).success || personalOf(environment) !== null) return null;
  let raw: unknown;
  try {
    // Decoded and counted as the route reads it (`readJson`).
    raw = parseJsonBody(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).length === 0) return null;
  const parsed = check(secretPatch, raw);
  if (!parsed.success) return null;
  const patch: Record<string, SecretValue> = {};
  for (const [name, value] of Object.entries(parsed.data)) {
    if (value === null) return null;
    if (typeof value !== 'string' && !('generated' in value && value.generated.pair === undefined && value.sensitivity === undefined)) return null;
    // A regenerate's precondition as a version's id, as the vault takes it: any other string the route takes names no
    // version, which today's path answers 409 `stale` (review r1 of #469: here, the vault's check of its input, a 500).
    if (typeof value !== 'string' && 'replaces' in value && value.replaces !== undefined && !VERSION_ID.test(value.replaces)) return null;
    patch[name] = value;
  }
  return { project, environment, patch, names: Object.keys(patch) };
}

/** One try of a write: the vault's answer, the data keys it wrapped (the app's to encrypt under, then wipe) and the ids drawn for it. */
export type WriteTry = {
  answer: Extract<WriteKeysOutcome, { served: true }>;
  deks: Buffer[];
  operationId: string;
  versionIds: string[];
};

/**
 * A try the vault's decision refused on its read (PR 6): the route answers it, and the vault records it (`RefusalRecord`).
 * Its operation, which the record names and an expired ticket's 0.14 entry names too, as today's path's does.
 */
export type RefusedTry = { refused: RefusalRecord; operationId: string };

/** A try as the vault answered it: decided and prepared, or refused. */
export type Tried = WriteTry | RefusedTry;

/** What a try's answer says of its caller and its place, served or refused: the rows, the standing, the vault's clock. */
function answerOf(tried: Tried): { app: string; standing: WriteTry['answer']['standing']; at: number } {
  return 'refused' in tried ? tried.refused.refused : tried.answer;
}

/**
 * A write the vault decided, for the route to commit (`ApiContext.written`): its tries, each a new request of the
 * vault's, three in all (`heldWrite`); the place as the vault's read found it; the credential's last use, which its
 * transaction writes (`Touch`). Its data keys are wiped once used, or once it is let go.
 */
export class Written {
  readonly asked: WriteAsked;
  readonly place: ResolvedPath | null;
  readonly touched: Touch | null;
  readonly tokenHash: Buffer;
  #try: Tried | null;
  readonly #ask: () => Promise<Tried | string>;
  readonly #still: (tried: Tried) => Promise<boolean>;
  readonly #placeOf: (tried: Tried) => ResolvedPath | null;

  constructor(
    asked: WriteAsked, tokenHash: Buffer, first: Tried, place: ResolvedPath | null, touched: Touch | null,
    ask: () => Promise<Tried | string>, still: (tried: Tried) => Promise<boolean>, placeOf: (tried: Tried) => ResolvedPath | null,
  ) {
    this.asked = asked;
    this.tokenHash = tokenHash;
    this.#try = first;
    this.place = place;
    this.touched = touched;
    this.#ask = ask;
    this.#still = still;
    this.#placeOf = placeOf;
  }

  /**
   * Whether a try's read found the place at the environment the route writes to, by its ids: a try asks by the
   * slugs, which a rename and a new environment of the old name may have moved to another since the first (review r1
   * of #469). Its read and decision are that other's, so it commits nothing at this one.
   */
  at(tried: Tried, environment: { projectId: string; environmentId: string }): boolean {
    const place = this.#placeOf(tried);
    return place?.environment != null && place.project.id === environment.projectId && place.environment.id === environment.environmentId;
  }

  /** The try at hand, or null once let go. */
  get current(): Tried | null {
    return this.#try;
  }

  /** The try at hand's refusal, which the vault records in place of the entry its answer would append (`refuse`); else null. */
  get refusal(): RefusalRecord | null {
    return this.#try !== null && 'refused' in this.#try ? this.#try.refused : null;
  }

  /**
   * The write asked again, a request of its own, once the vault's read moved under it; or why the vault no longer
   * serves it (`WriteKeysOutcome.why`), the request then going down today's path, but for its credential, no longer
   * the caller's (`credential`: ended, or its rows not the same caller's, checked as the first's were), which answers
   * 401, as the credential's own check would: today's path would go on with the caller the first try checked.
   */
  async again(): Promise<Tried | string> {
    this.wipe();
    const next = await this.#ask();
    if (next === 'forged' || next === 'ended') return 'credential';
    if (typeof next === 'string') return next;
    if (!(await this.#still(next))) {
      wipeTry(next);
      return 'credential';
    }
    this.#try = next;
    return next;
  }

  /** Every data key at hand wiped, and nothing more tried. */
  wipe(): void {
    if (this.#try !== null) wipeTry(this.#try);
    this.#try = null;
  }
}

function wipeTry(tried: Tried): void {
  if ('deks' in tried) for (const dek of tried.deks) dek.fill(0);
}

/**
 * The write's first try, and its caller checked on the rows it answered: null where this path does not serve it (the
 * request goes as ever), or the credential's own answer where the rows do not bear out the caller (401, as ever).
 */
export async function writeAhead(
  runtime: CoffreRuntime,
  request: Request,
  sourceIp: string | null,
  token: string,
  asked: WriteAsked,
): Promise<{ identity: AuthenticatedIdentity | Response; written: Written | null } | null> {
  const kind = tokenKind(token);
  if (kind === null || !WRITE_KINDS.includes(kind) || runtime.vault.writeKeys === undefined || !(await vaultWrites(runtime.vault))) return null;
  // Refused on its kind alone (a service's token on a strict instance): by the credential's own check, as ever, with
  // nothing asked of the vault.
  if (refusedByKind(runtime, token) !== null) return null;
  const requestId = randomUUID();
  const tokenHash = hashToken(token);
  // A new key's id, drawn once: the same for every try, as the place holds none until one commits.
  const ids = asked.names.map(() => randomUUID());
  const ask = async (): Promise<Tried | string> => {
    const deks = asked.names.map(() => freshDek());
    const operationId = randomUUID();
    const versionIds = asked.names.map(() => randomUUID());
    try {
      const answer = await runtime.vault.writeKeys!({
        tokenHash: tokenHash.toString('base64'), accepts: acceptance(runtime), project: asked.project, environment: asked.environment,
        keys: asked.names.map((name, i) => {
          const value = asked.patch[name]!;
          return {
            name, id: ids[i]!, versionId: versionIds[i]!, key: deks[i]!.toString('base64'),
            ...(typeof value === 'object' && 'replaces' in value && value.replaces !== undefined ? { replaces: value.replaces } : {}),
          };
        }),
        operationId, requestId,
      });
      if (!answer.served) {
        for (const dek of deks) dek.fill(0);
        return 'ticket' in answer ? { refused: new RefusalRecord(runtime.vault, answer, 'secret.write'), operationId } : answer.why;
      }
      return { answer, deks, operationId, versionIds };
    } catch (error) {
      for (const dek of deks) dek.fill(0);
      throw error;
    }
  };
  const first = await ask();
  // The caller's credential not as its log has it (put back, or its change forged): refused, as an unknown one is, and
  // never down today's path, whose check of its MAC alone would take it.
  if (first === 'forged') return { identity: unauthenticated(runtime.auth), written: null };
  // Revoked or expired, as the log has it: as the credential's own check answers it (`authenticateRequest`), and not down
  // today's path, whose second read of the row would take one put back meanwhile (formal/Writing.tla, Today).
  if (first === 'ended') return { identity: endedCredential(), written: null };
  if (typeof first === 'string') return null;
  const rows = (tried: Tried) => namedAhead(runtime.db, answerOf(tried).app);
  const ahead = rows(first);
  let touched: Touch | null = null;
  // The credential checked on the rows the vault answered, its MAC and token's hash among them, its expiry at the
  // vault's `at` (one clock), its standing as the vault decided it (AuthChecked: before anything commits), and what
  // stands behind a person's, the passkey rows the read answered with it (T216; docs/design/passkeys.md, section 6.4):
  // refused, 401 `passkey_required` (or 401, 503, as it answers any), nothing written and what the vault prepared
  // dropped, its refusal, if it refused, never recorded.
  const identity = await authenticateRequest(request, runtime, requestId, token, sourceIp, {
    standing: answerOf(first).standing, at: answerOf(first).at, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
    touch: (touch) => {
      touched = touch;
    },
  });
  if (identity instanceof Response || !identity.registered) {
    wipeTry(first);
    return { identity, written: null };
  }
  const credentialId = identity.credentialId;
  // A later try's rows, checked as the first's were: the same credential, its rows' MACs whole (`findCredential` reads
  // nothing given them, nor what stands behind it, which the first try's check decided on).
  const still = async (tried: Tried): Promise<boolean> => {
    const credential = rows(tried)?.credential;
    if (credential == null) return false;
    try {
      const row = await findCredential(runtime.db, runtime.chainKey, { tokenHash }, credential, false);
      return row !== null && row.id === credentialId;
    } catch {
      return false;
    }
  };
  return { identity, written: new Written(asked, tokenHash, first, ahead?.place ?? null, touched, ask, still, (tried) => rows(tried)?.place ?? null) };
}
