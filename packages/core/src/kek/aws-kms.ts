import { checkContext, type SecretContext } from '../context.ts';
import { signV4, type AwsCredentials } from './sigv4.ts';
import { cancellable, checkOperation, delay, operationSignal } from './cancellation.ts';
import {
  DEK_BYTES,
  KekBadClaimError,
  KekCancelledError,
  KekUnavailableError,
  type KeyOperation,
  type KekProvider,
  type WrappedDek,
} from './types.ts';

export type AwsKmsOptions = {
  /**
   * The key's ARN, `arn:aws:kms:<region>:<account>:key/<id>`. Coffre calls
   * KMS in that region, and records the ARN on every data key it wraps. Not
   * an alias, which can come to name another key.
   */
  keyArn: string;
  /**
   * An access key allowed `kms:Encrypt` and `kms:Decrypt` on it, or a
   * function that returns one, asked before each call so that it may refresh
   * (an AWS SDK credential provider is one).
   */
  credentials: AwsCredentials | (() => Promise<AwsCredentials>);
  /** For tests. */
  fetch?: typeof fetch;
};

const KEY_ARN = /^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):\d{12}:key\/[A-Za-z0-9-]{1,128}$/;

/** How many times one KMS request is tried, while KMS throttles, fails on its side or does not answer: a retry policy. */
export const KMS_ATTEMPTS = 3;

/**
 * How long one attempt waits for KMS's answer, at most; less when its operation's deadline comes first (each attempt
 * is cut at what is left of it). From a measurement (W331, 2026-11-07; #538's thread): coffre's own requests to a key in
 * us-east-2, p50 / p95 / p99 / max in ms, 475-500 calls each of Encrypt, Decrypt and GenerateDataKey:
 *
 *   a Worker placed next to the key (ORD)     19-20 / 23-64 / 60-70 / 70-92
 *   a Worker an ocean away (WAW)              124 / 128-487 / 132-506 / 299-517
 *   a host in Helsinki, a new connection each 362-365 / 388-406 / 410-413 / 412-415
 *
 * A request on a connection kept is one round trip and a few ms of KMS's; on a new one about four (TCP, TLS, the
 * request). So: the slowest p99 measured, 506 ms (a far Worker's Encrypt on a new connection), and one lost segment's
 * retransmission at Linux's least retransmission timeout, 200 ms (`TCP_RTO_MIN`, include/net/tcp.h; Cloudflare's and
 * Node's hosts taken to use Linux's, not checked): 706 ms. Past it the request is taken for lost, and tried again.
 */
export const KMS_ATTEMPT_MS = 506 + 200;

/** The pause before the `attempt`th try after a failure, at most: 100 ms × 4^(attempt-1), jittered up to twice. */
const backoffMs = (attempt: number) => 100 * 4 ** (attempt - 1) * (1 + Math.random());

/**
 * The longest one KMS request may take, all its attempts and pauses, on a path with no deadline of its own: 3 × 706 ms
 * and pauses of at most 200 and 800 ms, 3,118 ms. Every path the vault takes has a deadline (its operation's), which cuts
 * each attempt and starts no attempt nor pause past it: a use's, 3 s (`USE_DEADLINE_MS`), answers by it. Not a bound
 * of a use's, nor one anyone waits on: what a key read or write without a deadline would take at worst.
 */
export const KMS_REQUEST_MAX_MS = KMS_ATTEMPTS * KMS_ATTEMPT_MS + Array.from({ length: KMS_ATTEMPTS - 1 }, (_, i) => 200 * 4 ** i).reduce((a, b) => a + b, 0);

/**
 * How many of one call's KMS requests are in flight at once (an operation's: a read of many keys, a wrap of many):
 * Workers lets an invocation have six connections waiting for their response headers, a service binding's callee
 * sharing its caller's, and queues the seventh (developers.cloudflare.com/workers/platform/limits, "Simultaneous open
 * connections"). A vault call's own Hyperdrive socket counts only while it opens, before the call's first KMS request
 * (every path queries first). The same six on Node. Each call's requests wait for each other alone, never another
 * call's (formal/KeyService.tla, SlotsPerCall): no request waits behind another request's hung KMS calls, nor for a
 * promise another settles (AGENTS.md, "What an isolate keeps").
 */
const CONCURRENCY = 6;
/** What KMS says when the ciphertext does not open under this key and context: a bad claim, not an outage. */
const NOT_THIS_KEY = new Set(['InvalidCiphertextException', 'IncorrectKeyException']);

/** A KEK held in AWS KMS: it never leaves, and coffre asks KMS to wrap and unwrap each data key. */
export function awsKms(options: AwsKmsOptions): KekProvider {
  return new AwsKmsKekProvider(options);
}

/**
 * KMS's JSON API, `Encrypt` and `Decrypt`, signed with SigV4 and no SDK, so
 * it runs as is on Node and in a Worker. Each call sends the secret's UUIDs
 * as the encryption context, which KMS binds to the ciphertext and CloudTrail
 * logs with the call: every decrypt there names the secret it was for, in a
 * log neither coffre nor whoever runs it can edit.
 */
export class AwsKmsKekProvider implements KekProvider {
  readonly provider = 'aws-kms';
  readonly keyId: string;
  /** KMS keeps its own versions inside each ciphertext, and rotates the key material under the same ARN. */
  readonly keyVersion = '1';

  readonly #region: string;
  readonly #url: URL;
  readonly #credentials: () => Promise<AwsCredentials>;
  readonly #fetch: typeof fetch;
  /** Each operation's own slots (`CONCURRENCY`), kept while it lives: one call's requests take turns among themselves. */
  readonly #slots = new WeakMap<KeyOperation, Slots>();

  constructor(options: AwsKmsOptions) {
    const match = KEY_ARN.exec(options.keyArn);
    if (match === null) {
      throw new Error(
        `the KMS key must be a key ARN, like arn:aws:kms:eu-west-3:123456789012:key/<id>, not an alias; got "${options.keyArn}"`,
      );
    }
    const [, partition, region] = match as unknown as [string, string, string];
    this.keyId = options.keyArn;
    this.#region = region;
    this.#url = new URL(`https://kms.${region}.amazonaws.com${partition === 'aws-cn' ? '.cn' : ''}/`);
    const { credentials } = options;
    this.#credentials = typeof credentials === 'function' ? credentials : async () => credentials;
    // Called bare: a Worker's fetch refuses to run as a method of anything else.
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
  }

  async wrap(dek: Buffer, ctx: SecretContext, operation?: KeyOperation): Promise<WrappedDek> {
    if (dek.length !== DEK_BYTES) throw new Error(`DEK must be ${DEK_BYTES} bytes, got ${dek.length}`);
    const { CiphertextBlob } = await this.#call('Encrypt', {
      KeyId: this.keyId,
      Plaintext: base64(dek),
      EncryptionContext: encryptionContext(ctx),
    }, operation);
    return {
      kekProvider: this.provider,
      kekId: this.keyId,
      kekVersion: this.keyVersion,
      bytes: Buffer.from(CiphertextBlob, 'base64'),
    };
  }

  async unwrap(wrapped: WrappedDek, ctx: SecretContext, operation?: KeyOperation): Promise<Buffer> {
    if (wrapped.kekProvider !== this.provider || wrapped.kekId !== this.keyId) {
      throw new KekBadClaimError(`wrapped DEK is for ${wrapped.kekProvider}:${wrapped.kekId}, not ${this.provider}:${this.keyId}`);
    }
    // KeyId makes KMS refuse a ciphertext made under any other key.
    const { Plaintext, KeyId } = await this.#call('Decrypt', {
      KeyId: this.keyId,
      CiphertextBlob: base64(wrapped.bytes),
      EncryptionContext: encryptionContext(ctx),
    }, operation);
    if (KeyId !== this.keyId) throw new KekUnavailableError(`KMS decrypted under ${KeyId}, not ${this.keyId}`, true);
    const dek = Buffer.from(Plaintext, 'base64');
    if (dek.length !== DEK_BYTES) {
      dek.fill(0);
      throw new KekUnavailableError('unwrapped DEK has the wrong length', true);
    }
    return dek;
  }

  /**
   * One KMS call, tried up to three times while KMS throttles, fails on its
   * side or does not answer. Every failure but a ciphertext that does not
   * open is a `KekUnavailableError`, retried or not: a key KMS will not use
   * or credentials it refuses say nothing about the claim either.
   */
  async #call(action: 'Encrypt' | 'Decrypt', request: object, operation?: KeyOperation): Promise<Record<string, string>> {
    const body = JSON.stringify(request);
    const signal = operationSignal(operation);
    // A request with no operation is a call of its own: one request, nothing to take turns with.
    const slots = operation === undefined ? new Slots(CONCURRENCY) : this.#slots.get(operation) ?? new Slots(CONCURRENCY);
    if (operation !== undefined) this.#slots.set(operation, slots);
    return slots.run(async () => {
      checkOperation(operation);
      let credentials: AwsCredentials;
      try {
        credentials = await cancellable(this.#credentials(), signal);
      } catch (error) {
        if (error instanceof KekCancelledError) throw error;
        throw new KekUnavailableError(`no AWS credentials for KMS: ${messageOf(error)}`);
      }
      let uncertain = false;
      for (let attempt = 1; ; attempt++) {
        checkOperation(operation, uncertain);
        if (signal?.aborted) throw new KekCancelledError(uncertain);
        const answer = await this.#send(action, body, credentials, signal, operation);
        if ('data' in answer) return answer.data;
        uncertain ||= answer.uncertain;
        checkOperation(operation, uncertain);
        if (signal?.aborted) throw new KekCancelledError(uncertain);
        if (NOT_THIS_KEY.has(answer.type)) {
          if (uncertain) throw new KekUnavailableError(`KMS ${action}: ${answer.type} after an unanswered request`, true);
          throw new KekBadClaimError(`KMS ${action}: ${answer.type}`);
        }
        if (!answer.retry || attempt === KMS_ATTEMPTS) {
          throw new KekUnavailableError(`KMS ${action} failed${attempt > 1 ? ` ${attempt} times` : ''}: ${answer.failure}`, uncertain);
        }
        // No pause that would end past the deadline: no attempt could start after it, so the call ends now, cancelled by
        // its deadline as it would be at it (`KekCancelledError`), rather than wait for it.
        const pause = backoffMs(attempt);
        if (operation !== undefined && Date.now() + pause >= operation.deadline) throw new KekCancelledError(uncertain);
        try {
          await delay(pause, signal);
        } catch (error) {
          if (error instanceof KekCancelledError) throw new KekCancelledError(uncertain);
          throw error;
        }
      }
    }, signal);
  }

  async #send(
    action: string,
    body: string,
    credentials: AwsCredentials,
    signal?: AbortSignal,
    operation?: KeyOperation,
  ): Promise<{ data: Record<string, string> } | { type: string; failure: string; retry: boolean; uncertain: boolean }> {
    const headers = signV4({
      method: 'POST',
      url: this.#url,
      headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': `TrentService.${action}` },
      body,
      region: this.#region,
      service: 'kms',
      credentials,
      date: new Date(),
    });
    let response: Response;
    let text: string;
    let sent = false;
    try {
      checkOperation(operation);
      if (signal?.aborted) throw new KekCancelledError();
      sent = true;
      response = await this.#fetch(this.#url, {
        method: 'POST', headers, body,
        // An attempt waits `KMS_ATTEMPT_MS` at most, and no longer than what is left of its operation's deadline: then the
        // operation's own signal ends it, the one timer of the deadline, so no slot frees a moment before it (review r1).
        signal: operation !== undefined && operation.deadline - Date.now() <= KMS_ATTEMPT_MS && signal !== undefined
          ? signal
          : AbortSignal.any([AbortSignal.timeout(KMS_ATTEMPT_MS), ...(signal === undefined ? [] : [signal])]),
      });
      text = await response.text();
    } catch (error) {
      return { type: 'network', failure: messageOf(error), retry: sent, uncertain: sent };
    }
    const parsed = parse(text);
    if (response.ok) {
      const complete =
        parsed !== null && (action === 'Encrypt' ? typeof parsed.CiphertextBlob === 'string' : typeof parsed.Plaintext === 'string');
      if (complete) return { data: parsed as Record<string, string> };
      return { type: 'malformed', failure: `KMS answered ${response.status} without a result`, retry: true, uncertain: true };
    }
    // `__type` may carry a namespace (`com.amazonaws.kms#…`), the header a URL after `:`.
    const raw = response.headers.get('x-amzn-errortype') ?? (typeof parsed?.__type === 'string' ? parsed.__type : '');
    const type = raw.split(':')[0]!.split('#').pop() || `HTTP ${response.status}`;
    const message = parsed?.message ?? parsed?.Message;
    return {
      type,
      failure: `${type}${typeof message === 'string' ? `, ${message}` : ''}`,
      uncertain: false,
      retry: response.status >= 500 || response.status === 429 || type === 'ThrottlingException',
    };
  }
}

/**
 * The secret's UUIDs, as KMS binds them to the ciphertext and CloudTrail
 * shows them. Checked first, so a malformed one never reaches KMS.
 */
function encryptionContext(ctx: SecretContext): Record<string, string> {
  checkContext(ctx);
  return {
    'coffre:project': ctx.projectId,
    'coffre:environment': ctx.environmentId,
    'coffre:secret': ctx.secretId,
    // A personal config's owner, hashed: KMS refuses to decrypt under any other.
    ...(ctx.owner === undefined ? {} : { 'coffre:owner': ctx.owner }),
    // A sensitive value's: KMS refuses to decrypt it as anything else.
    ...(ctx.sensitive === true ? { 'coffre:sensitive': 'true' } : {}),
  };
}

/**
 * Bytes as base64. Through `Buffer.from`, a view of the same memory, because
 * Workers' types declare their own `Buffer` and a bare one loses its
 * `toString(encoding)` to them.
 */
function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
}

function parse(text: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(text) as unknown;
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** At most `n` calls at once; the rest wait their turn. */
class Slots {
  #free: number;
  readonly #waiting: { start: () => void; cancel: () => void }[] = [];

  constructor(n: number) {
    this.#free = n;
  }

  async run<T>(work: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (signal?.aborted) throw new KekCancelledError();
    if (this.#free > 0) this.#free--;
    else await new Promise<void>((resolve, reject) => {
      const waiting = {
        start: () => {
          signal?.removeEventListener('abort', waiting.cancel);
          resolve();
        },
        cancel: () => {
          const index = this.#waiting.indexOf(waiting);
          if (index >= 0) this.#waiting.splice(index, 1);
          signal?.removeEventListener('abort', waiting.cancel);
          reject(new KekCancelledError());
        },
      };
      this.#waiting.push(waiting);
      signal?.addEventListener('abort', waiting.cancel, { once: true });
    });
    try {
      if (signal?.aborted) throw new KekCancelledError();
      return await work();
    } finally {
      const next = this.#waiting.shift();
      if (next) next.start();
      else this.#free++;
    }
  }
}
