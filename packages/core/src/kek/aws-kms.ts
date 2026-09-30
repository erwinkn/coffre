import { checkContext, type SecretContext } from '../context.ts';
import { signV4, type AwsCredentials } from './sigv4.ts';
import { DEK_BYTES, KekUnavailableError, type KekProvider, type WrappedDek } from './types.ts';

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

const ATTEMPTS = 3;
const TIMEOUT_MS = 5_000;
/** Calls in flight at once. A Worker opens at most six connections anyway. */
const CONCURRENCY = 8;
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
  readonly #slots = new Slots(CONCURRENCY);

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

  async wrap(dek: Buffer, ctx: SecretContext): Promise<WrappedDek> {
    if (dek.length !== DEK_BYTES) throw new Error(`DEK must be ${DEK_BYTES} bytes, got ${dek.length}`);
    const { CiphertextBlob } = await this.#call('Encrypt', {
      KeyId: this.keyId,
      Plaintext: base64(dek),
      EncryptionContext: encryptionContext(ctx),
    });
    return {
      kekProvider: this.provider,
      kekId: this.keyId,
      kekVersion: this.keyVersion,
      bytes: Buffer.from(CiphertextBlob, 'base64'),
    };
  }

  async unwrap(wrapped: WrappedDek, ctx: SecretContext): Promise<Buffer> {
    if (wrapped.kekProvider !== this.provider || wrapped.kekId !== this.keyId) {
      throw new Error(`wrapped DEK is for ${wrapped.kekProvider}:${wrapped.kekId}, not ${this.provider}:${this.keyId}`);
    }
    // KeyId makes KMS refuse a ciphertext made under any other key.
    const { Plaintext, KeyId } = await this.#call('Decrypt', {
      KeyId: this.keyId,
      CiphertextBlob: base64(wrapped.bytes),
      EncryptionContext: encryptionContext(ctx),
    });
    if (KeyId !== this.keyId) throw new Error(`KMS decrypted under ${KeyId}, not ${this.keyId}`);
    const dek = Buffer.from(Plaintext, 'base64');
    if (dek.length !== DEK_BYTES) throw new Error('unwrapped DEK has the wrong length');
    return dek;
  }

  /**
   * One KMS call, tried up to three times while KMS throttles, fails on its
   * side or does not answer. Every failure but a ciphertext that does not
   * open is a `KekUnavailableError`, retried or not: a key KMS will not use
   * or credentials it refuses say nothing about the claim either.
   */
  async #call(action: 'Encrypt' | 'Decrypt', request: object): Promise<Record<string, string>> {
    const body = JSON.stringify(request);
    return this.#slots.run(async () => {
      let credentials: AwsCredentials;
      try {
        credentials = await this.#credentials();
      } catch (error) {
        throw new KekUnavailableError(`no AWS credentials for KMS: ${messageOf(error)}`);
      }
      for (let attempt = 1; ; attempt++) {
        const answer = await this.#send(action, body, credentials);
        if ('data' in answer) return answer.data;
        if (NOT_THIS_KEY.has(answer.type)) throw new Error(`KMS ${action}: ${answer.type}`);
        if (!answer.retry || attempt === ATTEMPTS) {
          throw new KekUnavailableError(`KMS ${action} failed${attempt > 1 ? ` ${attempt} times` : ''}: ${answer.failure}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 100 * 4 ** (attempt - 1) * (1 + Math.random())));
      }
    });
  }

  async #send(
    action: string,
    body: string,
    credentials: AwsCredentials,
  ): Promise<{ data: Record<string, string> } | { type: string; failure: string; retry: boolean }> {
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
    try {
      response = await this.#fetch(this.#url, { method: 'POST', headers, body, signal: AbortSignal.timeout(TIMEOUT_MS) });
      text = await response.text();
    } catch (error) {
      return { type: 'network', failure: messageOf(error), retry: true };
    }
    const parsed = parse(text);
    if (response.ok) {
      const complete =
        parsed !== null && (action === 'Encrypt' ? typeof parsed.CiphertextBlob === 'string' : typeof parsed.Plaintext === 'string');
      if (complete) return { data: parsed as Record<string, string> };
      return { type: 'malformed', failure: `KMS answered ${response.status} without a result`, retry: true };
    }
    // `__type` may carry a namespace (`com.amazonaws.kms#…`), the header a URL after `:`.
    const raw = response.headers.get('x-amzn-errortype') ?? (typeof parsed?.__type === 'string' ? parsed.__type : '');
    const type = raw.split(':')[0]!.split('#').pop() || `HTTP ${response.status}`;
    const message = parsed?.message ?? parsed?.Message;
    return {
      type,
      failure: `${type}${typeof message === 'string' ? `, ${message}` : ''}`,
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
  return { 'coffre:project': ctx.projectId, 'coffre:environment': ctx.environmentId, 'coffre:secret': ctx.secretId };
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
  readonly #waiting: (() => void)[] = [];

  constructor(n: number) {
    this.#free = n;
  }

  async run<T>(work: () => Promise<T>): Promise<T> {
    if (this.#free > 0) this.#free--;
    else await new Promise<void>((resolve) => this.#waiting.push(resolve));
    try {
      return await work();
    } finally {
      const next = this.#waiting.shift();
      if (next) next();
      else this.#free++;
    }
  }
}
