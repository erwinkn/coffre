import { Buffer } from 'node:buffer';

/** The NUL that ends a string in the protocol. */
export const N = '\0';

const SIZE = 256;

/**
 * The message being written: started with its type (`b.typed('Q')`), or
 * none (`b.untyped()`, for the startup's and the SSLRequest's), then its
 * fields, then `end()`, which writes its length and hands it over. One at a
 * time, each written whole before the next starts.
 */
class Writer {
  #buffer = Buffer.allocUnsafe(SIZE);
  /** Where the next field goes. */
  i = 0;

  /** A message of `type`, a letter: its length, written by `end()`, follows it. */
  typed(type: string): this {
    this.#buffer[0] = type.charCodeAt(0);
    this.i = 5;
    return this;
  }

  untyped(): this {
    this.i = 0;
    return this;
  }

  /** Skip `n` bytes, to be written later (`i32(x, at)`). */
  inc(n: number): this {
    this.i += n;
    return this;
  }

  str(x: string): this {
    const length = Buffer.byteLength(x);
    this.#fit(length);
    this.i += this.#buffer.write(x, this.i, length, 'utf8');
    return this;
  }

  i16(x: number): this {
    this.#fit(2);
    this.#buffer.writeUInt16BE(x, this.i);
    this.i += 2;
    return this;
  }

  /** `x` next, or at `at`, a place skipped before. */
  i32(x: number, at?: number): this {
    if (at !== undefined) {
      this.#buffer.writeUInt32BE(x, at);
      return this;
    }
    this.#fit(4);
    this.#buffer.writeUInt32BE(x, this.i);
    this.i += 4;
    return this;
  }

  /** `n` zero bytes. */
  z(n: number): this {
    this.#fit(n);
    this.#buffer.fill(0, this.i, this.i + n);
    this.i += n;
    return this;
  }

  /** The message, its length written at `at`: 1 after a type, 0 for an untyped one. */
  end(at = 1): Buffer {
    this.#buffer.writeUInt32BE(this.i - at, at);
    const out = this.#buffer.subarray(0, this.i);
    this.i = 0;
    this.#buffer = Buffer.allocUnsafe(SIZE);
    return out;
  }

  #fit(n: number): void {
    if (this.#buffer.length - this.i < n) {
      const prev = this.#buffer;
      this.#buffer = Buffer.allocUnsafe(prev.length + (prev.length >> 1) + n);
      prev.copy(this.#buffer);
    }
  }
}

export const b = new Writer();
