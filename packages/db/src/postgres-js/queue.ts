/** A queue that takes from either end, and lets go of what it took. */
export class Queue<T> {
  #xs: (T | undefined)[] = [];
  #index = 0;

  get length(): number {
    return this.#xs.length - this.#index;
  }

  push(x: T): T {
    this.#xs.push(x);
    return x;
  }

  remove(x: T): T | null {
    const index = this.#xs.indexOf(x);
    if (index === -1) return null;
    this.#xs.splice(index, 1);
    return x;
  }

  // Coffre: the newest, for the pool to take the connection idle the shortest, as pg-pool does: the others stay
  // idle, and close once idle_timeout passes, and the backends used stay few and warm.
  pop(): T | undefined {
    if (this.#xs.length === this.#index) return undefined;
    const out = this.#xs.pop();
    if (this.#index === this.#xs.length) this.#clear();
    return out;
  }

  shift(): T | undefined {
    const out = this.#xs[this.#index++];
    if (this.#index === this.#xs.length) this.#clear();
    else this.#xs[this.#index - 1] = undefined;
    return out;
  }

  #clear(): void {
    this.#index = 0;
    this.#xs = [];
  }
}
