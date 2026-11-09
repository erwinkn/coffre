/**
 * Adaptive throttling (Google's SRE book, "Handling Overload"; docs/design/config.md, Q1, step 2). An isolate counts,
 * over the last two minutes, the uses it has answered or refused (`requests`) and those that settled before their
 * deadline (`accepts`: answered, refused by policy or failed at once, but not `late`), and refuses a new use at once, `overloaded`, at the rate
 *
 *   p = max(0, (requests − K × accepts) ÷ (requests + 1)),   K = 2
 *
 * Both numbers are the book's. Nothing is refused while the vault answers at least half of its uses in time; past
 * that, part of the excess is refused before it costs a statement or a place. p stays below 1, so an isolate never
 * shuts and needs no rule to open again: as uses are answered in time, accepts catch up and refusals stop, with the
 * failures still in the window. A use refused counts as a request, not an accept, as the book counts it.
 *
 * Two departures from the book, both about when and how, not how much:
 * - A use counts once its outcome is known, not when it is asked: one still in flight is neither a success nor a
 *   failure yet. Counted on arrival, a cold isolate's burst would refuse itself: its 17th use of 16 in flight, none
 *   answered yet, would see p = 16 ÷ 17.
 * - The refusals are spread, not drawn: each use adds p to a credit, and is refused when the credit reaches 1, which
 *   takes 1 back. At p = 0.17, one use in six is refused, in a fixed pattern rather than at random; the same rate,
 *   reproducible (`refuses`).
 *
 *   2,500 uses a second offered, 1,040 answered in time, for two minutes: 300,000 requests, 124,800 accepts
 *     → p = (300,000 − 249,600) ÷ 300,001 ≈ 17% refused at once; the rest of the excess is still answered `late`
 *   a cold isolate whose first use was late: 1 request, 0 accepts → p = 1 ÷ 2: of the next two uses, one refused
 */
export const THROTTLE_K = 2;
export const THROTTLE_WINDOW_MS = 120_000;
/** The window in buckets of a second: the oldest second leaves as a new one starts. */
const BUCKET_MS = 1_000;
const BUCKETS = THROTTLE_WINDOW_MS / BUCKET_MS;

export class Throttle {
  readonly #requests = new Float64Array(BUCKETS);
  readonly #accepts = new Float64Array(BUCKETS);
  #requested = 0;
  #accepted = 0;
  /** The refusals owed: p added for each use asked, 1 taken back for each refused. */
  #credit = 0;
  /** The second the newest bucket is for. */
  #second = -Infinity;

  /** Whether a use asked at `now` is refused, then counted as a request; if not, its answer counts it (`answered`). */
  refuses(now: number): boolean {
    const p = this.rate(now);
    if (p === 0) {
      this.#credit = 0;
      return false;
    }
    this.#credit += p;
    if (this.#credit < 1) return false;
    this.#credit -= 1;
    this.#count(now, false);
    return true;
  }

  /** A use not refused here has answered at `now`: `inTime`, before its deadline, or not (`late`, or it failed). */
  answered(now: number, inTime: boolean): void {
    this.#roll(now);
    this.#count(now, inTime);
  }

  /** The share of the uses asked at `now` that are refused, p. */
  rate(now: number): number {
    this.#roll(now);
    return Math.max(0, (this.#requested - THROTTLE_K * this.#accepted) / (this.#requested + 1));
  }

  #count(now: number, accepted: boolean): void {
    const i = bucket(now);
    this.#requests[i] += 1;
    this.#requested += 1;
    if (!accepted) return;
    this.#accepts[i] += 1;
    this.#accepted += 1;
  }

  /** Empties the buckets of the seconds since the newest, which the window has left. */
  #roll(now: number): void {
    const second = Math.floor(now / BUCKET_MS);
    if (second <= this.#second) return;
    // The first call, or a gap of a whole window or more: every bucket empties.
    const gone = Math.min(BUCKETS, second - this.#second);
    for (let s = second - gone + 1; s <= second; s += 1) {
      const i = s % BUCKETS;
      this.#requested -= this.#requests[i]!;
      this.#accepted -= this.#accepts[i]!;
      this.#requests[i] = 0;
      this.#accepts[i] = 0;
    }
    this.#second = second;
  }
}

const bucket = (now: number) => Math.floor(now / BUCKET_MS) % BUCKETS;
