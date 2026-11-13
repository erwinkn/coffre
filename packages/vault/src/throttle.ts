import { USE_DEADLINE_MS } from '@coffre/core/vault';

/**
 * Adaptive throttling (Google's SRE book, "Handling Overload"; docs/design/config.md, Q1, step 2). An isolate counts,
 * over the last two use deadlines, the uses it has answered or refused (`requests`) and those that settled before their
 * deadline (`accepts`: answered, refused by policy or failed at once, but not `late`), and refuses a new use at once, `overloaded`, at the rate
 *
 *   p = max(0, (requests − K × accepts) ÷ (requests + 1)),   K = 1.5,   window = 2 × 3 s
 *
 * So it lets through about K times what it answered in time, and refuses the rest before it costs a statement or a
 * place. The book's numbers, K = 2 and two minutes, failed on Cloudflare (the first run, config.md): the excess
 * this vault lets through is not refused cheaply downstream but goes `late`, holding its place and a hot connection
 * for the whole 3 s, so K = 2 let half the burst go late; and a two-minute window kept refusing a light load three
 * minutes after the burst. Each number here comes from that, as config.md derives:
 *
 * - The window is two deadlines, nominally 6 s (a count leaves it 5 to 6 s after it lands, by where in its second it
 *   fell): a use's outcome is known at most one deadline after it is asked, so the window weighs the asks whose
 *   outcomes are in, not only the newest seconds' in-time answers, and the burst's last late uses leave it about one
 *   window after they settle.
 * - K is bounded on both sides and set between. Below, recovery: refused uses count as requests, so after an overload
 *   what an isolate lets through grows each window by roughly K. That is a large-count approximation, not a bound
 *   (overlapping windows let it grow faster, and the + 1 lets even K = 1 recover at a trickle), but it is why K must
 *   sit well above 1: near 1 the refusals long outlive the overload. Above, the late: past K × the vault's capacity
 *   everything is refused, and the K − 1 between goes late; at 2,500 uses a second against about 1,000 answered, the
 *   late outnumber the refused from K = 1.75 up. K = 1.5 sits inside both (config.md, Q1, step 2): in its model, a
 *   third of such a burst's excess late, and full service again 9 to 12 s after it at 500 a second (about 17 s if the
 *   load drops to 50); the second Cloudflare run is to confirm it.
 *
 * p stays below 1, so an isolate never shuts and needs no rule to open again. A use refused counts as a request, not
 * an accept, as the book counts it: that keeps what an isolate lets through at K times its accepts however much is
 * offered.
 *
 * Two departures from the book, both about when and how, not how much:
 * - A use counts once its outcome is known, not when it is asked: one still in flight is neither a success nor a
 *   failure yet. Counted on arrival, a cold isolate's burst would refuse itself: its 17th use of 16 in flight, none
 *   answered yet, would see p = 16 ÷ 17.
 * - The refusals are spread, not drawn: each use adds p to a credit, and is refused when the credit reaches 1, which
 *   takes 1 back. At p = 0.2, one use in five is refused, in a fixed pattern rather than at random; the same rate,
 *   reproducible (`refuses`).
 *
 *   2,500 uses a second offered, 1,040 answered in time, for a window: 15,000 requests, 6,240 accepts
 *     → p = (15,000 − 9,360) ÷ 15,001 ≈ 38% refused at once; about 1,560 a second let through, 520 of them late
 *   a cold isolate whose first use was late: 1 request, 0 accepts → p = 1 ÷ 2: of the next two uses, one refused
 */
export const THROTTLE_K = 1.5;
export const THROTTLE_WINDOW_MS = 2 * USE_DEADLINE_MS;
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
