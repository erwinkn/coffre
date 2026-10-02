// A list of steps as they run: every step shown from the start, dim until
// its turn, a spinner while it runs, then a check or a cross. On a terminal
// the list redraws in place; elsewhere each step prints one plain line when
// it ends.
import { Cancelled, type Keyboard, type Output, style, type Style, truncate, wrap, yes } from './tty.ts';

const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const FRAME_MS = 80;

type State = { text: string; status: 'pending' | 'running' | 'asking' | 'done' | 'failed'; details: string[] };

/** What a running step can do: say what it is doing now, and ask a yes-or-no question. */
export type Step = {
  note(text: string): void;
  ask(question: string): Promise<boolean>;
};

/** How a step ended: its line, and lines under it. */
export type Outcome = string | { text: string; details: string[] };

export class Steps {
  readonly #out: Output;
  readonly #s: Style;
  readonly #steps: State[];
  readonly #keys: () => Keyboard | null;
  readonly #describe: (error: unknown) => string;
  #frame = 0;
  #drawn = 0;
  #timer: NodeJS.Timeout | null = null;
  readonly #restoreCursor = () => this.#out.write('\x1b[?25h');
  /** Ctrl-C while a step runs, the terminal in its usual mode: the cursor back, then out, with nothing more to show. */
  readonly #interrupt = () => {
    this.#stop();
    this.end();
    this.#out.write('\n');
    process.exit(130);
  };

  /**
   * `titles`, what each step does while it runs; `keys`, the keyboard for
   * questions; `describe`, an error as it may be shown, a secret it quotes
   * taken out.
   */
  constructor(out: Output, titles: string[], keys: () => Keyboard | null, describe: (error: unknown) => string) {
    this.#out = out;
    this.#s = style(out);
    this.#keys = keys;
    this.#describe = describe;
    this.#steps = titles.map((text) => ({ text, status: 'pending', details: [] }));
    if (this.#s.ansi) {
      out.write('\x1b[?25l');
      process.once('exit', this.#restoreCursor);
      process.on('SIGINT', this.#interrupt);
      this.#draw();
    }
  }

  /** Run step `i`: its line is the outcome `work` returns, or the error it throws. */
  async run(i: number, work: (step: Step) => Promise<Outcome>): Promise<void> {
    const state = this.#steps[i]!;
    state.status = 'running';
    this.#tick();
    const step: Step = {
      note: (text) => {
        state.text = text;
        this.#draw();
      },
      ask: (question) => this.#ask(state, question),
    };
    try {
      const outcome = await work(step);
      Object.assign(state, typeof outcome === 'string' ? { text: outcome, details: [] } : outcome, { status: 'done' });
    } catch (error) {
      state.status = 'failed';
      state.details = error instanceof Cancelled ? [] : [this.#describe(error)];
      if (error instanceof Cancelled) state.text = `${state.text}: cancelled`;
      this.#stop();
      throw error;
    }
    this.#stop();
    if (!this.#s.ansi) this.#out.write(`✓ ${state.text}\n${state.details.map((line) => `  ${line}\n`).join('')}`);
    else if (this.#steps.every((each) => each.status === 'done')) this.end();
  }

  /** Leave the list as it stands, the cursor below it. */
  end(): void {
    this.#stop();
    if (this.#s.ansi) {
      this.#restoreCursor();
      process.off('exit', this.#restoreCursor);
      process.off('SIGINT', this.#interrupt);
    }
  }

  async #ask(state: State, question: string): Promise<boolean> {
    const keys = this.#keys();
    if (keys === null) return false;
    this.#stop();
    const before = state.text;
    state.text = `${question} ${this.#s.dim('y/N')}`;
    state.status = 'asking';
    this.#draw();
    try {
      return await yes(keys);
    } finally {
      state.text = before;
      state.status = 'running';
      this.#tick();
    }
  }

  #tick(): void {
    this.#draw();
    if (this.#s.ansi && this.#timer === null) {
      this.#timer = setInterval(() => {
        this.#frame = (this.#frame + 1) % SPINNER.length;
        this.#draw();
      }, FRAME_MS);
    }
  }

  #stop(): void {
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
    this.#draw();
    if (!this.#s.ansi) {
      const failed = this.#steps.find((each) => each.status === 'failed');
      if (failed !== undefined) this.#out.write(`✗ ${failed.text}\n${failed.details.map((line) => `  ${line}\n`).join('')}`);
    } else if (this.#steps.some((each) => each.status === 'failed')) {
      this.end();
    }
  }

  #draw(): void {
    if (!this.#s.ansi) return;
    const s = this.#s;
    const columns = Math.max(20, (this.#out.columns ?? 80) - 1);
    const lines = this.#steps.flatMap(({ text, status, details }) => {
      const icon = {
        pending: s.dim('·'),
        running: s.accent(SPINNER[this.#frame]!),
        asking: s.accent('?'),
        done: s.green('✓'),
        failed: s.red('✗'),
      }[status];
      const line = status === 'pending' ? s.dim(text) : status === 'failed' ? s.red(text) : text;
      // An error is wrapped, to be read whole; what a step found is one line each.
      const under = status === 'failed' ? details.flatMap((detail) => wrap(detail, columns - 4)) : details.map(s.dim);
      return [`  ${icon} ${line}`, ...under.map((detail) => `    ${detail}`)];
    });
    const up = this.#drawn > 0 ? `\x1b[${this.#drawn}F` : '';
    this.#out.write(`${up}${lines.map((line) => `${truncate(line, columns)}\x1b[K\n`).join('')}\x1b[J`);
    this.#drawn = lines.length;
  }
}
