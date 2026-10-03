// A list of steps as they run: every step shown from the start, dim until
// its turn, a spinner while it runs, then a check or a cross. On a terminal
// the list redraws in place; elsewhere each step prints one plain line when
// it ends.
import { Cancelled, edit, type Keyboard, type Output, readKeys, style, type Style, truncate, width, wrap, yes } from './tty.ts';

const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const FRAME_MS = 80;

type State = {
  text: string;
  status: 'pending' | 'running' | 'asking' | 'done' | 'failed';
  details: string[];
  /** Lines under the step while it runs, gone when it ends. */
  under: string[];
  /** A line being typed under it: bullets only, never the text. */
  input: { prompt: string; typed: string; error: string | null } | null;
  /** Options to choose from, under it. */
  choice: { options: readonly string[]; at: number } | null;
};

/** What a running step can do while it works. */
export type Step = {
  /** Say what it is doing now. */
  note(text: string): void;
  /** Show these lines under it while it runs. */
  under(lines: string[]): void;
  ask(question: string): Promise<boolean>;
  /** One of `options`, with the arrows and Enter. */
  choose(question: string, options: readonly string[]): Promise<number>;
  /**
   * A line pasted under the step, shown as bullets, until `accept` takes
   * it (returning null) or `signal` aborts the wait (resolving null).
   * `accept` returns why a line is not taken, shown under it.
   */
  paste(prompt: string, accept: (text: string) => Promise<string | null>, signal: AbortSignal): Promise<string | null>;
};

/** A step failed, and its line says why: nothing more to show. */
export class StepFailed extends Error {}

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
  /** The first step still redrawn: those above it have settled, and been printed for good. */
  #from = 0;
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
    this.#steps = titles.map((text) => ({ text, status: 'pending', details: [], under: [], input: null, choice: null }));
    if (this.#s.ansi) {
      out.write('\x1b[?25l');
      process.once('exit', this.#restoreCursor);
      process.on('SIGINT', this.#interrupt);
      this.#draw();
    }
  }

  /**
   * Run step `i`: its line is the outcome `work` returns, or the error it
   * throws, which comes out as StepFailed, unless it is Cancelled.
   */
  async run(i: number, work: (step: Step) => Promise<Outcome>): Promise<void> {
    const state = this.#steps[i]!;
    state.status = 'running';
    this.#tick();
    const step: Step = {
      note: (text) => {
        state.text = text;
        this.#draw();
      },
      under: (lines) => {
        state.under = lines;
        this.#draw();
      },
      ask: (question) => this.#ask(state, question),
      choose: (question, options) => this.#choose(state, question, options),
      paste: (prompt, accept, signal) => this.#paste(state, prompt, accept, signal),
    };
    try {
      const outcome = await work(step);
      Object.assign(state, typeof outcome === 'string' ? { text: outcome, details: [] } : outcome, { status: 'done', under: [], input: null });
    } catch (error) {
      Object.assign(state, { under: [], input: null, choice: null });
      state.status = 'failed';
      state.details = error instanceof Cancelled ? [] : [this.#describe(error)];
      if (error instanceof Cancelled) state.text = `${state.text}: cancelled`;
      this.#stop();
      throw error instanceof Cancelled ? error : new StepFailed(state.details[0]);
    }
    this.#stop();
    if (!this.#s.ansi) this.#out.write(`✓ ${state.text}\n${state.details.map((line) => `  ${line}\n`).join('')}`);
    else if (this.#steps.every((each) => each.status === 'done')) this.end();
  }

  /**
   * Lines that stay, such as an address to open, printed whole, so that a
   * terminal can wrap them, and they can be copied or clicked. They go
   * under the steps done, above the one running: those done are printed
   * for good first, and only the rest is redrawn from then on.
   */
  print(text: string): void {
    if (!this.#s.ansi) {
      this.#out.write(`${text}\n`);
      return;
    }
    const running = this.#steps.findIndex((each, i) => i >= this.#from && each.status !== 'done');
    const settled = this.#lines(this.#from, running === -1 ? this.#steps.length : running);
    this.#from = running === -1 ? this.#steps.length : running;
    const up = this.#drawn > 0 ? `\x1b[${this.#drawn}F` : '';
    this.#out.write(`${up}\x1b[J${settled.map((line) => `${line}\n`).join('')}${text}\n`);
    this.#drawn = 0;
    this.#draw();
  }

  /** A remark that stays, dim, wrapped to the terminal's width. */
  aside(text: string): void {
    this.print(this.#s.dim(wrap(text, Math.max(20, (this.#out.columns ?? 80) - 3)).map((line) => `  ${line}`).join('\n')));
  }

  /**
   * An address to open, after what it is for: on one line when both fit;
   * otherwise the address on a line of its own, from the first column, so
   * that the terminal wraps it in one piece, to copy whole.
   */
  link(label: string, address: string): void {
    const fits = width(`  ${label} ${address}`) < (this.#out.columns ?? 80);
    this.print(fits ? `  ${this.#s.dim(label)} ${address}` : `  ${this.#s.dim(label)}\n${address}`);
  }

  /** Leave the list as it stands, the cursor below it. */
  end(): void {
    this.#stop();
    this.#release();
  }

  /** The cursor back, and Ctrl-C the terminal's again. */
  #release(): void {
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

  async #choose(state: State, question: string, options: readonly string[]): Promise<number> {
    const keys = this.#keys();
    if (keys === null) return 0;
    this.#stop();
    const before = state.text;
    Object.assign(state, { text: `${question} ${this.#s.dim('↑↓ then Enter')}`, status: 'asking', choice: { options, at: 0 } });
    let cancelled = false;
    try {
      // Raw mode before the question shows (see readKeys).
      const chosen = readKeys(keys, (key) => {
        const choice = state.choice!;
        if (key.ctrl && key.name === 'c') cancelled = true;
        else if (key.name === 'return' || key.name === 'enter') return true;
        else if (key.name === 'up' || key.name === 'k') choice.at = (choice.at - 1 + options.length) % options.length;
        else if (key.name === 'down' || key.name === 'j' || key.name === 'tab') choice.at = (choice.at + 1) % options.length;
        if (cancelled) return true;
        this.#draw();
        return false;
      });
      this.#draw();
      await chosen;
      if (cancelled) throw new Cancelled();
      return state.choice!.at;
    } finally {
      Object.assign(state, { text: before, status: 'running', choice: null });
      this.#tick();
    }
  }

  async #paste(state: State, prompt: string, accept: (text: string) => Promise<string | null>, signal: AbortSignal): Promise<string | null> {
    const keys = this.#keys();
    if (keys === null) {
      await new Promise<void>((resolve) => (signal.aborted ? resolve() : signal.addEventListener('abort', () => resolve())));
      return null;
    }
    state.input = { prompt, typed: '', error: null };
    let taken: string | null = null;
    let cancelled = false;
    try {
      // Raw mode before the prompt shows: what is pasted the moment it does is never echoed.
      const pasted = readKeys(
        keys,
        async (key, sequence) => {
          const input = state.input!;
          const next = edit(input.typed, key, sequence);
          if (next === 'cancel') cancelled = true;
          else if (next === 'submit' && input.typed.trim() !== '') {
            const text = input.typed.trim();
            input.typed = '';
            input.error = await accept(text);
            if (input.error === null) taken = text;
          } else if (next !== 'submit') {
            input.typed = next;
            input.error = null;
          }
          this.#draw();
          return cancelled || taken !== null;
        },
        signal,
      );
      this.#draw();
      await pasted;
    } finally {
      state.input = null;
      this.#draw();
    }
    if (cancelled) throw new Cancelled();
    return taken;
  }

  #tick(): void {
    this.#draw();
    if (this.#s.ansi && this.#timer === null) {
      // Only drawing: what a step waits on keeps the process alive, never the spinner.
      this.#timer = setInterval(() => {
        this.#frame = (this.#frame + 1) % SPINNER.length;
        this.#draw();
      }, FRAME_MS).unref();
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
      this.#release();
    }
  }

  #draw(): void {
    if (!this.#s.ansi) return;
    const lines = this.#lines(this.#from, this.#steps.length);
    const up = this.#drawn > 0 ? `\x1b[${this.#drawn}F` : '';
    this.#out.write(`${up}${lines.map((line) => `${line}\x1b[K\n`).join('')}\x1b[J`);
    this.#drawn = lines.length;
  }

  /** Steps `from` to `to`, as lines cut to the terminal's width. */
  #lines(from: number, to: number): string[] {
    const s = this.#s;
    const columns = Math.max(20, (this.#out.columns ?? 80) - 1);
    const lines = this.#steps.slice(from, to).flatMap(({ text, status, details, under, input, choice }) => {
      const icon = {
        pending: s.dim('·'),
        running: s.accent(SPINNER[this.#frame]!),
        asking: s.accent('?'),
        done: s.green('✓'),
        failed: s.red('✗'),
      }[status];
      const line = status === 'pending' ? s.dim(text) : status === 'failed' ? s.red(text) : text;
      // An error is wrapped, to be read whole; what a step found is one line each.
      const below = status === 'failed' ? details.flatMap((detail) => wrap(detail, columns - 4)) : details.map(s.dim);
      const live = [
        ...under.map((text) => `    ${s.dim(text)}`),
        ...(choice === null ? [] : choice.options.map((option, i) => (i === choice.at ? `    ${s.accent('›')} ${s.accent(option)}` : `      ${option}`))),
        ...(input === null
          ? []
          : [
              `    ${input.prompt}`,
              `    ${s.accent('›')} ${'•'.repeat(input.typed.length)}`,
              ...(input.error === null ? [] : [`    ${s.red(input.error)}`]),
            ]),
      ];
      return [`  ${icon} ${line}`, ...below.map((detail) => `    ${detail}`), ...live];
    });
    return lines.map((line) => truncate(line, columns));
  }
}
