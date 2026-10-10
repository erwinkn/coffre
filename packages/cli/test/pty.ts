// The CLI in a pseudo-terminal, as an operator runs it, through util-linux's
// `script`: what it writes, byte for byte, and keys sent once it shows what
// a step waits for. Linux only; elsewhere the tests that need it skip.
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

export const ptySkip =
  process.platform !== 'linux' || spawnSync('script', ['--version']).status !== 0 ? 'needs util-linux script, on Linux' : false;

export const ENTER_ALT = '\x1b[?1049h';
export const LEAVE_ALT = '\x1b[?1049l';

export type Session = {
  /** Resolve once the output holds `text`, or the first of several, after what the last wait matched: with which one. */
  waitFor(text: string | readonly string[], timeoutMs?: number): Promise<number>;
  send(keys: string): void;
};

const quote = (arg: string) => `'${arg.replace(/'/g, `'\\''`)}'`;

/** Run `coffre <args>` in a terminal of `columns` by `rows`, in `cwd`, play `session`, and return everything it wrote. */
export async function inTerminal(
  args: string[],
  env: NodeJS.ProcessEnv,
  play: (session: Session) => Promise<void>,
  size = { columns: 160, rows: 48 },
  cwd?: string,
): Promise<{ output: string; code: number | null }> {
  const command = `stty cols ${size.columns} rows ${size.rows}; exec ${[process.execPath, '--conditions=coffre:source', main, ...args].map(quote).join(' ')}`;
  const child = spawn('script', ['-qfec', command, '/dev/null'], { cwd, env: { TERM: 'xterm-256color', ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  let seen = 0;
  const waiters: { texts: readonly string[]; resolve: (index: number) => void }[] = [];
  /** The text of `texts` that comes first after `seen`, which moves past it; -1 for none yet. */
  const match = (texts: readonly string[]): number => {
    let first = -1;
    let at = Infinity;
    texts.forEach((text, index) => {
      const found = output.indexOf(text, seen);
      if (found !== -1 && found < at) [first, at] = [index, found];
    });
    if (first !== -1) seen = at + texts[first]!.length;
    return first;
  };
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => {
    output += chunk;
    for (const waiter of [...waiters]) {
      const index = match(waiter.texts);
      if (index !== -1) {
        waiters.splice(waiters.indexOf(waiter), 1);
        waiter.resolve(index);
      }
    }
  });
  const exited = new Promise<number | null>((resolve) => child.on('close', resolve));
  const session: Session = {
    waitFor: (text, timeoutMs = 20_000) =>
      new Promise((resolve, reject) => {
        const texts = typeof text === 'string' ? [text] : text;
        const index = match(texts);
        if (index !== -1) return resolve(index);
        const timer = setTimeout(() => reject(new Error(`never saw ${JSON.stringify(text)} in:\n${visible(output)}`)), timeoutMs);
        waiters.push({ texts, resolve: (index) => (clearTimeout(timer), resolve(index)) });
      }),
    send: (keys) => child.stdin.write(keys),
  };
  try {
    await play(session);
  } catch (error) {
    child.kill();
    throw error;
  }
  // The exit first: `output` read before it would miss what came after the last key.
  const code = await exited;
  return { output, code };
}

/** The output outside the alternate screen, and inside it. */
export function screens(output: string): { main: string; alternate: string } {
  let main = '';
  let alternate = '';
  let rest = output;
  for (;;) {
    const enter = rest.indexOf(ENTER_ALT);
    if (enter === -1) return { main: main + rest, alternate };
    main += rest.slice(0, enter);
    rest = rest.slice(enter + ENTER_ALT.length);
    const leave = rest.indexOf(LEAVE_ALT);
    if (leave === -1) return { main, alternate: alternate + rest };
    alternate += rest.slice(0, leave);
    rest = rest.slice(leave + LEAVE_ALT.length);
  }
}

/** Output without its escape codes, to read. */
export function visible(output: string): string {
  return output.replace(/\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07/g, '');
}

/** On a terminal, the URL typed at setup's hidden prompt, then the rest as `play` goes. */
export function typingUrl(url: string, play: (terminal: Session) => Promise<void>): (terminal: Session) => Promise<void> {
  return async (terminal) => {
    // The first thing the CLI shows, after it starts: on a loaded host, that can take a while.
    await terminal.waitFor('connection string', 60_000);
    terminal.send(`${url}\r`);
    await play(terminal);
  };
}

/**
 * Each question `answers` names answered as it comes, once, in whatever order
 * the CLI asks, until the output holds one of `until`: a flow whose order is
 * what a test checks.
 */
export async function answering(terminal: Session, answers: Record<string, string>, until: readonly string[]): Promise<void> {
  const left = new Map(Object.entries(answers));
  for (;;) {
    const questions = [...left.keys()];
    const index = await terminal.waitFor([...until, ...questions]);
    if (index < until.length) return;
    const question = questions[index - until.length]!;
    terminal.send(left.get(question)!);
    left.delete(question);
  }
}
