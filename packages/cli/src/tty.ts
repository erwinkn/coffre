// The terminal, for the CLI's screens of its own: `coffre setup` and `coffre
// keys`. Hand-rolled ANSI rather than a dependency: colour as the web UI has
// it, neutral with one accent, honouring NO_COLOR and plain off a terminal;
// widths that ignore escape codes; the keyboard, from stdin, or from
// /dev/tty when stdin is piped; and prompts that echo nothing secret.
import { openSync } from 'node:fs';
import { emitKeypressEvents } from 'node:readline';
import tty from 'node:tty';
import type { Writable } from 'node:stream';

export type Paint = (text: string) => string;

export type Style = {
  /** Whether the stream is a terminal: escape codes only then. */
  ansi: boolean;
  bold: Paint;
  dim: Paint;
  accent: Paint;
  green: Paint;
  red: Paint;
};

/** What a screen or a step list writes to: a stream, and its size when it is a terminal. */
export type Output = Writable & { isTTY?: boolean; columns?: number; rows?: number };

const plain: Paint = (text) => text;

/**
 * The web UI's accent, green and red, at the depth the terminal takes:
 * 24-bit, 256 colours or the 16 named ones. NO_COLOR (and FORCE_COLOR) are
 * the stream's own `hasColors`; bold and dim stay, being no colour.
 */
export function style(stream: Output): Style {
  if (stream.isTTY !== true) return { ansi: false, bold: plain, dim: plain, accent: plain, green: plain, red: plain };
  const terminal = stream as tty.WriteStream;
  const depth = typeof terminal.hasColors === 'function' && terminal.hasColors() ? terminal.getColorDepth() : 1;
  const sgr = (open: string, close: string): Paint => (text) => `\x1b[${open}m${text}\x1b[${close}m`;
  const colour = (rgb: [number, number, number], index256: number, index16: number): Paint =>
    depth >= 24 ? sgr(`38;2;${rgb.join(';')}`, '39') : depth >= 8 ? sgr(`38;5;${index256}`, '39') : depth >= 4 ? sgr(String(index16), '39') : plain;
  return {
    ansi: true,
    bold: sgr('1', '22'),
    dim: sgr('2', '22'),
    accent: colour([91, 141, 239], 69, 94),
    green: colour([63, 174, 111], 71, 32),
    red: colour([229, 83, 75], 167, 31),
  };
}

const ESCAPE = /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07/g;

/** Columns `text` takes on screen: its characters, less its escape codes. */
export function width(text: string): number {
  return [...text.replace(ESCAPE, '')].length;
}

/** `text` cut to `columns` on screen, escape codes kept, an ellipsis where it was cut. */
export function truncate(text: string, columns: number): string {
  if (width(text) <= columns) return text;
  let out = '';
  let used = 0;
  for (let i = 0; i < text.length; ) {
    ESCAPE.lastIndex = i;
    const code = text[i] === '\x1b' ? ESCAPE.exec(text) : null;
    if (code !== null && code.index === i) {
      out += code[0];
      i += code[0].length;
      continue;
    }
    const char = String.fromCodePoint(text.codePointAt(i)!);
    if (used === columns - 1) return `${out}…${text.includes('\x1b') ? '\x1b[0m' : ''}`;
    out += char;
    used += 1;
    i += char.length;
  }
  return out;
}

/** Plain `text` in lines of at most `columns`, broken at spaces, or anywhere in a word longer than a line. */
export function wrap(text: string, columns: number): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(' ')) {
    let rest = word;
    while (width(rest) > columns) {
      if (line !== '') lines.push(line);
      line = '';
      lines.push([...rest].slice(0, columns).join(''));
      rest = [...rest].slice(columns).join('');
    }
    if (line === '') line = rest;
    else if (width(line) + 1 + width(rest) <= columns) line += ` ${rest}`;
    else {
      lines.push(line);
      line = rest;
    }
  }
  return [...lines, line];
}

/** `text` wrapped to the stream's width, each line indented by `indent` spaces. */
export function paragraph(out: Output, text: string, indent = 2): string {
  const pad = ' '.repeat(indent);
  return wrap(text, Math.max(20, (out.columns || 80) - indent - 1)).map((line) => `${pad}${line}`).join('\n');
}

/** A labelled row: `label` in a column of `column`, `text` wrapped beside it with a hanging indent. */
export function row(out: Output, s: Style, label: string, text: string, indent = 4, column = 10): string {
  const lines = wrap(text, Math.max(20, (out.columns || 80) - indent - column - 1));
  const pad = ' '.repeat(indent);
  return lines.map((line, i) => `${pad}${i === 0 ? s.dim(label.padEnd(column)) : ' '.repeat(column)}${line}`).join('\n');
}

/** A key, as node:readline names it. */
export type Key = { name?: string; sequence?: string; ctrl?: boolean; meta?: boolean; shift?: boolean };

/** Where keys come from: a terminal in raw mode. */
export type Keyboard = NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?(raw: boolean): unknown; destroy?(): void };

/**
 * The keyboard: stdin when it is a terminal, otherwise the terminal itself,
 * as `less` reads it when its input is piped. Null without one.
 */
export function keyboard(): Keyboard | null {
  if (process.stdin.isTTY) return process.stdin;
  try {
    return new tty.ReadStream(openSync('/dev/tty', 'r'));
  } catch {
    return null;
  }
}

/** Where a screen is drawn and read from: stdout, and the keyboard. Null unless both are a terminal. */
export function openTerminal(): { keys: Keyboard; out: Output } | null {
  if (!process.stdout.isTTY) return null;
  const keys = keyboard();
  return keys === null ? null : { keys, out: process.stdout };
}

/** Release a keyboard `keyboard()` opened: stdin stays, /dev/tty closes. */
export function release(keys: Keyboard): void {
  keys.setRawMode?.(false);
  keys.pause();
  if (keys !== process.stdin) keys.destroy?.();
}

/** Every key pressed, in raw mode, until `until` returns true. */
export function readKeys(keys: Keyboard, until: (key: Key, sequence: string) => boolean | Promise<boolean>): Promise<void> {
  emitKeypressEvents(keys);
  keys.setRawMode?.(true);
  keys.resume();
  return new Promise((resolve, reject) => {
    let busy = Promise.resolve();
    const onKey = (sequence: string | undefined, key: Key | undefined) => {
      busy = busy.then(async () => {
        if (await until(key ?? { sequence }, sequence ?? key?.sequence ?? '')) {
          keys.off('keypress', onKey);
          keys.setRawMode?.(false);
          keys.pause();
          resolve();
        }
      }).catch(reject);
    };
    keys.on('keypress', onKey);
  });
}

export class Cancelled extends Error {
  constructor() {
    super('cancelled');
  }
}

/**
 * A line typed without echo: a bullet for each character, so that a paste
 * shows it arrived. The question, its hint and the bullets go once it is
 * given. Ctrl-C cancels.
 */
export async function hiddenLine(keys: Keyboard, out: Output, s: Style, question: string, hint: string): Promise<string> {
  const columns = Math.max(20, (out.columns || 80) - 1);
  out.write(`${truncate(`  ${s.accent('?')} ${s.bold(question)}`, columns)}\n${truncate(`    ${s.dim(hint)}`, columns)}\n`);
  let typed = '';
  const draw = () => {
    const count = typed.length > 0 ? s.dim(`  ${typed.length} characters`) : '';
    out.write(`\r\x1b[2K${truncate(`    ${s.accent('›')} ${'•'.repeat(typed.length)}`, columns - width(count))}${count}`);
  };
  draw();
  let cancelled = false;
  await readKeys(keys, (key, sequence) => {
    if (key.ctrl && key.name === 'c') cancelled = true;
    else if (key.name === 'return' || key.name === 'enter') return true;
    else if (key.name === 'backspace') typed = typed.slice(0, -1);
    else if (key.ctrl && key.name === 'u') typed = '';
    else if (!key.ctrl && !key.meta && sequence.length > 0 && !sequence.startsWith('\x1b') && sequence >= ' ') typed += sequence;
    if (cancelled) return true;
    draw();
    return false;
  });
  out.write('\r\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K');
  if (cancelled) throw new Cancelled();
  return typed.trim();
}

/** One key: y for yes, anything else for no. Ctrl-C cancels. */
export async function yes(keys: Keyboard): Promise<boolean> {
  let answer = false;
  let cancelled = false;
  await readKeys(keys, (key) => {
    if (key.ctrl && key.name === 'c') cancelled = true;
    answer = key.name === 'y';
    return true;
  });
  if (cancelled) throw new Cancelled();
  return answer;
}
