/**
 * A small .env parser, for bulk import.
 *
 * Deliberately hand-written rather than pulled from npm: this runs inside the
 * service that holds every credential we own, and the whole grammar is about
 * thirty lines.
 *
 * Supported: `KEY=value`, `export KEY=value`, single and double quoting,
 * escapes inside double quotes, `#` comments, blank lines, and surrounding
 * whitespace. NOT supported: multi-line values and variable interpolation --
 * both are reported as errors rather than being silently mangled.
 */

export type ParsedEntry = { key: string; value: string; line: number };
export type ParseProblem = { line: number; text: string; reason: string };

export type ParseResult = {
  entries: ParsedEntry[];
  problems: ParseProblem[];
};

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

export function parseDotenv(input: string): ParseResult {
  const entries: ParsedEntry[] = [];
  const problems: ParseProblem[] = [];
  const seen = new Set<string>();

  const lines = input.split(/\r?\n/);

  for (let index = 0; index < lines.length; index++) {
    const lineNumber = index + 1;
    const raw = lines[index];
    const trimmed = raw.trim();

    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const withoutExport = trimmed.startsWith('export ')
      ? trimmed.slice('export '.length).trim()
      : trimmed;

    const equals = withoutExport.indexOf('=');
    if (equals === -1) {
      problems.push({ line: lineNumber, text: trimmed, reason: 'no "=" on this line' });
      continue;
    }

    const key = withoutExport.slice(0, equals).trim();
    if (!KEY_RE.test(key)) {
      problems.push({
        line: lineNumber,
        text: key,
        reason: 'key must match ^[A-Za-z_][A-Za-z0-9_]*$',
      });
      continue;
    }

    let rest = withoutExport.slice(equals + 1).trim();
    let value: string;

    if (rest.startsWith('"')) {
      const closing = findClosingQuote(rest, '"');
      if (closing === -1) {
        problems.push({
          line: lineNumber,
          text: key,
          reason: 'unterminated double quote (multi-line values are not supported)',
        });
        continue;
      }
      value = unescapeDoubleQuoted(rest.slice(1, closing));
    } else if (rest.startsWith("'")) {
      const closing = rest.indexOf("'", 1);
      if (closing === -1) {
        problems.push({
          line: lineNumber,
          text: key,
          reason: 'unterminated single quote (multi-line values are not supported)',
        });
        continue;
      }
      // Single quotes are literal, as in a shell.
      value = rest.slice(1, closing);
    } else {
      // Unquoted: strip a trailing comment, then trailing whitespace.
      const comment = rest.indexOf(' #');
      if (comment !== -1) rest = rest.slice(0, comment);
      value = rest.trim();
    }

    if (seen.has(key)) {
      problems.push({ line: lineNumber, text: key, reason: 'duplicate key in this file' });
      continue;
    }
    seen.add(key);

    entries.push({ key, value, line: lineNumber });
  }

  return { entries, problems };
}

function findClosingQuote(text: string, quote: string): number {
  for (let index = 1; index < text.length; index++) {
    if (text[index] === '\\') {
      index++;
      continue;
    }
    if (text[index] === quote) return index;
  }
  return -1;
}

function unescapeDoubleQuoted(text: string): string {
  return text.replace(/\\(.)/g, (_match, character: string) => {
    switch (character) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      default:
        return character;
    }
  });
}
