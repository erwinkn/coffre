import { readFileSync } from 'node:fs';

/**
 * This CLI's version: the schema it migrates to, the version of coffre a
 * deployment it makes runs, and the one `coffre migrate` expects to find.
 */
export function cliVersion(): string {
  return (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;
}
