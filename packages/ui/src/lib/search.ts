/**
 * The router's search, every value a string as the URL has it. TanStack's
 * default reads what looks like JSON or a number as such, so `state=1e5`
 * would come back as `100000` and `code=0123` as `123`; the server's
 * canonical redirect would then rewrite the URL. Here a page's
 * `validateSearch` gets strings, and the URL comes back as it went.
 */
export function parseSearch(searchStr: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(searchStr));
}

/** The inverse of `parseSearch`: each value that is set, as text. */
export function stringifySearch(search: Record<string, unknown>): string {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(search)) {
    if (value !== undefined) query.set(name, String(value));
  }
  const text = query.toString();
  return text === '' ? '' : `?${text}`;
}

/** The string values of a search, as a page that takes them as given reads them. */
export function stringsOf(search: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(Object.entries(search).filter((entry): entry is [string, string] => typeof entry[1] === 'string'));
}
