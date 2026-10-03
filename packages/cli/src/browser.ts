// Sending someone to a page in their browser, as far as this machine can.
// On a server or a VM there is often no browser here at all: the address
// is printed too, and every browser step also takes the address its
// callback failed at, pasted back (`localCallback`).
import { spawn } from 'node:child_process';

/** Open `url` in this machine's browser, if it has one. Silent either way. */
export function openBrowser(url: string, platform: NodeJS.Platform = process.platform): void {
  const [command, ...args] =
    platform === 'darwin' ? ['open', url] : platform === 'win32' ? ['cmd', '/c', 'start', '', url] : ['xdg-open', url];
  try {
    const child = spawn(command!, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    // No opener here: the printed address serves.
  }
}

/**
 * `text` as a callback address on this machine, or why not: it must name
 * localhost or 127.0.0.1, `port` and `path`, and carry each of `params`.
 * Only such an address is ever fetched, so a paste can never send this
 * machine anywhere else.
 */
export function localCallback(text: string, port: number, path: string, params: readonly string[]): URL | string {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    return 'that is not an address: paste the whole one your browser shows';
  }
  if (url.protocol !== 'http:' || (url.hostname !== 'localhost' && url.hostname !== '127.0.0.1')) {
    return `that is not a localhost address: paste the one that starts http://localhost:${port}`;
  }
  if (url.port !== String(port) || url.pathname !== path) return `that is not this step's address: it starts http://localhost:${port}${path}`;
  const missing = params.filter((param) => !url.searchParams.get(param));
  if (missing.length > 0) return `that address has no ${missing.join(' or ')}: paste it whole`;
  return url;
}
