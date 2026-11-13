// The driver on Node: Node's sockets, TLS and crypto (platform.ts).
import crypto from 'node:crypto';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import tls from 'node:tls';

import type { Platform, Socket } from './platform.ts';

export const tcp: Platform['tcp'] = (to, connected) => ('path' in to ? net.connect(to.path, connected) : net.connect(to.port, to.host, connected)) as Socket;

export const startTls: Platform['startTls'] = (socket, options) => tls.connect({ ...options, socket: socket as net.Socket }) as Socket;

export const isIP: Platform['isIP'] = (host) => net.isIP(host);

export const setImmediate: Platform['setImmediate'] = (fn) => globalThis.setImmediate(fn);
export const clearImmediate: Platform['clearImmediate'] = (handle) => globalThis.clearImmediate(handle as NodeJS.Immediate | undefined);
export const nextTask: Platform['nextTask'] = setImmediate;
export const cancelTask: Platform['cancelTask'] = clearImmediate;

export const now: Platform['now'] = () => performance.now();

export const randomBytes: Platform['randomBytes'] = (length) => crypto.randomBytes(length);

// Synchronous, as upstream salts on Node: a few milliseconds once per connection.
export const pbkdf2: Platform['pbkdf2'] = async (password, salt, iterations, length) => crypto.pbkdf2Sync(password, salt, iterations, length, 'sha256');

export const hmac: Platform['hmac'] = async (key, text) => crypto.createHmac('sha256', key).update(text).digest();

export const sha256: Platform['sha256'] = async (data) => crypto.createHash('sha256').update(data).digest();

export const md5: Platform['md5'] = async (data) => crypto.createHash('md5').update(data).digest('hex');
