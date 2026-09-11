import { z } from 'zod';
import type { Envelope, KeyProvider, SecretContext, WrappedKey } from '../../contracts/src/index';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
export const bytes = (s: string) => enc.encode(s);
export function b64(data: Uint8Array): string { let binary = ''; for (let i = 0; i < data.length; i += 8192) binary += String.fromCharCode(...data.subarray(i, i + 8192)); return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
export function unb64(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('Invalid base64url');
  const b = Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  if (b64(b) !== s) throw new Error('Noncanonical base64url');
  return b;
}
export const random = (size: number) => crypto.getRandomValues(new Uint8Array(size));
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value as object).sort().map(k => JSON.stringify(k) + ':' + canonical((value as Record<string, unknown>)[k])).join(',') + '}';
}
export async function sha256(value: string): Promise<string> { return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(value)))); }
export async function fingerprint(key: Uint8Array, value: unknown): Promise<string> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(new Uint8Array(await crypto.subtle.sign('HMAC', k, bytes(canonical(value)))));
}
const contextSchema = z.object({ instanceId: z.string().uuid(), projectId: z.string().uuid(), envId: z.string().uuid(), secretId: z.string().uuid(), version: z.number().int().positive() }).strict();
export function aad(context: SecretContext, layer: 'value' | 'wrap', keyRef?: string): Uint8Array {
  contextSchema.parse(context);
  return bytes(canonical({ domain: 'coffre/envelope/v1', layer, context, ...(keyRef ? { keyRef } : {}) }));
}
async function aesKey(raw: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('Expected a 256-bit key');
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, usage);
}
async function encrypt(raw: Uint8Array, plaintext: Uint8Array, additionalData: Uint8Array) {
  const iv = random(12);
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: additionalData as BufferSource, tagLength: 128 }, await aesKey(raw, ['encrypt']), plaintext as BufferSource));
  return { nonce: b64(iv), data: b64(data) };
}
async function decrypt(raw: Uint8Array, nonce: string, data: string, additionalData: Uint8Array) {
  const iv = unb64(nonce);
  if (iv.length !== 12) throw new Error('Invalid GCM nonce');
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: additionalData as BufferSource, tagLength: 128 }, await aesKey(raw, ['decrypt']), unb64(data) as BufferSource));
}
export class LocalKeyProvider implements KeyProvider {
  constructor(private readonly keys: ReadonlyMap<string, Uint8Array>, private readonly current: string) {
    if (!keys.has(current) || [...keys.values()].some(k => k.length !== 32)) throw new Error('Invalid root key configuration');
  }
  async wrap(dek: Uint8Array, context: SecretContext): Promise<WrappedKey> {
    if (dek.length !== 32) throw new Error('Invalid data key');
    return { keyRef: this.current, ...await encrypt(this.keys.get(this.current)!, dek, aad(context, 'wrap', this.current)) };
  }
  async unwrap(key: WrappedKey, context: SecretContext): Promise<Uint8Array> {
    const root = this.keys.get(key.keyRef);
    if (!root || !key.nonce) throw new Error('Unknown wrapping key');
    const dek = await decrypt(root, key.nonce, key.data, aad(context, 'wrap', key.keyRef));
    if (dek.length !== 32) throw new Error('Invalid unwrapped key');
    return dek;
  }
}
export async function seal(value: string, context: SecretContext, provider: KeyProvider): Promise<Envelope> {
  const dek = random(32);
  try {
    const { nonce, data } = await encrypt(dek, bytes(value), aad(context, 'value'));
    const wrappedKey = await provider.wrap(dek, context);
    return { format: 1, algorithm: 'AES-256-GCM', nonce, ciphertext: data, wrappedKey };
  } finally { dek.fill(0); }
}
export async function open(envelope: Envelope, context: SecretContext, provider: KeyProvider): Promise<string> {
  if (envelope.format !== 1 || envelope.algorithm !== 'AES-256-GCM') throw new Error('Unsupported envelope');
  const dek = await provider.unwrap(envelope.wrappedKey, context);
  try { return dec.decode(await decrypt(dek, envelope.nonce, envelope.ciphertext, aad(context, 'value'))); }
  finally { dek.fill(0); }
}
export async function rewrap(envelope: Envelope, context: SecretContext, from: KeyProvider, to: KeyProvider): Promise<Envelope> {
  const dek = await from.unwrap(envelope.wrappedKey, context);
  try { return { ...envelope, wrappedKey: await to.wrap(dek, context) }; } finally { dek.fill(0); }
}
export interface KmsBinding { wrap(request: { data: string; context: SecretContext; requestId: string }): Promise<WrappedKey>; unwrap(request: { key: WrappedKey; context: SecretContext; requestId: string }): Promise<string> }
export class ServiceKeyProvider implements KeyProvider {
  constructor(private readonly binding: KmsBinding) {}
  wrap(dek: Uint8Array, context: SecretContext) { return this.binding.wrap({ data: b64(dek), context, requestId: crypto.randomUUID() }); }
  async unwrap(key: WrappedKey, context: SecretContext) { return unb64(await this.binding.unwrap({ key, context, requestId: crypto.randomUUID() })); }
}
export const kmsRequestSchema = z.discriminatedUnion('operation', [
  z.object({ operation: z.literal('wrap'), requestId: z.string().uuid(), context: contextSchema, data: z.string().max(64) }).strict(),
  z.object({ operation: z.literal('unwrap'), requestId: z.string().uuid(), context: contextSchema, key: z.object({ keyRef: z.string().max(256), nonce: z.string().max(64).optional(), data: z.string().max(8192) }).strict() }).strict(),
]);
