import { Buffer } from 'node:buffer';

/** How a column's text is read, by its type's oid. */
export type Parsers = Record<number, ((text: string) => unknown) | undefined>;
/** How a value is written as text, by its parameter's type's oid. */
export type Serializers = Record<number, ((value: unknown) => unknown) | undefined>;

/**
 * The types read and written by default, as upstream's `types.js`: each one's
 * oid when sent (`to`), the oids read as it (`from`), and how.
 */
const TYPES: { to: number; from: number[]; serialize: (x: unknown) => string; parse?: (x: string) => unknown }[] = [
  // string: read as the text it is.
  { to: 25, from: [], serialize: (x) => String(x) },
  // number
  { to: 0, from: [21, 23, 26, 700, 701], serialize: (x) => String(x), parse: (x) => +x },
  // json
  { to: 114, from: [114, 3802], serialize: (x) => JSON.stringify(x), parse: (x) => JSON.parse(x) as unknown },
  // boolean
  { to: 16, from: [16], serialize: (x) => (x === true ? 't' : 'f'), parse: (x) => x === 't' },
  // date
  { to: 1184, from: [1082, 1114, 1184], serialize: (x) => (x instanceof Date ? x : new Date(x as string)).toISOString(), parse: (x) => new Date(x) },
  // bytea
  { to: 17, from: [17], serialize: (x) => '\\x' + Buffer.from(x as Uint8Array).toString('hex'), parse: (x) => Buffer.from(x.slice(2), 'hex') },
];

/** A client's own parsers and serializers, made from the defaults: it may change them (`options.parsers[oid] = …`). */
export function defaultTypes(): { parsers: Parsers; serializers: Serializers } {
  const parsers: Parsers = {};
  const serializers: Serializers = {};
  for (const type of TYPES) {
    for (const oid of type.from) parsers[oid] = type.parse;
    serializers[type.to] = type.serialize;
    for (const oid of type.from) serializers[oid] = type.serialize;
  }
  return { parsers, serializers };
}

/**
 * The type a value is sent as, which a parameter's serializer goes by: 0,
 * none, for the server to type its text, but for a date, bytes, a boolean or
 * a bigint. An array goes by its first element (porsager/postgres#1225; coffre
 * sends arrays as their text, `asPgSends` in postgres.ts).
 */
export function inferType(x: unknown): number {
  return x instanceof Date ? 1184
    : x instanceof Uint8Array ? 17
    : x === true || x === false ? 16
    : typeof x === 'bigint' ? 20
    : Array.isArray(x) ? inferType(x[0])
    : 0;
}
