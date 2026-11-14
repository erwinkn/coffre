import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

import { getTableColumns, getTableName, type InferSelectModel } from 'drizzle-orm';
import { getTableConfig, type PgTable } from 'drizzle-orm/pg-core';

/**
 * A row as the vault reads and writes it, and the MAC it puts on each row
 * that turns into access (docs/design/0.16.md, "Row MAC"). Everything here
 * is derived from a table's definition in `@coffre/db/schema`: which columns
 * it has, which are its key, which are times or bytes. No table is spelled
 * out twice.
 *
 * A row crosses the database as JSON, both ways: `to_jsonb(t)` on a read,
 * `jsonb_populate_recordset` on a write. So one statement reads rows of any
 * tables, and one writes them.
 */

/** A table whose rows carry the vault's MAC. */
export type Sealed = PgTable & { mac: unknown };

/** A row as read: every column, as Drizzle types them. */
export type Row<T extends PgTable> = InferSelectModel<T>;

/**
 * A row as the vault is about to write it: every column but its MAC, which
 * `seal` makes, and a column the database computes. Every one is given, null
 * included: a default the database filled in would be a value the MAC covers
 * and the vault never saw.
 */
export type Fresh<T extends PgTable> = Omit<Row<T>, 'mac' | Computed<T>>;

/** The columns of a table the database computes. */
type Computed<T extends PgTable> = { [K in keyof T['_']['columns']]: T['_']['columns'][K]['_']['generated'] extends undefined ? never : K }[keyof T['_']['columns']];

/** A row as JSON, keyed by column name: what `to_jsonb` gives and `jsonb_populate_recordset` takes. */
export type Wire = Record<string, unknown>;

/**
 * Columns that only say when a row was last used. A use moves them on with
 * no change, so no MAC covers them, and no change writes them over. An
 * identity's last sign-in is not one: a sign-in is a change, and writes it.
 */
const LAST_SEEN: ReadonlySet<string> = new Set(['last_used_at', 'last_used_ip']);

/** A UUID as Postgres writes one. It reads others too, capitals and braces, and gives this back. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The kinds of column a sealed row has, each with the values that Postgres
 * stores exactly as given. Any other is refused before it is sealed
 * (`toWire`): Postgres would take a capital UUID, or a number for a text,
 * and store another value, so the row would read back as one the vault
 * never sealed, and stay, a row no decision sees and so none removes.
 */
const KINDS = {
  time: (value: unknown) => value instanceof Date && !Number.isNaN(value.getTime()),
  bytes: (value: unknown) => Buffer.isBuffer(value),
  uuid: (value: unknown) => typeof value === 'string' && UUID.test(value),
  integer: (value: unknown) => Number.isSafeInteger(value),
  boolean: (value: unknown) => typeof value === 'boolean',
  text: (value: unknown) => typeof value === 'string',
  texts: (value: unknown) => Array.isArray(value) && value.every((item) => typeof item === 'string'),
};
type Kind = keyof typeof KINDS;

/** By the type Postgres gives the column. One the vault has no kind for, a bigint say, which JSON would round, fails here. */
const KIND_OF: Readonly<Record<string, Kind>> = { 'timestamp (3) with time zone': 'time', bytea: 'bytes', uuid: 'uuid', integer: 'integer', boolean: 'boolean', text: 'text', 'text[]': 'texts' };

type Column = {
  /** Its name in a `Row`, and in the database. */
  key: string;
  name: string;
  kind: Kind;
  primary: boolean;
  /** Computed by the database: read, never written. */
  generated: boolean;
  /** Under the row's MAC, and written by a change. */
  sealed: boolean;
};

/** What the vault needs to know of a table, worked out once. */
export type Shape = { name: string; columns: readonly Column[]; key: readonly Column[] };

const shapes = new WeakMap<PgTable, Shape>();

export function shapeOf(table: PgTable): Shape {
  let shape = shapes.get(table);
  if (shape === undefined) {
    const config = getTableConfig(table);
    const primary = new Set((config.primaryKeys[0]?.columns ?? config.columns.filter((column) => column.primary)).map((column) => column.name));
    const columns = Object.entries(getTableColumns(table)).map(([key, column]): Column => {
      const kind = KIND_OF[column.getSQLType()];
      if (kind === undefined) throw new Error(`${getTableName(table)}.${column.name}: the vault has no way to carry a ${column.getSQLType()}`);
      const generated = column.generated !== undefined;
      return {
        key,
        name: column.name,
        kind,
        primary: primary.has(column.name),
        generated,
        sealed: !generated && column.name !== 'mac' && !LAST_SEEN.has(column.name),
      };
    });
    shape = { name: config.name, columns, key: columns.filter((column) => column.primary) };
    if (shape.key.length === 0) throw new Error(`${shape.name} has no primary key`);
    shapes.set(table, shape);
  }
  return shape;
}

/** A row from the JSON the database gave: times as dates, bytes as buffers. */
export function fromWire<T extends PgTable>(table: T, wire: Wire): Row<T> {
  const row: Record<string, unknown> = {};
  for (const column of shapeOf(table).columns) {
    const value = wire[column.name] ?? null;
    if (value === null) row[column.key] = null;
    // `to_jsonb` writes a time with the session's offset, and bytes as `\x` and hex.
    else if (column.kind === 'time') row[column.key] = new Date(value as string);
    else if (column.kind === 'bytes') row[column.key] = Buffer.from((value as string).slice(2), 'hex');
    else row[column.key] = value;
  }
  return row as Row<T>;
}

/** A row as the JSON a write sends, each value one its column stores as given (`KINDS`). `only` leaves the other columns out, for a row named by its key. */
export function toWire(table: PgTable, row: object, only?: readonly Column[]): Wire {
  const wire: Wire = {};
  for (const column of only ?? shapeOf(table).columns) {
    if (column.generated) continue;
    const value: unknown = (row as Record<string, unknown>)[column.key] ?? null;
    if (value === null) wire[column.name] = null;
    else if (!KINDS[column.kind](value)) throw new Error(`${shapeOf(table).name}.${column.name}: ${JSON.stringify(value)} is not a ${column.kind} as Postgres stores one`);
    else if (column.kind === 'time') wire[column.name] = (value as Date).toISOString();
    else if (column.kind === 'bytes') wire[column.name] = `\\x${(value as Buffer).toString('hex')}`;
    else wire[column.name] = value;
  }
  return wire;
}

/** A row's key, as the log and the signer's mirror name it: its table, then its primary key's values. */
export function nameOf(table: PgTable, row: object): string {
  const shape = shapeOf(table);
  return JSON.stringify([shape.name, ...shape.key.map((column) => (row as Record<string, unknown>)[column.key])]);
}

/**
 * The vault's keys, all derived from one seed (`signingKeys` in config.ts):
 * the four bytes that name the seed at the head of every MAC, the key over
 * rows and the key over log entries.
 */
export type Key = { id: Buffer; rows: Buffer; entries: Buffer };

export function keyOf(seed: Uint8Array): Key {
  const derive = (info: string, bytes: number) => Buffer.from(hkdfSync('sha256', seed, new Uint8Array(0), info, bytes));
  return { id: derive('coffre.vault.key-id.v2', 4), rows: derive('coffre.vault.rows.v2', 32), entries: derive('coffre.vault.entries.v2', 32) };
}

/** Four bytes that name the key, then 32 of HMAC-SHA256. */
const MAC_BYTES = 36;

/** `data`'s MAC under `secret`, headed by the key's name. */
export function macOf(key: Key, secret: Buffer, data: string | Uint8Array): Buffer {
  return Buffer.concat([key.id, createHmac('sha256', secret).update(data).digest()]);
}

/**
 * The key among `keys` that `mac` is `data`'s MAC under, if any. An empty
 * MAC, as the upgrade leaves, is under none. The four bytes only say which
 * keys to try: two that share a name are both tried.
 */
export function checked(keys: readonly Key[], secret: (key: Key) => Buffer, data: string | Uint8Array, mac: Uint8Array): Key | undefined {
  if (mac.length !== MAC_BYTES) return undefined;
  return keys.find((key) => key.id.equals(mac.subarray(0, 4)) && timingSafeEqual(macOf(key, secret(key), data), mac));
}

/**
 * What a row's MAC covers: its table's name, then each sealed column that
 * holds a value, by name. A null is left out, so a nullable column added
 * later leaves every MAC made before it good. Times are milliseconds and
 * bytes hex, so that a row reads back from the database as exactly what was
 * sealed.
 */
function sealedText(table: PgTable, row: object): string {
  const shape = shapeOf(table);
  const fields: [string, unknown][] = [];
  for (const column of shape.columns) {
    const value: unknown = (row as Record<string, unknown>)[column.key] ?? null;
    if (!column.sealed || value === null) continue;
    fields.push([column.name, column.kind === 'time' ? (value as Date).getTime() : column.kind === 'bytes' ? (value as Buffer).toString('hex') : value]);
  }
  fields.sort(([a], [b]) => (a < b ? -1 : 1));
  return JSON.stringify([shape.name, ...fields]);
}

/** The MAC `key` puts on `row`. */
export function seal(key: Key, table: PgTable, row: object): Buffer {
  return macOf(key, key.rows, sealedText(table, row));
}

/** The key `row`'s MAC is good under, if any: a row with none is not the vault's, and no decision sees it. */
export function sealedBy<T extends Sealed>(keys: readonly Key[], table: T, row: Row<T>): Key | undefined {
  return checked(keys, (key) => key.rows, sealedText(table, row), (row as { mac: Buffer }).mac);
}
