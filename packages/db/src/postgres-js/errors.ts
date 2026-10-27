/** What Postgres said in an ErrorResponse or a NoticeResponse, each field by its name. */
export type Notice = Partial<Record<(typeof FIELDS)[keyof typeof FIELDS], string>>;

/** An ErrorResponse's fields, by their code. `data type_name` is upstream's spelling, kept. */
export const FIELDS = {
  83: 'severity_local', // S
  86: 'severity', // V
  67: 'code', // C
  77: 'message', // M
  68: 'detail', // D
  72: 'hint', // H
  80: 'position', // P
  112: 'internal_position', // p
  113: 'internal_query', // q
  87: 'where', // W
  115: 'schema_name', // s
  116: 'table_name', // t
  99: 'column_name', // c
  100: 'data type_name', // d
  110: 'constraint_name', // n
  70: 'file', // F
  76: 'line', // L
  82: 'routine', // R
} as const;

/** An error Postgres answered, with its fields: `code` (the SQLSTATE), `detail`, `constraint_name`… */
export class PostgresError extends Error {
  declare readonly severity_local: string;
  declare readonly severity: string;
  declare readonly code: string;
  declare readonly detail?: string;
  declare readonly hint?: string;
  declare readonly position?: string;
  declare readonly internal_position?: string;
  declare readonly internal_query?: string;
  declare readonly where?: string;
  declare readonly schema_name?: string;
  declare readonly table_name?: string;
  declare readonly column_name?: string;
  declare readonly constraint_name?: string;
  declare readonly file?: string;
  declare readonly line?: string;
  declare readonly routine?: string;

  constructor(fields: Notice) {
    super(fields.message);
    this.name = this.constructor.name;
    Object.assign(this, fields);
  }
}

/** An error of the driver's own, with its `code`. */
export type DriverError = Error & { code: string };

/** The connection lost, never made or ended (`CONNECTION_CLOSED`, `CONNECT_TIMEOUT`…), naming where it was to. */
export function connection(code: string, options: { host: string; port: number; path?: string | undefined }): DriverError {
  const where = options.path ?? options.host + ':' + options.port;
  const error = Object.assign(new Error('write ' + code + ' ' + where), {
    code,
    errno: code,
    address: options.path ?? options.host,
    ...(options.path ? {} : { port: options.port }),
  });
  Error.captureStackTrace(error, connection);
  return error;
}

export function postgres(fields: Notice): PostgresError {
  const error = new PostgresError(fields);
  Error.captureStackTrace(error, postgres);
  return error;
}

export function generic(code: string, message: string): DriverError {
  const error = Object.assign(new Error(code + ': ' + message), { code });
  Error.captureStackTrace(error, generic);
  return error;
}

export function notSupported(name: string): DriverError {
  const error = Object.assign(new Error(name + ' (B) is not supported'), { code: 'MESSAGE_NOT_SUPPORTED', name });
  Error.captureStackTrace(error, notSupported);
  return error;
}
