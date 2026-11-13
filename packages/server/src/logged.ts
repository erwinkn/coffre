// What a log line says about an error. Logged as it is, an error shows
// only its stack on Workers, without its message, and none of what Postgres
// said: an unhandled error in production then names the line and nothing
// else. So each error is logged as a plain object: its name and message,
// Postgres's fields (`code`, `detail`, `hint`, …), the SQL Drizzle ran but
// never its parameters, which may hold values, the same for its cause, and
// its stack last.

/**
 * The fields postgres.js copies from a Postgres error response, each by the
 * name a log line gives it: the names node-postgres gave, which logs kept.
 */
const POSTGRES_FIELDS = [
  ['severity', 'severity'],
  ['code', 'code'],
  ['detail', 'detail'],
  ['hint', 'hint'],
  ['position', 'position'],
  ['where', 'where'],
  ['schema_name', 'schema'],
  ['table_name', 'table'],
  ['column_name', 'column'],
  ['data type_name', 'dataType'],
  ['constraint_name', 'constraint'],
  ['routine', 'routine'],
] as const;

/** How many causes deep a log line follows an error. */
const DEPTH = 4;

export function logged(error: unknown, depth = 0): unknown {
  if (!(error instanceof Error)) return error;
  const fields = error as Error & Record<string, unknown>;
  // Drizzle's error puts the parameters in its message: the SQL alone, from its own field.
  const message = typeof fields.query === 'string' && 'params' in fields ? `Failed query: ${fields.query}` : error.message;
  const out: Record<string, unknown> = { name: error.name, message };
  for (const [field, name] of POSTGRES_FIELDS) {
    if (fields[field] !== undefined) out[name] = fields[field];
  }
  if (error.cause !== undefined && depth < DEPTH) out.cause = logged(error.cause, depth + 1);
  // The frames alone: the stack begins with the message, the parameters with it.
  if (depth === 0 && error.stack !== undefined) out.stack = error.stack.split('\n').filter((line) => /^\s+at /.test(line)).join('\n');
  return out;
}
