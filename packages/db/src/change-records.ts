import { sql, type SQL, type SQLWrapper } from 'drizzle-orm';

/**
 * What a change of 0.15's log records besides its op, which the audit pages
 * list where 0.14's entry stood (D147): a sign-in through a trust binding
 * (`signIn`, T156); a token the vault issued (`issue`); a credential it
 * revoked by request, or that signed itself out (a revoke's `reason`,
 * T164). Each is known by text its payload holds (`holds`), and by how the
 * payload starts (`starts`): the vault writes it canonical, its keys in
 * order, so an issue's is `{"caller":…` and a revoke's
 * `{"op":"credential.revoke",…`. A string the payload holds has its quotes
 * escaped, but an object's keys need not be the vault's own (a role's
 * name, in the roles' change: review r1), so where the text alone could be
 * one, the start says whose payload it is. The partial indexes of
 * `log_changes` hold each set, and a read that is to use one repeats its
 * condition (`recorded`), word for word and with no parameter.
 */
export const RECORDS = {
  signIn: { holds: '"signIn":{' },
  issue: { starts: '{"caller":"', holds: '"issue":{"by":"' },
  revoke: { starts: '{"op":"credential.revoke",', holds: '"reason":"revoke"' },
  signOut: { starts: '{"op":"credential.revoke",', holds: '"reason":"sign_out"' },
} as const satisfies Record<string, { starts?: string; holds: string }>;

export type ChangeRecord = keyof typeof RECORDS;

/** Whether `payload` holds one of `records`, on Postgres or SQLite: an index's condition, and the reads' that use it. */
export function recorded(engine: 'postgres' | 'sqlite', payload: SQLWrapper, ...records: ChangeRecord[]): SQL {
  const at = (text: string) => {
    const marker = sql.raw(`'${text}'`);
    return engine === 'postgres' ? sql`strpos(${payload}, ${marker})` : sql`instr(${payload}, ${marker})`;
  };
  const each = records.map((record) => {
    const { starts, holds }: { starts?: string; holds: string } = RECORDS[record];
    return starts === undefined ? sql`${at(holds)} > 0` : sql`(${at(starts)} = 1 AND ${at(holds)} > 0)`;
  });
  return each.length === 1 ? each[0]! : sql`(${sql.join(each, sql` OR `)})`;
}
