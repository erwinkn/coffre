import { sql, type SQL, type SQLWrapper } from 'drizzle-orm';

/**
 * What a change in `log_changes` records besides its op, which the audit
 * pages list: a sign-in through a trust binding
 * (`signIn`); a token the vault issued (`issue`); a credential it
 * revoked by request, or that signed itself out (a revoke's `reason`).
 * Each is known by text its payload holds (`holds`), and by how the
 * payload starts (`starts`): the vault writes it canonical, its keys in
 * order, so an issue's is `{"caller":…` and a revoke's
 * `{"op":"credential.revoke",…`. A string the payload holds has its quotes
 * escaped, but an object's keys need not be the vault's own (a role's
 * name, in the roles' change), so where the text alone could be
 * one, the start says whose payload it is. The partial indexes of
 * `log_changes` hold each set, and a read that is to use one repeats its
 * condition (`recorded`), word for word and with no parameter.
 */
export const RECORDS = {
  signIn: { holds: '"signIn":{' },
  issue: { starts: '{"caller":"', holds: '"issue":{"by":"' },
  revoke: { starts: '{"op":"credential.revoke",', holds: '"reason":"revoke"' },
  signOut: { starts: '{"op":"credential.revoke",', holds: '"reason":"sign_out"' },
  // A key write and a member's first add down the two-trip path: the change is their only record, and names the read it was decided on (`inputs`, the digest, which only those two
  // paths write). Keys sort, so every key write's change starts with its `digest`, today's path's too: that start only
  // narrows the match to key writes, and `inputs` picks the two-trip ones out; drop it and every write is listed twice.
  // An add's change starts with `inputs`, its own first, as no change of today's path does.
  written: { starts: '{"digest":', holds: '"inputs":"' },
  admitted: { starts: '{"inputs":"', holds: '"op":"member.add"' },
  // Their refusals, which the vault's decision makes on the read and records itself (refusal.ts): a change of the
  // request's own object, its payload's first key its `code`, as no other change's is (an op's, a ref's, a caller's or a digest's come first in theirs).
  refusedWrite: { starts: '{"code":"', holds: '"op":"write.refused"' },
  refusedAdd: { starts: '{"code":"', holds: '"op":"add.refused"' },
} as const satisfies Record<string, { starts?: string; holds: string }>;

export type ChangeRecord = keyof typeof RECORDS;

/** Whether `payload` holds one of `records`: an index's condition, and the reads' that use it. */
export function recorded(payload: SQLWrapper, ...records: ChangeRecord[]): SQL {
  const at = (text: string) => sql`strpos(${payload}, ${sql.raw(`'${text}'`)})`;
  const each = records.map((record) => {
    const { starts, holds }: { starts?: string; holds: string } = RECORDS[record];
    return starts === undefined ? sql`${at(holds)} > 0` : sql`(${at(starts)} = 1 AND ${at(holds)} > 0)`;
  });
  return each.length === 1 ? each[0]! : sql`(${sql.join(each, sql` OR `)})`;
}

/**
 * A field of a change's payload, as the indexes of `log_changes` that hold one (`log_changes_written_environment_idx`)
 * repeat it, word for word: the payload as JSON, the field's text.
 */
export function recordField(payload: SQLWrapper, field: 'environmentId'): SQL {
  return sql`(${payload}::jsonb ->> ${sql.raw(`'${field}'`)})`;
}
