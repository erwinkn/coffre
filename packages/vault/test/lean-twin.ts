// The lean statement answers what the full one would, or hands off (0086). A suite run as a twin makes every use
// twice on the same rows: a copy of `use_credential` that answers `whole` wherever the full statement would run, in a
// subtransaction rolled back, then a copy that never runs the lean one, which makes the use. Wherever the lean copy
// answered, both answers must be the same but for the entry's number, or the call fails.
import test from 'node:test';
import assert from 'node:assert/strict';

import { sql } from 'drizzle-orm';

import { onOpen, rows, run, type TestDatabase } from './database.ts';

const GATE = 'IF (dry AND form = 0) OR (NOT dry AND NOT probe AND NOT whole) THEN';
const HANDOFF = 'IF r.state = \'whole\' THEN\n            whole := true;\n            CONTINUE;\n        END IF;';
const WHOLE = 'RETURN json_build_object(\'state\', \'whole\');';

/**
 * The file's database a twin's (one, however often opened), and at least `least` uses answered by the lean copy: a
 * test of its own, the file's last, since a failing root hook goes unreported in `use.test.ts` (a run's exit stays 0).
 */
export function twinLean(least: number): void {
  let twinned: Promise<void> | undefined;
  let closed = 0;
  const open = new Set<TestDatabase>();
  const count = async (db: TestDatabase) => Number((await rows<{ n: string }>(db.owner, sql.raw('SELECT count(*) AS n FROM lean_twins')))[0]!.n);
  onOpen.push(async (db) => {
    await (twinned ??= twin(db.owner));
    open.add(db);
    const close = db.close;
    db.close = async () => {
      closed = Math.max(closed, await count(db));
      open.delete(db);
      await close();
    };
  });
  test(`the lean statement answered at least ${least} of the file's uses`, async () => {
    const answered = Math.max(closed, ...await Promise.all([...open].map(count)));
    assert.ok(answered >= least, `the lean statement answered ${answered} uses, not ${least}`);
  });
}

async function twin(owner: Parameters<typeof run>[0]): Promise<void> {
  const [fn] = await rows<{ def: string; args: string[] }>(owner, sql.raw(
    `SELECT pg_get_functiondef(p.oid) AS def, p.proargnames AS args FROM pg_proc p WHERE p.oid = 'public.use_credential'::regproc`));
  const copy = (name: string, edits: [string, string][]) => edits.reduce((def, [from, to]) => {
    assert.ok(def.includes(from), `use_credential no longer holds ${from}`);
    return def.replace(from, to);
  }, fn!.def.replace('public.use_credential(', `public.${name}(`));
  await run(owner, sql.raw(copy('use_credential_lean', [[GATE, `IF NOT dry AND (probe OR whole) THEN ${WHOLE} END IF;\n        ${GATE}`], [HANDOFF, `IF r.state = 'whole' THEN ${WHOLE} END IF;`]])));
  await run(owner, sql.raw(copy('use_credential_full', [[GATE, 'IF dry AND form = 0 THEN']])));
  await run(owner, sql.raw('CREATE TABLE lean_twins (state text)'));
  const call = (name: string) => `public.${name}(${fn!.args.map((arg) => `${arg} => ${arg}`).join(', ')})`;
  // `a`, the lean copy's answer, and `b`, the full one's (`full` is a keyword).
  await run(owner, sql.raw(`${fn!.def.slice(0, fn!.def.indexOf('AS $function$'))}AS $twin$
DECLARE a json; b json;
BEGIN
    BEGIN
        a := ${call('use_credential_lean')};
        RAISE EXCEPTION USING ERRCODE = 'LT001', MESSAGE = a::text;
    EXCEPTION WHEN SQLSTATE 'LT001' THEN a := SQLERRM::json; WHEN OTHERS THEN a := json_build_object('error', SQLSTATE);
    END;
    BEGIN
        b := ${call('use_credential_full')};
    EXCEPTION WHEN OTHERS THEN
        IF a ->> 'error' IS DISTINCT FROM SQLSTATE AND a ->> 'state' IS DISTINCT FROM 'whole' THEN RAISE EXCEPTION 'the lean statement answered %, the full one raised %', a, SQLSTATE; END IF;
        RAISE;
    END;
    IF a ->> 'state' IS DISTINCT FROM 'whole' THEN
        IF a::jsonb - 'number' IS DISTINCT FROM b::jsonb - 'number' OR (a ->> 'number' IS NULL) <> (b ->> 'number' IS NULL) THEN
            RAISE EXCEPTION 'the lean statement answered %, the full one %', a, b;
        END IF;
        INSERT INTO public.lean_twins VALUES (a ->> 'state');
    END IF;
    RETURN b;
END
$twin$`));
}
