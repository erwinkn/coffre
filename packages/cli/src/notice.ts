// Whether an instance's database is behind the code it runs, said once a
// day per instance, on stderr, by any command that talks to it. Only owners
// and root admins are told an instance's version (`/me`), and only they can
// migrate it; for anyone else, and for service tokens, this says nothing.
import type { InstanceState } from '@coffre/client';

export const DAY_MS = 24 * 60 * 60 * 1000;

/** When each instance was last asked, by origin. */
export type Checked = Record<string, number>;

/** The line to show, or null: nothing pending, or nothing told. */
export function noticeFor(origin: string, instance: InstanceState | null): string | null {
  if (instance === null) return null;
  const pending = instance.migrations.known.slice(instance.migrations.applied);
  if (pending.length === 0) return null;
  const what = pending.length === 1 ? '1 migration' : `${pending.length} migrations`;
  return `${what} pending on ${origin} (${pending.join(', ')}): run \`coffre migrate\``;
}

/**
 * The notice for `origin`, at most once a day: null without asking when it
 * was asked less than a day ago; otherwise `me` is asked, and the time kept,
 * whatever the answer. A failure to ask says nothing, and is not kept.
 */
export async function dailyNotice(
  origin: string,
  now: number,
  checked: { read(): Checked; write(checked: Checked): void },
  me: () => Promise<{ instance: InstanceState | null }>,
): Promise<string | null> {
  const last = checked.read()[origin];
  if (last !== undefined && now - last < DAY_MS) return null;
  let instance: InstanceState | null;
  try {
    ({ instance } = await me());
  } catch {
    return null;
  }
  checked.write({ ...checked.read(), [origin]: now });
  return noticeFor(origin, instance);
}
