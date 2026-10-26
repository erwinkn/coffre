// What `coffre backup`, `coffre restore` and `coffre verify backup` say to
// --help: apart from the commands, which load the database driver, so that
// help loads nothing.

export const BACKUP_USAGE = `usage: coffre backup [<file>]

Dumps the database with pg_dump, as a backup login, a member of
coffre_backup (\`coffre migrate --backup-login <login>\` grants it), into
<file> (coffre-<UTC time>.dump by default), and writes what it holds
beside it, <file minus .dump>.manifest.json: each table's rows, counted and
hashed, the newest migration and the audit log's head, read in the snapshot
pg_dump dumps, and the dump's SHA-256. Neither file holds a key: values stay
encrypted, but plain ones are in the clear, so the files are yours alone.

Asks for the login's connection string at a hidden prompt, or reads it from
stdin, never an argument. Needs PostgreSQL's pg_dump, of the server's major
version or newer, on PATH. Refuses a login whose row-level security would
hide rows of any table it counts, the audit log's above all, from the dump.`;

const KEYS_HELP = `With --keys, it asks for the vault keys, then the app keys, separated by
spaces: first the one each signs with now, then any it replaced. The
vault signs with its own signing key if its config gives one, otherwise
with its current vault key; a vault with a signing key of its own gets
that first, then its vault keys. It
then also opens every version of every value, each under the vault key
its vault ID names, and authenticates each audit entry under the keys
given; entries under others are linked only, and counted, but each
author's newest entries must be under the first key given, and no other
may write once it has. On stdin, the connection string
is the first line, the vault keys the second and the app keys the third;
a blank line skips them. Only local vault keys: one in a key service
never leaves it.`;
export const RESTORE_USAGE = `usage: coffre restore <dump> [--keys]

Restores a dump \`coffre backup\` made into an empty database, as its
owner, with pg_restore, then checks it against the manifest beside the
dump: every table's rows, counted and hashed, the migrations, the audit
log's head, and its chain from the first entry to the head. Says what is
left to do before the deployment runs on it.

Asks for the owner's connection string at a hidden prompt, or reads it
from stdin, never an argument. The server needs coffre's roles, which the
dump's grants name. Needs PostgreSQL's pg_restore on PATH.

${KEYS_HELP}

Exits 1 when a check fails.`;

export const VERIFY_BACKUP_USAGE = `usage: coffre verify backup <dump> [--keys]

Restores a dump \`coffre backup\` made into an empty scratch database, then
checks it as \`coffre restore\` does. Leaves owners, grants and row policies
out, so it needs none of coffre's roles on that server; the copy stays,
for you to drop. Asks for that database's owner's connection string at a
hidden prompt, or reads it from stdin. Needs pg_restore on PATH.

${KEYS_HELP}

Exits 1 when a check fails.`;
