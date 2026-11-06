#!/usr/bin/env node
// pnpm test:compat (compat-check.sh), for a release from before 0.16.0's
// table renames (T178, packages/db/src/migrations/postgres/0073_table_renames.sql)
// only: tells that release's conformance the three names it holds the
// database to by name.
//
// Its code needs nothing: it reads and writes the old names, which 0.16.0
// keeps one release as views of the renamed tables. Its harness does: it
// requires `vault_members`, `vault_grants` and `device_authorizations` among
// the database's base tables, and holds the vault's login to writing no base
// table but `vault_members`, `vault_grants` and the log's two. Renamed, those
// are views, and `principals` and `grants` base tables the vault writes, so
// the harness fails before it checks anything else. Two edits, nothing more:
// the shared tables it requires by their new names, and `principals` and
// `grants` among the vault's own. Every other base table stays under its
// vault-must-not-write check.
//
// Each edit must match the release's source exactly once, or this fails: a
// release whose harness reads otherwise is never held unchecked. The file is
// moved aside and a new one takes its place, never written through: pnpm
// links it from its store.
//
//   node scripts/compat/renamed-tables.mjs <the release's @coffre/conformance/dist/main.js>
//
// Delete this, and its call, once 0.16.0 is the newest release.
import { readFileSync, renameSync, writeFileSync } from 'node:fs';

const EDITS = [
  {
    what: "the shared tables its storage check requires (storage.ts, TABLES)",
    from: `const TABLES = [
\t"projects",
\t"environments",
\t"secrets",
\t"secret_versions",
\t"vault_members",
\t"vault_grants",
\t"audit_log",
\t"audit_chain_head",
\t"identities",
\t"credentials",
\t"device_authorizations"
];`,
    to: `const TABLES = [
\t"projects",
\t"environments",
\t"secrets",
\t"secret_versions",
\t"principals",
\t"grants",
\t"audit_log",
\t"audit_chain_head",
\t"identities",
\t"credentials",
\t"device_logins"
];`,
  },
  {
    what: "the tables its vault login may write (logins.ts, vaultReadOnly)",
    from: `.filter((name) => ![
\t\t"vault_members",
\t\t"vault_grants",
\t\t"audit_log",
\t\t"audit_chain_head"
\t].includes(name));`,
    to: `.filter((name) => ![
\t\t"vault_members",
\t\t"vault_grants",
\t\t"principals",
\t\t"grants",
\t\t"audit_log",
\t\t"audit_chain_head"
\t].includes(name));`,
  },
];

const [file] = process.argv.slice(2);
if (file === undefined) {
  console.error('usage: renamed-tables.mjs <@coffre/conformance/dist/main.js>');
  process.exit(2);
}
const aside = `${file}.release`;
let text;
try {
  text = readFileSync(aside, 'utf8');
} catch {
  text = readFileSync(file, 'utf8');
  renameSync(file, aside);
}
for (const edit of EDITS) {
  const found = text.split(edit.from).length - 1;
  if (found !== 1) {
    console.error(`compat-check: ${edit.what} is not the source this patch expects (${found} matches, not 1) in ${file}`);
    process.exit(1);
  }
  text = text.replace(edit.from, edit.to);
}
// The note goes after a shebang, which must stay the first line.
const shebang = text.startsWith('#!') ? text.slice(0, text.indexOf('\n') + 1) : '';
writeFileSync(file, `${shebang}// pnpm test:compat: 0.16.0's renamed tables told to this release's conformance (scripts/compat/renamed-tables.mjs).\n${text.slice(shebang.length)}`);
