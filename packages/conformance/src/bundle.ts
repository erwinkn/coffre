// What the browser loads, held to holding nothing of the server: the
// client files a deployment's build wrote, read as the browser would get
// them. A page that imports across the line otherwise just grows by the
// database layer, with no error, since a bundler keeps a module whose top
// level has side effects, such as `pgTable(…)`, even when nothing uses its
// exports.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * The schema's tables whose names could appear in no page: those with an
 * underscore. Single words such as `secrets` are in the pages' own copy.
 * A test holds this to the schema (@coffre/db).
 */
export const SERVER_TABLES = [
  'audit_chain_head',
  'audit_log',
  'consumed_tokens',
  'device_authorizations',
  'dismissed_keys',
  'mcp_connections',
  'oauth_clients',
  'project_folders',
  'secret_folders',
  'secret_references',
  'secret_versions',
  'service_bindings',
  'vault_grants',
  'vault_members',
];

/** What only server code carries. */
const MARKERS: { label: string; pattern: RegExp }[] = [
  { label: 'drizzle-orm', pattern: /drizzle:[A-Z]/ },
  ...SERVER_TABLES.map((name) => ({ label: `the table ${name}`, pattern: new RegExp(`\\b${name}\\b`) })),
  { label: 'pg', pattern: /cloudflare:sockets|pg-protocol|pgpass/ },
  { label: 'libsql', pattern: /@libsql|libsql/ },
  { label: 'a COFFRE_ variable read', pattern: /env\s*(\.|\[\s*['"`])COFFRE_/ },
];

/** Files the browser runs or reads as text, whatever their size or how the build emitted them. */
const TEXT = /\.(m?js|css|html|json|svg|txt|wasm\.js)$/;

/** What each file holds that only the server may: `<file>: <what>`. */
export function serverCodeIn(files: { name: string; code: string }[]): string[] {
  return files.flatMap(({ name, code }) => MARKERS.filter(({ pattern }) => pattern.test(code)).map(({ label }) => `${name}: ${label}`));
}

/** The text files under `dir`, the browser's half of a build, each as the browser reads it. */
export function clientFiles(dir: string): { name: string; code: string }[] {
  const files: { name: string; code: string }[] = [];
  const walk = (at: string) => {
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      const path = join(at, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (TEXT.test(entry.name)) files.push({ name: relative(dir, path), code: new TextDecoder().decode(readFileSync(path)) });
    }
  };
  walk(dir);
  return files;
}
