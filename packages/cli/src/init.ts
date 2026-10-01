// `coffre init --workers|--node [<dir>]`: a new deployment, as a small
// project of its own. The templates are the repository's examples/workers
// and examples/node, copied as they are but for two things in package.json:
// the project's name, and the version of coffre's packages, which becomes
// this CLI's own.
//
// Published, the CLI carries them in dist/templates, each `.gitignore`
// renamed `gitignore`: npm leaves any file called `.gitignore` out of a
// package.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const KINDS = ['workers', 'node'] as const;
export type Kind = (typeof KINDS)[number];

/** Where a template lives: in the package when published, else in the repository. */
export function templateDir(kind: Kind): string {
  const packed = fileURLToPath(new URL(`./templates/${kind}/`, import.meta.url));
  if (existsSync(packed)) return packed;
  return fileURLToPath(new URL(`../../../examples/${kind}/`, import.meta.url));
}

/**
 * A template's files, relative and sorted: everything but what its own
 * `.gitignore` names, such as installed packages, local state and secrets.
 * Patterns are file or directory names, `*` standing for any run of
 * characters.
 */
export function templateFiles(dir: string): string[] {
  const ignoreFile = [join(dir, '.gitignore'), join(dir, 'gitignore')].find((path) => existsSync(path));
  const ignored = (ignoreFile === undefined ? '' : readFileSync(ignoreFile, 'utf8'))
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map((glob) => new RegExp(`^${glob.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`));

  const files: string[] = [];
  const walk = (relative: string) => {
    for (const entry of readdirSync(join(dir, relative), { withFileTypes: true })) {
      if (ignored.some((pattern) => pattern.test(entry.name))) continue;
      const path = relative === '' ? entry.name : `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else files.push(path);
    }
  };
  walk('');
  return files.sort();
}

/** The name a template file has in a project. */
export function projectPath(templatePath: string): string {
  return templatePath === 'gitignore' ? '.gitignore' : templatePath;
}

/** A package name from a directory's, e.g. `Acme Secrets` → `acme-secrets`. */
function packageName(dir: string): string {
  const name = basename(dir)
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[-._]+|-+$/g, '');
  return name === '' ? 'coffre' : name;
}

/** The template's package.json, for this project and this version of coffre. */
function manifest(source: string, name: string, version: string): string {
  const pkg = JSON.parse(source) as Record<string, unknown>;
  pkg.name = name;
  for (const field of ['dependencies', 'devDependencies']) {
    const deps = pkg[field] as Record<string, string> | undefined;
    for (const dep of Object.keys(deps ?? {})) {
      if (dep.startsWith('@coffre/')) deps![dep] = version;
    }
  }
  return `${JSON.stringify(pkg, null, 2)}\n`;
}

/** Write a new deployment into `target`, which must be empty or absent. Returns the files written. */
export function init(kind: Kind, target: string, version: string): string[] {
  if (existsSync(target) && readdirSync(target).length > 0) {
    throw new Error(`${target} is not empty; give \`coffre init\` a new directory`);
  }
  const source = templateDir(kind);
  const written: string[] = [];
  for (const file of templateFiles(source)) {
    const path = projectPath(file);
    const content = readFileSync(join(source, file), 'utf8');
    mkdirSync(dirname(join(target, path)), { recursive: true });
    writeFileSync(join(target, path), path === 'package.json' ? manifest(content, packageName(target), version) : content);
    written.push(path);
  }
  return written;
}
