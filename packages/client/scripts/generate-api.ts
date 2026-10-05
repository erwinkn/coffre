/**
 * Writes `src/api.ts`: every route's input and output, as the JSON that
 * crosses the wire, printed from the server's route table.
 *
 *   node scripts/generate-api.ts           write it
 *   node scripts/generate-api.ts --check   exit 1 if it is out of date
 *
 * The client's types would otherwise be the server's own, and its `.d.ts`
 * would carry the server along: its database, drizzle and pg. Printed out,
 * they are plain object types with nothing to import.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = fileURLToPath(new URL('../../server/src/', import.meta.url));
const target = fileURLToPath(new URL('../src/api.ts', import.meta.url));

/**
 * The named types the client re-exports, beside the route map: what callers
 * hold on to and pass around, such as the pages' views of a member.
 */
const NAMED = {
  AccessValue: 'api/access.ts',
  AuditEntryView: 'api/audit.ts',
  AuthInfo: 'fetch-api.ts',
  BindingPlan: 'api/workloads.ts',
  BindingView: 'api/workloads.ts',
  Deletion: 'api/projects.ts',
  DeletionResult: 'api/projects.ts',
  WorkloadIds: 'api/workloads.ts',
  DryRunOutcome: 'api/secrets.ts',
  DryRunResult: 'api/secrets.ts',
  IdentityRow: 'api/signin.ts',
  InheritedGrant: 'api/projects.ts',
  InstanceState: 'api/projects.ts',
  Me: 'api/projects.ts',
  Member: 'api/members.ts',
  OffboardingReport: 'api/members.ts',
  ProjectSummary: 'api/projects.ts',
  RemovedMember: 'api/members.ts',
  SecretKey: 'api/secrets.ts',
  SecretVersion: 'api/secrets.ts',
  ServiceTokenRow: 'api/signin.ts',
  SessionRow: 'api/signin.ts',
  SetResult: 'api/secrets.ts',
} as const;

const PROBE = `${root}__api_probe.ts`;

function probeSource(keys: readonly string[]): string {
  const lines = [
    `import type { RouteInput, RouteOutput } from './api/routes.ts';`,
    ...Object.entries(NAMED).map(([name, file]) => `import type { ${name} } from './${file}';`),
    ...Object.keys(NAMED).map((name) => `type named_${name} = ${name};`),
    ...keys.flatMap((key, i) => [
      `type input_${i} = RouteInput<${JSON.stringify(key)}>;`,
      `type output_${i} = RouteOutput<${JSON.stringify(key)}>;`,
    ]),
  ];
  return lines.join('\n');
}

function program(probe: string): ts.Program {
  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2023,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    allowImportingTsExtensions: true,
    strict: true,
    noEmit: true,
    skipLibCheck: true,
    types: ['node'],
    // The server imports the other packages by name; read their sources, as tsconfig.base.json does.
    customConditions: ['coffre:source'],
  };
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile;
  host.getSourceFile = (name, version, ...rest) =>
    name === PROBE ? ts.createSourceFile(name, probe, version) : getSourceFile(name, version, ...rest);
  const fileExists = host.fileExists;
  host.fileExists = (name) => name === PROBE || fileExists(name);
  return ts.createProgram([PROBE], options, host);
}

/** The type each alias in the probe names. */
function aliases(built: ts.Program): Map<string, ts.Type> {
  const checker = built.getTypeChecker();
  const errors = ts.getPreEmitDiagnostics(built).filter((error) => error.file?.fileName === PROBE);
  if (errors.length > 0) throw new Error(ts.flattenDiagnosticMessageText(errors[0].messageText, '\n'));
  const types = new Map<string, ts.Type>();
  for (const statement of built.getSourceFile(PROBE)!.statements) {
    if (ts.isTypeAliasDeclaration(statement)) types.set(statement.name.text, checker.getTypeAtLocation(statement.name));
  }
  return types;
}

/** The route keys, in the table's order. */
function routeKeys(): string[] {
  const keys = aliases(program(`import type { RouteKey } from './api/routes.ts';\ntype keys = RouteKey;`)).get('keys')!;
  return (keys.isUnion() ? keys.types : [keys]).map((type) => (type as ts.StringLiteralType).value);
}

const KEYWORDS = ['string', 'number', 'boolean', 'undefined', 'null'];

/** Literals in order, then keywords, then objects and arrays as they came. */
function byKind(a: string, b: string): number {
  const rank = (part: string) => (/^["\d-]/.test(part) ? 0 : KEYWORDS.includes(part) ? 1 : 2);
  const ranked = rank(a) - rank(b);
  if (ranked !== 0) return ranked;
  if (rank(a) === 0) return a < b ? -1 : a > b ? 1 : 0;
  return rank(a) === 1 ? KEYWORDS.indexOf(a) - KEYWORDS.indexOf(b) : 0;
}

/**
 * A type as the JSON that carries it: dates become strings, and functions
 * have no place. A type that contains itself, such as a JSON value, is
 * printed once under its own name.
 */
function printer(checker: ts.TypeChecker) {
  const open = new Set<ts.Type>();
  const recursive = new Map<string, ts.Type>();

  function print(type: ts.Type, indent: string): string {
    const flags = type.flags;
    if (flags & ts.TypeFlags.Any || flags & ts.TypeFlags.Unknown) return 'unknown';
    if (flags & ts.TypeFlags.Never) return 'never';
    if (flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void)) return 'undefined';
    if (flags & ts.TypeFlags.Null) return 'null';
    if (flags & ts.TypeFlags.String || flags & ts.TypeFlags.TemplateLiteral) return 'string';
    if (flags & ts.TypeFlags.Number) return 'number';
    if (flags & ts.TypeFlags.Boolean) return 'boolean';
    if (flags & ts.TypeFlags.StringLiteral) return JSON.stringify((type as ts.StringLiteralType).value);
    if (flags & ts.TypeFlags.NumberLiteral) return String((type as ts.NumberLiteralType).value);
    if (flags & ts.TypeFlags.BooleanLiteral) return (type as { intrinsicName?: string }).intrinsicName ?? 'boolean';
    if (!type.isUnion() && !(flags & ts.TypeFlags.Object) && !type.isIntersection()) {
      throw new Error(`cannot print ${checker.typeToString(type)} as JSON`);
    }

    if (open.has(type)) {
      const name = type.aliasSymbol?.name;
      if (name === undefined) throw new Error(`a recursive type without a name: ${checker.typeToString(type)}`);
      recursive.set(name, type);
      return name;
    }
    open.add(type);
    try {
      return type.isUnion() ? union(type.types, indent) : object(type, indent);
    } finally {
      open.delete(type);
    }
  }

  function union(types: readonly ts.Type[], indent: string): string {
    const parts = types.map((member) => print(member, indent));
    // `boolean` reaches a union as `false | true`.
    const merged = parts.includes('false') && parts.includes('true')
      ? [...parts.filter((part) => part !== 'false' && part !== 'true'), 'boolean']
      : parts;
    // The checker's order follows the order it met each type in, which any
    // change to the server can shuffle; a fixed one keeps the diffs to real changes.
    return [...new Set(merged)].sort(byKind).join(' | ');
  }

  function object(type: ts.Type, indent: string): string {
    if (type.symbol?.name === 'Date') return 'string';
    if (checker.isTupleType(type)) {
      return `[${checker.getTypeArguments(type as ts.TypeReference).map((member) => print(member, indent)).join(', ')}]`;
    }
    if (checker.isArrayType(type)) {
      const element = checker.getTypeArguments(type as ts.TypeReference)[0];
      const printed = print(element, indent);
      // `A | B[]` is an A or a list of B; a list of either needs `(A | B)[]`.
      // An intersection prints as one object, and `boolean` as one word.
      return element.isUnion() && printed.includes(' | ') ? `(${printed})[]` : `${printed}[]`;
    }
    if (type.getCallSignatures().length > 0) throw new Error(`a function is not JSON: ${checker.typeToString(type)}`);

    const inner = `${indent}  `;
    const lines: string[] = [];
    for (const info of checker.getIndexInfosOfType(type)) {
      lines.push(`${inner}[key: ${print(info.keyType, inner)}]: ${print(info.type, inner)};`);
    }
    for (const property of checker.getPropertiesOfType(type)) {
      const optional = (property.flags & ts.SymbolFlags.Optional) !== 0;
      const value = checker.getTypeOfSymbol(property);
      // `name?: T` already says it may be missing; JSON has no `undefined` to send.
      const members = (value.isUnion() ? value.types : [value]).filter(
        (member) => !optional || !(member.flags & ts.TypeFlags.Undefined),
      );
      const name = /^[A-Za-z_$][\w$]*$/.test(property.name) ? property.name : JSON.stringify(property.name);
      lines.push(`${inner}${name}${optional ? '?' : ''}: ${union(members, inner)};`);
    }
    return lines.length === 0 ? '{}' : `{\n${lines.join('\n')}\n${indent}}`;
  }

  /** The named recursive types the others refer to, each printed once. */
  function definitions(): string[] {
    const done = new Map<string, string>();
    for (let pending = [...recursive]; pending.length > 0; pending = [...recursive].filter(([name]) => !done.has(name))) {
      for (const [name, type] of pending) {
        open.add(type);
        try {
          done.set(name, `export type ${name} = ${type.isUnion() ? union(type.types, '') : object(type, '')};`);
        } finally {
          open.delete(type);
        }
      }
    }
    return [...done.keys()].sort().map((name) => done.get(name)!);
  }

  return { print, definitions };
}

export function generate(): string {
  const keys = routeKeys();
  const built = program(probeSource(keys));
  const types = aliases(built);
  const { print, definitions } = printer(built.getTypeChecker());
  const typeOf = (name: string) => types.get(name)!;

  const out = [
    '// Generated from the route table in packages/server/src/api/routes.ts by',
    '// `pnpm --dir packages/client generate`. Do not edit: a test fails when it',
    '// is out of date.',
    '',
    '/** Every route, by `METHOD /path`: what a caller sends (the body, or the query of a GET) and gets back. */',
    'export type Api = {',
  ];
  keys.forEach((key, i) => {
    out.push(`  ${JSON.stringify(key)}: {`);
    out.push(`    input: ${print(typeOf(`input_${i}`), '    ')};`);
    out.push(`    output: ${print(typeOf(`output_${i}`), '    ')};`);
    out.push('  };');
  });
  out.push('};', '');
  for (const name of Object.keys(NAMED)) {
    out.push(`export type ${name} = ${print(typeOf(`named_${name}`), '')};`, '');
  }
  for (const definition of definitions()) out.push(definition, '');
  return out.join('\n');
}

if (import.meta.main) {
  const text = generate();
  if (process.argv.includes('--check')) {
    if (readFileSync(target, 'utf8') !== text) {
      console.error('packages/client/src/api.ts is out of date: run `pnpm --dir packages/client generate`');
      process.exit(1);
    }
  } else {
    writeFileSync(target, text);
  }
}
