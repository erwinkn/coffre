import { SyncConfigError } from './types.ts';

// Just enough validation to turn untrusted JSON into a typed config with
// messages a person can act on; not a schema library.

type Fields = Record<string, unknown>;

export function readFields(input: unknown, label: string, allowed: readonly string[]): Fields {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new SyncConfigError(`${label} config must be an object`);
  }
  // A misspelled optional field would otherwise be dropped silently, and the
  // sync would go somewhere the user did not mean.
  const unknown = Object.keys(input).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new SyncConfigError(`${label} config has unknown field ${unknown.map((key) => `"${key}"`).join(', ')}`);
  }
  return input as Fields;
}

type StringRule = { pattern?: RegExp; hint?: string; maxLength?: number };

export function requiredString(fields: Fields, name: string, rule: StringRule = {}): string {
  const value = fields[name];
  if (value === undefined || value === null || value === '') {
    throw new SyncConfigError(`"${name}" is required`);
  }
  return checkString(value, name, rule);
}

export function optionalString(fields: Fields, name: string, rule: StringRule = {}): string | undefined {
  const value = fields[name];
  if (value === undefined || value === null) return undefined;
  return checkString(value, name, rule);
}

function checkString(value: unknown, name: string, rule: StringRule): string {
  if (typeof value !== 'string') throw new SyncConfigError(`"${name}" must be a string`);
  if (value.trim() !== value || value === '') {
    throw new SyncConfigError(`"${name}" must not be empty or padded with spaces`);
  }
  if (rule.maxLength !== undefined && value.length > rule.maxLength) {
    throw new SyncConfigError(`"${name}" must be at most ${rule.maxLength} characters`);
  }
  if (rule.pattern && !rule.pattern.test(value)) {
    throw new SyncConfigError(`"${name}" ${rule.hint ?? 'is not valid'}`);
  }
  return value;
}

export function optionalEnum<T extends string>(fields: Fields, name: string, options: readonly T[]): T | undefined {
  const value = fields[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || !options.includes(value as T)) {
    throw new SyncConfigError(`"${name}" must be one of ${options.map((option) => `"${option}"`).join(', ')}`);
  }
  return value as T;
}
