/**
 * A sync provider's form, as the web page and `coffre sync add` fill it in.
 *
 * Each provider describes its fields (`GET /syncs/providers`); the server's
 * parser validates every one of them (formats, lengths, combinations) and
 * says what is wrong in a sentence. This only turns what someone typed into
 * the JSON that parser expects.
 */
import type { SyncField, SyncProviderInfo } from './api.ts';

export type FormValues = Record<string, string | string[]>;

export function initialValues(provider: SyncProviderInfo): FormValues {
  return Object.fromEntries(
    provider.fields.map((field) => [field.name, field.type === 'text' ? '' : field.initial]),
  );
}

/** Whether the rest of the form makes the field meaningful. */
export function isAsked(field: SyncField, values: FormValues): boolean {
  if (field.type === 'options' || field.when === undefined) return true;
  const picked = values[field.when.field];
  const list = Array.isArray(picked) ? picked : [];
  return list.length === field.when.is.length && field.when.is.every((value) => list.includes(value));
}

/** The label of the first required field left empty, or null when the form can be sent. */
export function firstMissing(provider: SyncProviderInfo, values: FormValues): string | null {
  for (const field of provider.fields) {
    if (!isAsked(field, values)) continue;
    const value = values[field.name];
    const empty = typeof value === 'string' ? value.trim() === '' : (value ?? []).length === 0;
    if (empty && (field.type === 'options' || field.optional !== true)) return field.label;
  }
  return null;
}

/**
 * The provider's config. Text is trimmed, and an optional field left empty
 * is left out rather than sent as "", which the server rightly refuses.
 */
export function configFromForm(provider: SyncProviderInfo, values: FormValues): Record<string, unknown> {
  const config: Record<string, unknown> = {};
  for (const field of provider.fields) {
    if (!isAsked(field, values)) continue;
    const value = values[field.name];
    if (field.type === 'options') {
      const picked = Array.isArray(value) ? value : [];
      config[field.name] = field.multiple ? picked : picked[0];
    } else {
      const text = typeof value === 'string' ? value.trim() : '';
      if (text !== '') config[field.name] = text;
    }
  }
  return config;
}

/**
 * The config from `name=value` arguments, as the CLI takes them. A field with
 * several options takes them comma-separated, and one left out gets what the
 * form preselects. Text goes as typed, for the server to check.
 */
export function configFromArguments(provider: SyncProviderInfo, assignments: readonly string[]): Record<string, unknown> {
  const config: Record<string, unknown> = {};
  for (const assignment of assignments) {
    const equals = assignment.indexOf('=');
    const name = equals === -1 ? assignment : assignment.slice(0, equals);
    const field = provider.fields.find((candidate) => candidate.name === name);
    if (equals === -1 || field === undefined) {
      const names = provider.fields.map((candidate) => candidate.name).join(', ');
      throw new Error(`${provider.label} takes ${names} as name=value; got ${JSON.stringify(assignment)}`);
    }
    if (Object.hasOwn(config, name)) throw new Error(`${name} is given twice`);
    const value = assignment.slice(equals + 1);
    if (field.type === 'text') config[name] = value;
    else if (field.multiple) config[name] = value.split(',').map((item) => item.trim()).filter((item) => item !== '');
    else config[name] = value;
  }
  for (const field of provider.fields) {
    if (field.type === 'options' && !Object.hasOwn(config, field.name)) {
      config[field.name] = field.multiple ? field.initial : field.initial[0];
    }
  }
  return config;
}
