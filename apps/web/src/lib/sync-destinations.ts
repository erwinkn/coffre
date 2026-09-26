/**
 * What the Add sync form asks for, per destination.
 *
 * The server validates every field (formats, lengths, combinations) and says
 * what is wrong in a sentence; this only lays out the form and turns it into
 * the JSON the destination's config parser expects.
 */

export type DestinationKind = 'github-actions' | 'vercel' | 'railway' | 'cloudflare-workers';

export type FormValues = Record<string, string | string[]>;

type TextField = {
  type: 'text';
  name: string;
  label: string;
  placeholder: string;
  optional?: true;
  hint?: string;
  /** Asked only when the rest of the form makes it meaningful. */
  when?: (values: FormValues) => boolean;
};

type OptionsField = {
  type: 'options';
  name: string;
  label: string;
  options: { value: string; label: string }[];
  /** Several may be picked (checkboxes) or exactly one (a segmented control). */
  multiple: boolean;
  initial: string[];
  hint?: string;
};

export type DestinationField = TextField | OptionsField;

export type Destination = {
  kind: DestinationKind;
  label: string;
  fields: DestinationField[];
  /** Where the destination's token could live, as a `project/environment/KEY` example. */
  credentialExample: string;
  /** Which token to create, in a sentence. */
  token: string;
};

export const DESTINATIONS: Destination[] = [
  {
    kind: 'github-actions',
    label: 'GitHub Actions',
    fields: [
      { type: 'text', name: 'owner', label: 'Owner', placeholder: 'erwinkn' },
      { type: 'text', name: 'repo', label: 'Repository', placeholder: 'app' },
      {
        type: 'text',
        name: 'environment',
        label: 'Environment',
        placeholder: 'production',
        optional: true,
        hint: 'Leave empty to write repository secrets.',
      },
    ],
    credentialExample: 'ops/sync/GITHUB_TOKEN',
    token:
      'Use a fine-grained token for this one repository, with Secrets: Read and write, or Environments: Read and write for an environment’s secrets. A classic token needs the repo scope.',
  },
  {
    kind: 'vercel',
    label: 'Vercel',
    fields: [
      { type: 'text', name: 'projectId', label: 'Project ID', placeholder: 'prj_…' },
      {
        type: 'text',
        name: 'teamId',
        label: 'Team ID',
        placeholder: 'team_…',
        optional: true,
        hint: 'Needed when a team owns the project.',
      },
      {
        type: 'options',
        name: 'targets',
        label: 'Targets',
        options: [
          { value: 'production', label: 'Production' },
          { value: 'preview', label: 'Preview' },
          { value: 'development', label: 'Development' },
        ],
        multiple: true,
        initial: ['production'],
      },
      {
        type: 'text',
        name: 'gitBranch',
        label: 'Git branch',
        placeholder: 'staging',
        optional: true,
        hint: 'Limit these values to one branch’s previews.',
        when: (values) => sameSet(values.targets, ['preview']),
      },
    ],
    credentialExample: 'ops/sync/VERCEL_TOKEN',
    token: 'Use an access token scoped to the team that owns the project.',
  },
  {
    kind: 'railway',
    label: 'Railway',
    fields: [
      { type: 'text', name: 'projectId', label: 'Project ID', placeholder: 'UUID' },
      { type: 'text', name: 'environmentId', label: 'Environment ID', placeholder: 'UUID' },
      {
        type: 'text',
        name: 'serviceId',
        label: 'Service ID',
        placeholder: 'UUID',
        optional: true,
        hint: 'Leave empty to write shared variables.',
      },
      {
        type: 'options',
        name: 'tokenKind',
        label: 'Token',
        options: [
          { value: 'project', label: 'Project token' },
          { value: 'account', label: 'Account or workspace token' },
        ],
        multiple: false,
        initial: ['project'],
      },
    ],
    credentialExample: 'ops/sync/RAILWAY_TOKEN',
    token:
      'A project token for this one environment is the narrowest grant. Railway redeploys the service after every change.',
  },
  {
    kind: 'cloudflare-workers',
    label: 'Cloudflare Workers',
    fields: [
      { type: 'text', name: 'accountId', label: 'Account ID', placeholder: '32 hex characters' },
      { type: 'text', name: 'scriptName', label: 'Worker name', placeholder: 'api' },
    ],
    credentialExample: 'ops/sync/CLOUDFLARE_API_TOKEN',
    token: 'Use an API token with the Account › Workers Scripts › Edit permission. Each change deploys a new version of the Worker.',
  },
];

export function destination(kind: DestinationKind): Destination {
  return DESTINATIONS.find((entry) => entry.kind === kind) ?? DESTINATIONS[0]!;
}

export function initialValues(entry: Destination): FormValues {
  return Object.fromEntries(
    entry.fields.map((field) => [field.name, field.type === 'text' ? '' : field.initial]),
  );
}

export function isAsked(field: DestinationField, values: FormValues): boolean {
  return field.type === 'options' || field.when === undefined || field.when(values);
}

/** The label of the first required field left empty, or null when the form can be sent. */
export function firstMissing(entry: Destination, values: FormValues): string | null {
  for (const field of entry.fields) {
    if (!isAsked(field, values)) continue;
    const value = values[field.name];
    const empty = typeof value === 'string' ? value.trim() === '' : (value ?? []).length === 0;
    if (empty && (field.type === 'options' || field.optional !== true)) return field.label;
  }
  return null;
}

/**
 * The destination's config. Text is trimmed, and an optional field left empty
 * is left out rather than sent as "", which the server rightly refuses.
 */
export function destinationConfig(entry: Destination, values: FormValues): Record<string, unknown> {
  const config: Record<string, unknown> = {};
  for (const field of entry.fields) {
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

function sameSet(value: string | string[] | undefined, expected: string[]): boolean {
  const list = Array.isArray(value) ? value : [];
  return list.length === expected.length && expected.every((item) => list.includes(item));
}
