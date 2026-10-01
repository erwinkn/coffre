/**
 * Why the vault's members and grants do not follow from its log, as facts
 * rather than a sentence. The vault knows only ids; the app knows what the
 * people and places are called, so it words the same fault with names.
 */
export type AccessFault =
  /** An entry changes someone the log never admitted. */
  | { kind: 'unadmitted-change'; seq: number; principal: string }
  /** The store has a member the log never admitted. */
  | { kind: 'unlogged-member'; principal: string }
  /** The log admits someone the store does not have. */
  | { kind: 'missing-member'; principal: string }
  /** The store's row for someone differs from the log's in these fields. */
  | { kind: 'member-differs'; principal: string; fields: string[] }
  /** The store holds a grant the log never gave. */
  | { kind: 'unlogged-grant'; grant: FaultGrant }
  /** The log gives a grant the store does not hold. */
  | { kind: 'missing-grant'; grant: FaultGrant };

export type FaultGrant = { principal: string; projectId: string; environmentId: string | null; role: string };

/** How to name a principal (`user:ada@…`) and a place; ids by default. */
export type FaultNames = {
  principal?: (principal: string) => string;
  place?: (projectId: string, environmentId: string | null) => string;
};

/** The fault in a sentence, with whatever names the caller can give. */
export function describeAccessFault(fault: AccessFault, names: FaultNames = {}): string {
  const who = names.principal ?? ((principal: string) => principal);
  const where =
    names.place ??
    ((projectId: string, environmentId: string | null) =>
      environmentId === null ? projectId : `${projectId}/${environmentId}`);
  const grant = ({ principal, projectId, environmentId, role }: FaultGrant) =>
    `${who(principal)} as ${role} on ${where(projectId, environmentId)}`;
  switch (fault.kind) {
    case 'unadmitted-change':
      return `entry ${fault.seq} changes ${who(fault.principal)}, whom the log never admitted`;
    case 'unlogged-member':
      return `the store has ${who(fault.principal)} as a member, whom the log never admitted`;
    case 'missing-member':
      return `the log admits ${who(fault.principal)}, whom the store does not have`;
    case 'member-differs':
      return `the store's ${who(fault.principal)} differs from the log's in ${fault.fields.join(', ')}`;
    case 'unlogged-grant':
      return `the store holds a grant the log never gave: ${grant(fault.grant)}`;
    case 'missing-grant':
      return `the log gives a grant the store does not hold: ${grant(fault.grant)}`;
  }
}
