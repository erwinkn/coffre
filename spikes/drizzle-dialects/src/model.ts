export type AuditMetadata = Record<string, unknown>;

export type NewProject = {
  id: string;
  slug: string;
  name: string;
  createdAt: Date;
};

export type AuditHead = {
  nextSeq: number;
  headHash: Buffer;
};

export type AuditInput = {
  id: string;
  actorId: string;
  action: string;
  metadata: AuditMetadata;
};
