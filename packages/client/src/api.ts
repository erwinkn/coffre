// Generated from the route table in packages/server/src/api/routes.ts by
// `pnpm --dir packages/client generate`. Do not edit: a test fails when it
// is out of date.

/** Every route, by `METHOD /path`: what a caller sends (the body, or the query of a GET) and gets back. */
export type Api = {
  "GET /me": {
    input: undefined;
    output: {
      principal: {
        type: "service" | "user";
        id: string;
      };
      registered: boolean;
      instanceRole: "owner" | "root-admin" | "user";
      isRootAdmin: boolean;
      canReadAudit: boolean;
      environments: {
        project: string;
        environment: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
      }[];
    };
  };
  "GET /projects": {
    input: undefined;
    output: {
      projects: {
        slug: string;
        name: string;
        archivedAt: string | null;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
        environments: {
          slug: string;
          name: string;
          accessible: boolean;
          details: null | {
            archivedAt: string | null;
            secretCount: number | null;
          };
        }[];
      }[];
    };
  };
  "PUT /projects/:project": {
    input: {
      name: string;
    };
    output: {
      project: {
        slug: string;
        name: string;
        archivedAt: string | null;
      };
      created: boolean;
    };
  };
  "PATCH /projects/:project": {
    input: {
      name?: string;
      slug?: string;
      archived?: boolean;
    };
    output: {
      project: {
        slug: string;
        name: string;
        archivedAt: string | null;
      };
    };
  };
  "PUT /projects/:project/:environment": {
    input: {
      name: string;
    };
    output: {
      environment: {
        slug: string;
        name: string;
        archivedAt: string | null;
      };
      created: boolean;
    };
  };
  "PATCH /projects/:project/:environment": {
    input: {
      name?: string;
      slug?: string;
      archived?: boolean;
    };
    output: {
      environment: {
        slug: string;
        name: string;
        archivedAt: string | null;
      };
    };
  };
  "GET /secrets/:project/:environment": {
    input: undefined;
    output: {
      permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
      keys: {
        key: string;
        archived: boolean;
        version: number | null;
        updatedAt: string | null;
        updatedBy: string | null;
      }[];
    };
  };
  "PATCH /secrets/:project/:environment": {
    input: {
      [key: string]: string | null;
    };
    output: {
      bundleId: string;
      keys: {
        [key: string]: {
          version: number;
        } | {
          archived: true;
        };
      };
    } | {
      dryRun: true;
      keys: {
        [key: string]: "added" | "archived" | "changed" | "unchanged";
      };
    };
  };
  "PATCH /secrets/:project/:environment/:key": {
    input: {
      key?: string;
      archived?: boolean;
    };
    output: {
      key: string;
      archived: boolean;
    };
  };
  "GET /secrets/:project/:environment/:key/versions": {
    input: undefined;
    output: {
      key: string;
      archived: boolean;
      versions: {
        version: number;
        createdAt: string;
        createdBy: string;
        current: boolean;
        kek: string;
      }[];
    };
  };
  "POST /secrets/:project/:environment/:key/restore": {
    input: {
      version: number;
    };
    output: {
      key: string;
      version: number;
    };
  };
  "POST /reveals": {
    input: {
      path: string;
    };
    output: {
      bundleId: string;
      values: {
        [key: string]: string;
      };
    };
  };
  "GET /members": {
    input: {
      path?: string;
    };
    output: {
      members: {
        member: string;
        principalType: "service" | "user";
        principalId: string;
        instanceRole: "owner" | "root-admin" | "user";
        isRootAdmin: boolean;
        grants: {
          id: string;
          project: string;
          environment: string | null;
          role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
          roleName: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
          expiresAt: string | null;
        }[];
      }[];
      removed: {
        principalType: "service" | "user";
        principalId: string;
        toRotate: number;
      }[];
    };
  };
  "GET /members/:member": {
    input: undefined;
    output: {
      principalType: "service" | "user";
      principalId: string;
      status: "active" | "removed";
      instanceRole: "owner" | "root-admin" | "user";
      isRootAdmin: boolean;
      removedAt: string | null;
      removedBy: string | null;
      live: {
        grants: number;
        sessions: number;
        tokens: number;
        identities: number;
      };
      exposed: {
        project: string;
        environment: string;
        key: string;
        version: number;
        how: "read" | "wrote";
        at: string;
      }[];
      rotated: number;
      issuedTokens: {
        id: string;
        service: string;
        label: string | null;
        hint: string;
        expiresAt: string;
        lastUsedAt: string | null;
      }[];
      syncs: {
        id: string;
        provider: string;
        providerLabel: string;
        brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
        offered: boolean;
        destination: string;
        config: {
          [key: string]: string | number | boolean | null | Json[] | {
            [key: string]: Json;
          };
        };
        credential: string;
        createdAt: string;
        createdBy: string;
        paused: boolean;
        running: boolean;
        lastRunAt: string | null;
        lastStatus: "failed" | "ok" | "partial" | null;
        lastError: string | null;
        synced: number;
        pending: number;
        skipped: {
          key: string;
          reason: string;
        }[];
        project: string;
        environment: string;
      }[];
    };
  };
  "PUT /members/:member": {
    input: {
      owner?: boolean;
    };
    output: {
      member: string;
      instanceRole: "owner" | "user";
      created: boolean;
    };
  };
  "DELETE /members/:member": {
    input: undefined;
    output: {
      revoked: {
        grants: number;
        sessions: number;
        tokens: number;
        identities: number;
      };
      report: {
        principalType: "service" | "user";
        principalId: string;
        status: "active" | "removed";
        instanceRole: "owner" | "root-admin" | "user";
        isRootAdmin: boolean;
        removedAt: string | null;
        removedBy: string | null;
        live: {
          grants: number;
          sessions: number;
          tokens: number;
          identities: number;
        };
        exposed: {
          project: string;
          environment: string;
          key: string;
          version: number;
          how: "read" | "wrote";
          at: string;
        }[];
        rotated: number;
        issuedTokens: {
          id: string;
          service: string;
          label: string | null;
          hint: string;
          expiresAt: string;
          lastUsedAt: string | null;
        }[];
        syncs: {
          id: string;
          provider: string;
          providerLabel: string;
          brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
          offered: boolean;
          destination: string;
          config: {
            [key: string]: string | number | boolean | null | Json[] | {
              [key: string]: Json;
            };
          };
          credential: string;
          createdAt: string;
          createdBy: string;
          paused: boolean;
          running: boolean;
          lastRunAt: string | null;
          lastStatus: "failed" | "ok" | "partial" | null;
          lastError: string | null;
          synced: number;
          pending: number;
          skipped: {
            key: string;
            reason: string;
          }[];
          project: string;
          environment: string;
        }[];
      };
    };
  };
  "GET /members/:member/tokens": {
    input: undefined;
    output: {
      tokens: {
        id: string;
        label: string | null;
        hint: string;
        createdAt: string;
        createdBy: string;
        expiresAt: string;
        lastUsedAt: string | null;
        lastUsedIp: string | null;
      }[];
    };
  };
  "POST /members/:member/tokens": {
    input: {
      expiresInDays: number;
      label?: string | null;
    };
    output: {
      id: string;
      token: string;
      expiresAt: string;
    };
  };
  "DELETE /members/:member/tokens/:id": {
    input: undefined;
    output: {
      revoked: true;
    };
  };
  "PATCH /access/:member": {
    input: {
      [key: string]: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer" | null | {
        role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
        until: string | null;
      };
    };
    output: {
      changes: {
        [key: string]: "created" | "revoked" | "unchanged" | "updated";
      };
    };
  };
  "GET /sessions": {
    input: undefined;
    output: {
      sessions: {
        id: string;
        kind: "browser" | "cli";
        label: string | null;
        hint: string;
        provider: string | null;
        createdAt: string;
        expiresAt: string;
        lastUsedAt: string | null;
        lastUsedIp: string | null;
        current: boolean;
      }[];
    };
  };
  "DELETE /sessions/:id": {
    input: undefined;
    output: {
      revoked: true;
    };
  };
  "GET /identities": {
    input: undefined;
    output: {
      identities: {
        id: string;
        provider: string;
        email: string | null;
        createdAt: string;
        lastSignInAt: string | null;
      }[];
    };
  };
  "DELETE /identities/:id": {
    input: undefined;
    output: {
      unlinked: true;
    };
  };
  "GET /device-logins/:code": {
    input: undefined;
    output: {
      request: null | {
        userCode: string;
        clientLabel: string | null;
        clientIp: string | null;
        createdAt: string;
        expiresAt: string;
      };
      sessionDays: number;
    };
  };
  "POST /device-logins/:code": {
    input: {
      approve: boolean;
    };
    output: {
      decided: true;
    };
  };
  "GET /syncs/providers": {
    input: undefined;
    output: {
      providers: {
        brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
        id: string;
        credential: {
          placeholder: string;
          hint: string;
        };
        label: string;
        fields: ({
          type: "text";
          name: string;
          label: string;
          placeholder: string;
          optional?: boolean;
          hint?: string;
          when?: {
            field: string;
            is: string[];
          };
        } | {
          type: "options";
          name: string;
          label: string;
          options: {
            value: string;
            label: string;
          }[];
          multiple: boolean;
          initial: string[];
          hint?: string;
        })[];
      }[];
    };
  };
  "GET /syncs/:project/:environment": {
    input: undefined;
    output: {
      syncs: {
        id: string;
        provider: string;
        providerLabel: string;
        brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
        offered: boolean;
        destination: string;
        config: {
          [key: string]: string | number | boolean | null | Json[] | {
            [key: string]: Json;
          };
        };
        credential: string;
        createdAt: string;
        createdBy: string;
        paused: boolean;
        running: boolean;
        lastRunAt: string | null;
        lastStatus: "failed" | "ok" | "partial" | null;
        lastError: string | null;
        synced: number;
        pending: number;
        skipped: {
          key: string;
          reason: string;
        }[];
      }[];
      canManage: boolean;
    };
  };
  "POST /syncs/:project/:environment": {
    input: {
      provider: string;
      config: {
        [key: string]: unknown;
      };
      credential: string;
    };
    output: {
      id: string;
      provider: string;
      providerLabel: string;
      brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
      offered: boolean;
      destination: string;
      config: {
        [key: string]: string | number | boolean | null | Json[] | {
          [key: string]: Json;
        };
      };
      credential: string;
      createdAt: string;
      createdBy: string;
      paused: boolean;
      running: boolean;
      lastRunAt: string | null;
      lastStatus: "failed" | "ok" | "partial" | null;
      lastError: string | null;
      synced: number;
      pending: number;
      skipped: {
        key: string;
        reason: string;
      }[];
    };
  };
  "PATCH /syncs/by-id/:id": {
    input: {
      paused: boolean;
    };
    output: {
      id: string;
      provider: string;
      providerLabel: string;
      brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
      offered: boolean;
      destination: string;
      config: {
        [key: string]: string | number | boolean | null | Json[] | {
          [key: string]: Json;
        };
      };
      credential: string;
      createdAt: string;
      createdBy: string;
      paused: boolean;
      running: boolean;
      lastRunAt: string | null;
      lastStatus: "failed" | "ok" | "partial" | null;
      lastError: string | null;
      synced: number;
      pending: number;
      skipped: {
        key: string;
        reason: string;
      }[];
    };
  };
  "DELETE /syncs/by-id/:id": {
    input: undefined;
    output: {
      id: string;
      provider: string;
      providerLabel: string;
      brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
      offered: boolean;
      destination: string;
      config: {
        [key: string]: string | number | boolean | null | Json[] | {
          [key: string]: Json;
        };
      };
      credential: string;
      createdAt: string;
      createdBy: string;
      paused: boolean;
      running: boolean;
      lastRunAt: string | null;
      lastStatus: "failed" | "ok" | "partial" | null;
      lastError: string | null;
      synced: number;
      pending: number;
      skipped: {
        key: string;
        reason: string;
      }[];
    };
  };
  "POST /syncs/by-id/:id/runs": {
    input: undefined;
    output: {
      sync: {
        id: string;
        provider: string;
        providerLabel: string;
        brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
        offered: boolean;
        destination: string;
        config: {
          [key: string]: string | number | boolean | null | Json[] | {
            [key: string]: Json;
          };
        };
        credential: string;
        createdAt: string;
        createdBy: string;
        paused: boolean;
        running: boolean;
        lastRunAt: string | null;
        lastStatus: "failed" | "ok" | "partial" | null;
        lastError: string | null;
        synced: number;
        pending: number;
        skipped: {
          key: string;
          reason: string;
        }[];
      };
      outcome: {
        status: "busy";
      } | {
        status: "failed" | "ok" | "partial";
        upserted: string[];
        deleted: string[];
        failed: {
          key: string;
          operation: "delete" | "upsert";
          message: string;
        }[];
        error: string | null;
      };
    };
  };
  "GET /audit": {
    input: {
      path?: string;
      actor?: string;
      decision?: "allow" | "deny";
      exclude?: "sign-ins";
      before?: unknown;
      limit?: unknown;
    };
    output: {
      entries: {
        seq: number;
        occurredAt: string;
        actorType: string;
        actorId: string;
        action: string;
        decision: "allow" | "deny";
        project: string | null;
        environment: string | null;
        bundleId: string | null;
        requestId: string | null;
        metadata: {
          [key: string]: unknown;
        };
      }[];
    };
  };
  "GET /audit/verification": {
    input: undefined;
    output: {
      ok: true;
      rows: number;
      head: string;
      checkpoint: null | {
        seq: number;
        signedAt: string;
      };
      vault: {
        entries: number;
        pending?: number;
      };
    } | {
      ok: false;
      log: "audit" | "vault";
      failedAtSeq: number | null;
      reason: string;
    };
  };
  "GET /audit/vault": {
    input: {
      before?: unknown;
      limit?: unknown;
      full?: "1" | "true";
    };
    output: {
      entries: {
        seq: number;
        at: string;
        actor: string;
        action: string;
        outcome: "allow" | "refuse";
        code: string | null;
        subject: string | null;
        detail: {
          [key: string]: unknown;
        };
        hash: string;
      }[];
      verification: {
        ok: true;
        entries: number;
        pending?: number;
      } | {
        ok: false;
        failedAtSeq: number | null;
        reason: string;
      };
    };
  };
};

export type AccessValue = "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer" | null | {
  role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
  until: string | null;
};

export type AuditEntryView = {
  seq: number;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  decision: "allow" | "deny";
  project: string | null;
  environment: string | null;
  bundleId: string | null;
  requestId: string | null;
  metadata: {
    [key: string]: unknown;
  };
};

export type AuthInfo = {
  signin: null | {
    title: string;
    note: string | null;
    providers: {
      id: string;
      label: string;
      brand: "github" | "google" | "microsoft" | "oidc";
    }[];
  };
  access: null | {
    assertion: boolean;
  };
};

export type DryRunOutcome = "added" | "archived" | "changed" | "unchanged";

export type DryRunResult = {
  dryRun: true;
  keys: {
    [key: string]: "added" | "archived" | "changed" | "unchanged";
  };
};

export type IdentityRow = {
  id: string;
  provider: string;
  email: string | null;
  createdAt: string;
  lastSignInAt: string | null;
};

export type Me = {
  principal: {
    type: "service" | "user";
    id: string;
  };
  registered: boolean;
  instanceRole: "owner" | "root-admin" | "user";
  isRootAdmin: boolean;
  canReadAudit: boolean;
  environments: {
    project: string;
    environment: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
  }[];
};

export type Member = {
  member: string;
  principalType: "service" | "user";
  principalId: string;
  instanceRole: "owner" | "root-admin" | "user";
  isRootAdmin: boolean;
  grants: {
    id: string;
    project: string;
    environment: string | null;
    role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
    roleName: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
    expiresAt: string | null;
  }[];
};

export type OffboardingReport = {
  principalType: "service" | "user";
  principalId: string;
  status: "active" | "removed";
  instanceRole: "owner" | "root-admin" | "user";
  isRootAdmin: boolean;
  removedAt: string | null;
  removedBy: string | null;
  live: {
    grants: number;
    sessions: number;
    tokens: number;
    identities: number;
  };
  exposed: {
    project: string;
    environment: string;
    key: string;
    version: number;
    how: "read" | "wrote";
    at: string;
  }[];
  rotated: number;
  issuedTokens: {
    id: string;
    service: string;
    label: string | null;
    hint: string;
    expiresAt: string;
    lastUsedAt: string | null;
  }[];
  syncs: {
    id: string;
    provider: string;
    providerLabel: string;
    brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
    offered: boolean;
    destination: string;
    config: {
      [key: string]: string | number | boolean | null | Json[] | {
        [key: string]: Json;
      };
    };
    credential: string;
    createdAt: string;
    createdBy: string;
    paused: boolean;
    running: boolean;
    lastRunAt: string | null;
    lastStatus: "failed" | "ok" | "partial" | null;
    lastError: string | null;
    synced: number;
    pending: number;
    skipped: {
      key: string;
      reason: string;
    }[];
    project: string;
    environment: string;
  }[];
};

export type ProjectSummary = {
  slug: string;
  name: string;
  archivedAt: string | null;
  permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
  environments: {
    slug: string;
    name: string;
    accessible: boolean;
    details: null | {
      archivedAt: string | null;
      secretCount: number | null;
    };
  }[];
};

export type RemovedMember = {
  principalType: "service" | "user";
  principalId: string;
  toRotate: number;
};

export type RunOutcome = {
  status: "busy";
} | {
  status: "failed" | "ok" | "partial";
  upserted: string[];
  deleted: string[];
  failed: {
    key: string;
    operation: "delete" | "upsert";
    message: string;
  }[];
  error: string | null;
};

export type SecretKey = {
  key: string;
  archived: boolean;
  version: number | null;
  updatedAt: string | null;
  updatedBy: string | null;
};

export type SecretVersion = {
  version: number;
  createdAt: string;
  createdBy: string;
  current: boolean;
  kek: string;
};

export type ServiceTokenRow = {
  id: string;
  label: string | null;
  hint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
};

export type SessionRow = {
  id: string;
  kind: "browser" | "cli";
  label: string | null;
  hint: string;
  provider: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  current: boolean;
};

export type SetResult = {
  bundleId: string;
  keys: {
    [key: string]: {
      version: number;
    } | {
      archived: true;
    };
  };
};

export type SyncField = {
  type: "text";
  name: string;
  label: string;
  placeholder: string;
  optional?: boolean;
  hint?: string;
  when?: {
    field: string;
    is: string[];
  };
} | {
  type: "options";
  name: string;
  label: string;
  options: {
    value: string;
    label: string;
  }[];
  multiple: boolean;
  initial: string[];
  hint?: string;
};

export type SyncProviderInfo = {
  brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
  id: string;
  credential: {
    placeholder: string;
    hint: string;
  };
  label: string;
  fields: ({
    type: "text";
    name: string;
    label: string;
    placeholder: string;
    optional?: boolean;
    hint?: string;
    when?: {
      field: string;
      is: string[];
    };
  } | {
    type: "options";
    name: string;
    label: string;
    options: {
      value: string;
      label: string;
    }[];
    multiple: boolean;
    initial: string[];
    hint?: string;
  })[];
};

export type SyncView = {
  id: string;
  provider: string;
  providerLabel: string;
  brand: "cloudflare" | "github" | "other" | "railway" | "vercel";
  offered: boolean;
  destination: string;
  config: {
    [key: string]: string | number | boolean | null | Json[] | {
      [key: string]: Json;
    };
  };
  credential: string;
  createdAt: string;
  createdBy: string;
  paused: boolean;
  running: boolean;
  lastRunAt: string | null;
  lastStatus: "failed" | "ok" | "partial" | null;
  lastError: string | null;
  synced: number;
  pending: number;
  skipped: {
    key: string;
    reason: string;
  }[];
};

export type Json = string | number | boolean | null | Json[] | {
  [key: string]: Json;
};
