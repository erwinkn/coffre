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
      tampered: boolean;
      instanceRole: "owner" | "root-admin" | "user";
      isRootAdmin: boolean;
      canReadAudit: boolean;
      environments: {
        project: string;
        environment: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
      }[];
      instance: null | {
        version: string;
        migrations: {
          applied: number;
          known: string[];
        };
      };
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
        secretCount: number | null;
      }[];
      everyProject: {
        member: string;
        place: string;
        role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
        roleName: string;
        expiresAt: string | null;
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
      inherited: {
        member: string;
        place: string;
        role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
        roleName: string;
        expiresAt: string | null;
      }[];
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
  "DELETE /projects/:project": {
    input: undefined;
    output: {
      dryRun: boolean;
      deletion: {
        path: string;
        tombstone: string;
        environments: string[];
        keys: number;
        versions: number;
        grants: {
          member: string;
          place: string;
          role: string;
        }[];
        stranded: string[];
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
      inherited: {
        member: string;
        place: string;
        role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
        roleName: string;
        expiresAt: string | null;
      }[];
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
      inherited: {
        member: string;
        place: string;
        role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
        roleName: string;
        expiresAt: string | null;
      }[];
    };
  };
  "DELETE /projects/:project/:environment": {
    input: undefined;
    output: {
      dryRun: boolean;
      deletion: {
        path: string;
        tombstone: string;
        environments: string[];
        keys: number;
        versions: number;
        grants: {
          member: string;
          place: string;
          role: string;
        }[];
        stranded: string[];
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
      operationId: string;
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
      operationId: string;
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
        tampered: boolean;
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
      status: "active" | "removed" | "tampered";
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
        status: "active" | "removed" | "tampered";
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
  "GET /members/:member/bindings": {
    input: undefined;
    output: {
      bindings: {
        id: string;
        profile: "custom" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab";
        issuer: string;
        jwksUri: string;
        claims: {
          [key: string]: string;
        };
        label: string | null;
        createdAt: string;
        createdBy: string;
        lastUsedAt: string | null;
      }[];
    };
  };
  "POST /members/:member/bindings": {
    input: {
      profile: "custom" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab";
      claims: {
        [key: string]: string;
      };
      issuer?: string | null;
      label?: string | null;
      replaces?: string[];
    };
    output: {
      profile: "custom" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab";
      issuer: string;
      jwksUri: string;
      claims: {
        [key: string]: string;
      };
      replaces: {
        id: string;
        why: "asked" | "keys_moved";
      }[];
    } | {
      binding: {
        id: string;
        profile: "custom" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab";
        issuer: string;
        jwksUri: string;
        claims: {
          [key: string]: string;
        };
        label: string | null;
        createdAt: string;
        createdBy: string;
        lastUsedAt: string | null;
      };
      replaced: string[];
    };
  };
  "GET /workloads/lookup": {
    input: {
      github?: string;
      gitlab?: string;
      gitlabUrl?: string;
    };
    output: {
      github: string;
      repositoryId: string;
      ownerId: string;
    } | {
      gitlab: string;
      projectId: string;
      namespaceId: string;
    };
  };
  "DELETE /members/:member/bindings/:id": {
    input: undefined;
    output: {
      unbound: true;
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
  "GET /audit": {
    input: {
      path?: string;
      actor?: string;
      decision?: "allow" | "deny";
      detail?: "1" | "true";
      before?: unknown;
      limit?: unknown;
    };
    output: {
      entries: {
        seq: number;
        author: "app" | "vault";
        occurredAt: string;
        actorType: "service" | "system" | "user";
        actorId: string;
        action: string;
        decision: "allow" | "deny";
        reason: string | null;
        detail: boolean;
        subject: string | null;
        project: string | null;
        environment: string | null;
        key: string | null;
        version: number | null;
        operationId: string | null;
        relatedSeq: number | null;
        requestId: string | null;
        run: null | {
          exchangeSeq: number;
          claims: {
            [key: string]: string | number;
          };
        };
        metadata: {
          [key: string]: unknown;
        };
      }[];
      hidden?: {
        action: string;
        count: number;
      }[];
    };
  };
  "GET /audit/verification": {
    input: undefined;
    output: {
      ok: true;
      through: number | null;
      entries: number;
      checkpoint: null | {
        seq: number;
        signedAt: string;
      };
      pending?: number;
    } | {
      ok: false;
      through: number | null;
      failedAtSeq: number | null;
      author: "app" | "vault";
      reason: string;
    };
  };
  "GET /audit/keys": {
    input: undefined;
    output: {
      app: {
        keyId: string;
      };
      vault: {
        current: {
          vaultId: string;
          provider: string;
        };
        checks: {
          seq: number;
          vaultId: string;
          provider: string;
          version: string;
          wrapped: string;
        }[];
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
  author: "app" | "vault";
  occurredAt: string;
  actorType: "service" | "system" | "user";
  actorId: string;
  action: string;
  decision: "allow" | "deny";
  reason: string | null;
  detail: boolean;
  subject: string | null;
  project: string | null;
  environment: string | null;
  key: string | null;
  version: number | null;
  operationId: string | null;
  relatedSeq: number | null;
  requestId: string | null;
  run: null | {
    exchangeSeq: number;
    claims: {
      [key: string]: string | number;
    };
  };
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

export type BindingPlan = {
  profile: "custom" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab";
  issuer: string;
  jwksUri: string;
  claims: {
    [key: string]: string;
  };
  replaces: {
    id: string;
    why: "asked" | "keys_moved";
  }[];
};

export type BindingView = {
  id: string;
  profile: "custom" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab";
  issuer: string;
  jwksUri: string;
  claims: {
    [key: string]: string;
  };
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
};

export type Deletion = {
  path: string;
  tombstone: string;
  environments: string[];
  keys: number;
  versions: number;
  grants: {
    member: string;
    place: string;
    role: string;
  }[];
  stranded: string[];
};

export type DeletionResult = {
  dryRun: boolean;
  deletion: {
    path: string;
    tombstone: string;
    environments: string[];
    keys: number;
    versions: number;
    grants: {
      member: string;
      place: string;
      role: string;
    }[];
    stranded: string[];
  };
};

export type WorkloadIds = {
  github: string;
  repositoryId: string;
  ownerId: string;
} | {
  gitlab: string;
  projectId: string;
  namespaceId: string;
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

export type InheritedGrant = {
  member: string;
  place: string;
  role: "access-manager" | "auditor" | "developer" | "maintainer" | "owner" | "viewer";
  roleName: string;
  expiresAt: string | null;
};

export type InstanceState = {
  version: string;
  migrations: {
    applied: number;
    known: string[];
  };
};

export type Me = {
  principal: {
    type: "service" | "user";
    id: string;
  };
  registered: boolean;
  tampered: boolean;
  instanceRole: "owner" | "root-admin" | "user";
  isRootAdmin: boolean;
  canReadAudit: boolean;
  environments: {
    project: string;
    environment: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.write")[];
  }[];
  instance: null | {
    version: string;
    migrations: {
      applied: number;
      known: string[];
    };
  };
};

export type Member = {
  member: string;
  principalType: "service" | "user";
  principalId: string;
  instanceRole: "owner" | "root-admin" | "user";
  isRootAdmin: boolean;
  tampered: boolean;
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
  status: "active" | "removed" | "tampered";
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
  secretCount: number | null;
};

export type RemovedMember = {
  principalType: "service" | "user";
  principalId: string;
  toRotate: number;
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
  operationId: string;
  keys: {
    [key: string]: {
      version: number;
    } | {
      archived: true;
    };
  };
};
