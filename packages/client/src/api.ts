// Generated from the route table in packages/server/src/api/routes.ts by
// `pnpm --filter @coffre/client generate`. Do not edit: a test fails when it
// is out of date.

/** Every route, by `METHOD /path`: what a caller sends (the body, or the query of a GET) and gets back. */
export type Api = {
  "POST /reveals": {
    input: {
      path: string;
      keys?: string[];
    };
    output: {
      operationId: string | null;
      values: {
        [key: string]: string;
      };
      sensitive: string[];
      useOnly: string[];
      version: string | null;
    };
  };
  "PATCH /secrets/:project/:environment": {
    input: {
      [key: string]: string | null | {
        value: string;
        generated: {
          recipe: string;
          pair?: {
            private: string;
            public: string;
          };
        };
        replaces?: string;
        sensitivity?: "secret" | "sensitive";
      } | {
        value: string;
        sensitivity: "plain" | "secret" | "sensitive";
        replaces?: string;
      } | {
        ref: string;
      };
    };
    output: {
      operationId: string | null;
      keys: {
        [key: string]: {
          version: number;
          sensitivity: "plain" | "secret" | "sensitive";
        } | {
          archived: true;
        } | {
          reference: string;
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
      folder?: string | null;
      inherit?: boolean;
    };
    output: {
      inherit?: boolean;
      folder?: string | null;
      archived?: boolean;
      operationId: string | null;
      key: string;
    };
  };
  "POST /secrets/:project/:environment/:key/restore": {
    input: {
      version: number;
    };
    output: {
      operationId: string | null;
      key: string;
      version: number;
      sensitivity: "plain" | "secret" | "sensitive";
    };
  };
  "PATCH /folders/:project/:environment/:folder": {
    input: {
      name: string;
    };
    output: {
      operationId: string | null;
      folder: string;
      moved: string[];
    };
  };
  "DELETE /folders/:project/:environment/:folder": {
    input: undefined;
    output: {
      operationId: string | null;
      folder: null;
      moved: string[];
    };
  };
  "PATCH /projects/:project/:environment/dismissals": {
    input: {
      [key: string]: null | true;
    };
    output: {
      operationId: string | null;
      keys: {
        [key: string]: "dismissed" | "restored" | "unchanged";
      };
    };
  };
  "DELETE /secrets/:project/:environment/:key/reference": {
    input: undefined;
    output: {
      operationId: string | null;
      reference: {
        holder: string;
        source: string;
        state: "broken";
      };
    };
  };
  "GET /secrets/:project/:environment": {
    input: undefined;
    output: {
      permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
      keys: {
        key: string;
        reference: null | {
          id: string;
          holder: string;
          source: string;
          state: "broken" | "live" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
          version: number | null;
          createdBy: null;
          createdAt: null;
          endedBy: null;
          endedAt: null;
          sourceId: string;
          canOpenSource: boolean;
        };
        folder: string | null;
        archived: boolean;
        version: number | null;
        versionId: string | null;
        updatedAt: string | null;
        updatedBy: string | null;
        generated: null | {
          recipe: string;
          pair?: {
            private: string;
            public: string;
          };
        };
        value: string | null;
        sensitivity: "plain" | "secret" | "sensitive" | null;
        readable: boolean;
        parent: null | {
          from: string;
          state: "inherited" | "overridden" | "removed";
          changed: boolean;
          reset: boolean;
          held: boolean;
        };
      }[];
      parents: string[];
      personal: null | {
        of: string;
        fallback: boolean;
      };
      protected: boolean;
      unprotectable: boolean;
      loosenable: boolean;
      rotateAfterDays: number | null;
    };
  };
  "GET /secrets/:project/:environment/:key/versions": {
    input: {
      before?: string;
    };
    output: {
      key: string;
      archived: boolean;
      versions: {
        version: number;
        createdAt: string;
        createdBy: string;
        current: boolean;
        kek: string;
        recipe: string | null;
        plain: boolean;
        sensitivity: "plain" | "secret" | "sensitive";
      }[];
      more: boolean;
    };
  };
  "GET /references": {
    input: {
      path: string;
    };
    output: {
      references: {
        readers: null | string[];
        canBreak: boolean;
        holderArchived: boolean;
        id: string;
        holder: string;
        source: string;
        state: "broken" | "live" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
        version: number | null;
        createdBy: null;
        createdAt: null;
        endedBy: null;
        endedAt: null;
      }[];
    };
  };
  "GET /projects/:project/:environment/missing": {
    input: undefined;
    output: {
      missing: {
        key: string;
        in: string[];
        folder: string | null;
      }[];
      dismissed: {
        dismissedBy: string;
        dismissedAt: string;
        key: string;
        in: string[];
        folder: string | null;
      }[];
    };
  };
  "GET /projects/:project/:environment/version": {
    input: undefined;
    output: {
      version: string;
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
        scope: null | {
          [key: string]: string;
        };
        session?: {
          bindingId: string | null;
        };
      }[];
    };
  };
  "POST /members/:member/tokens": {
    input: {
      label?: string | null;
      expiresInDays?: number;
      expiresInMinutes?: number;
      scope?: {
        [key: string]: string;
      };
    };
    output: {
      id: string;
      token: string;
      expiresAt: string;
      scope: {
        [key: string]: string;
      };
    };
  };
  "DELETE /members/:member/tokens/:id": {
    input: undefined;
    output: {
      revoked: true;
    };
  };
  "POST /handles": {
    input: {
      label: string;
      paths: string[];
      expiresInMinutes?: number;
    };
    output: {
      id: string;
      token: string;
      expiresAt: string;
      scope: {
        [key: string]: string;
      };
    };
  };
  "DELETE /handles/:id": {
    input: undefined;
    output: {
      revoked: true;
    };
  };
  "DELETE /sessions/:id": {
    input: undefined;
    output: {
      revoked: true;
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
        instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
        scope: null | {
          projects: "all" | {
            only: string[];
          } | {
            except: string[];
          };
          environments: "all" | {
            only: string[];
          } | {
            except: string[];
          };
        };
        reachesByRole: boolean;
        managed: boolean;
        tampered: boolean;
        declared: boolean;
        grants: {
          id: string;
          project: string;
          environment: string | null;
          role: string;
          roleName: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
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
      instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
      scope: {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
      declared: boolean;
      removedAt: string | null;
      removedBy: string | null;
      live: {
        grants: number;
        sessions: number;
        tokens: number;
        identities: number;
        apps: number;
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
      issuedTokens: null | {
        id: string;
        service: string;
        label: string | null;
        hint: string;
        expiresAt: string;
        lastUsedAt: string | null;
        scope: null | {
          [key: string]: string;
        };
      }[];
      apps: null | {
        id: string;
        name: string;
        host: string | null;
        registration: "cimd" | "dcr";
        scopes: ("manage-access" | "read" | "reveal" | "write")[];
        createdAt: string;
        lastUsedAt: string | null;
        lastUsedIp: string | null;
        expiresAt: string;
      }[];
      personalTokens: null | {
        id: string;
        label: string | null;
        hint: string;
        createdAt: string;
        createdBy: string;
        expiresAt: string;
        lastUsedAt: string | null;
        lastUsedIp: string | null;
        scope: null | {
          [key: string]: string;
        };
        session?: {
          bindingId: string | null;
        };
      }[];
      references: null | {
        version: number | null;
        source: string;
        id: string;
        holder: string;
        state: "broken" | "live" | "replaced" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
        createdBy: string;
        createdAt: string;
        endedBy: string | null;
        endedAt: string | null;
      }[];
      personal: {
        project: string;
        of: string;
        slug: string;
      }[];
    };
  };
  "GET /members/:member/access": {
    input: undefined;
    output: {
      member: string;
      principalType: "service" | "user";
      principalId: string;
      status: "active" | "removed" | "tampered";
      instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
      scope: null | {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
      managed: boolean;
      grants: {
        id: string;
        project: string;
        environment: string | null;
        role: string;
        roleName: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        expiresAt: string | null;
      }[];
    };
  };
  "PUT /members/:member": {
    input: {
      role?: "admin" | "auditor" | "developer" | "member" | "owner";
      scope?: {
        projects?: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments?: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
      access?: {
        [key: string]: string | null | {
          role: string;
          until: string | null;
        };
      };
    };
    output: {
      member: string;
      instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
      scope: {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
      created: boolean;
      changes?: {
        [key: string]: "created" | "revoked" | "unchanged" | "updated";
      };
    };
  };
  "DELETE /members/:member": {
    input: undefined;
    output: {
      revoked: {
        grants: number;
        sessions: number | null;
        tokens: number | null;
        identities: number | null;
        apps: number | null;
      };
      report: null | {
        principalType: "service" | "user";
        principalId: string;
        status: "active" | "removed" | "tampered";
        instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
        scope: {
          projects: "all" | {
            only: string[];
          } | {
            except: string[];
          };
          environments: "all" | {
            only: string[];
          } | {
            except: string[];
          };
        };
        declared: boolean;
        removedAt: string | null;
        removedBy: string | null;
        live: {
          grants: number;
          sessions: number;
          tokens: number;
          identities: number;
          apps: number;
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
        issuedTokens: null | {
          id: string;
          service: string;
          label: string | null;
          hint: string;
          expiresAt: string;
          lastUsedAt: string | null;
          scope: null | {
            [key: string]: string;
          };
        }[];
        apps: null | {
          id: string;
          name: string;
          host: string | null;
          registration: "cimd" | "dcr";
          scopes: ("manage-access" | "read" | "reveal" | "write")[];
          createdAt: string;
          lastUsedAt: string | null;
          lastUsedIp: string | null;
          expiresAt: string;
        }[];
        personalTokens: null | {
          id: string;
          label: string | null;
          hint: string;
          createdAt: string;
          createdBy: string;
          expiresAt: string;
          lastUsedAt: string | null;
          lastUsedIp: string | null;
          scope: null | {
            [key: string]: string;
          };
          session?: {
            bindingId: string | null;
          };
        }[];
        references: null | {
          version: number | null;
          source: string;
          id: string;
          holder: string;
          state: "broken" | "live" | "replaced" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
          createdBy: string;
          createdAt: string;
          endedBy: string | null;
          endedAt: string | null;
        }[];
        personal: {
          project: string;
          of: string;
          slug: string;
        }[];
      };
    };
  };
  "PATCH /access/:member": {
    input: {
      [key: string]: string | null | {
        role: string;
        until: string | null;
      };
    };
    output: {
      changes: {
        [key: string]: "created" | "revoked" | "unchanged" | "updated";
      };
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
        secrets: null | {
          key: string | null;
          version: number | null;
        }[];
        operationId: string | null;
        relatedSeq: number | null;
        requestId: string | null;
        run: null | {
          exchangeSeq: number;
          claims: {
            [key: string]: string | number;
          };
        };
        token: null | {
          id: string;
          label: string;
        };
        metadata: {
          [key: string]: unknown;
        };
        proof: "failed" | "proven" | "unproven";
      }[];
      more: boolean;
      next: number | null;
      hidden?: {
        action: string;
        count: number;
      }[];
      head: null | {
        size: number;
        signedAt: string;
      };
      holes: null | {
        above: number | null;
        below: number | null;
        kept: number;
        aging: number;
      }[];
    };
  };
  "GET /members/:member/bindings": {
    input: undefined;
    output: {
      bindings: {
        id: string;
        profile: "aws" | "azure" | "cloudflare" | "custom" | "enrollment" | "fly" | "gcp" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab" | "kubernetes" | "vercel";
        issuer: string;
        jwksUri: string;
        keys: null | {
          kid: string | null;
          alg: "ES256" | "RS256";
          thumbprint: string;
        }[];
        claims: {
          [key: string]: string | string[];
        };
        scope: null | {
          [key: string]: string;
        };
        policy: null | {
          sources?: string[];
          audience?: string;
          keyAudience?: true;
          sessionHours?: number;
          replicas?: number;
          sessionDays?: number;
          overlapMinutes?: number;
          mintedBy?: string;
          approve?: true;
          onContention?: "alert";
          unsignedUploads?: true;
          reads?: {
            [key: string]: "*" | string[];
          };
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
      profile: string;
      claims: {
        [key: string]: unknown;
      };
      issuer?: string | null;
      scope?: {
        [key: string]: string;
      };
      label?: string | null;
      replaces?: string[];
      jwks?: {
        [key: string]: unknown;
        keys: {
          [key: string]: unknown;
        }[];
      };
      policy?: {
        [key: string]: unknown;
      };
    };
    output: {
      binding: {
        id: string;
        scope: {
          [key: string]: string;
        };
      };
      replaced: string[];
    };
  };
  "POST /members/:member/bindings/keys": {
    input: {
      issuer: string;
      jwks: {
        [key: string]: unknown;
        keys: {
          [key: string]: unknown;
        }[];
      };
    };
    output: {
      bindings: {
        id: string;
        scope: {
          [key: string]: string;
        };
      }[];
      replaced: string[];
    };
  };
  "DELETE /members/:member/bindings/:id": {
    input: undefined;
    output: {
      unbound: true;
    };
  };
  "GET /freezes": {
    input: undefined;
    output: {
      freezes: {
        target: string;
        service: string | null;
        frozenAt: string;
      }[];
    };
  };
  "POST /freezes": {
    input: {
      target: string;
      reason: string;
    };
    output: {
      target: string;
      frozenAt: string | null;
    };
  };
  "DELETE /freezes/:target": {
    input: undefined;
    output: {
      target: string;
      frozenAt: string | null;
    };
  };
  "GET /me": {
    input: undefined;
    output: {
      principal: {
        type: "service" | "user";
        id: string;
      };
      registered: boolean;
      tampered: boolean;
      instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
      scope: {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
      runsInstance: boolean;
      canReadAudit: boolean;
      setsUpServices: boolean;
      serviceSetup: null | {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
      features: {
        mcp: string | null;
        workloads: boolean;
      };
      personalToken: null | {
        id: string;
        label: string;
        expiresAt: string;
        scope: {
          [key: string]: string;
        };
      };
      credentialExpiresAt: string | null;
      environments: {
        project: string;
        environment: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
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
        folder: string | null;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        environments: {
          slug: string;
          name: string;
          accessible: boolean;
          parent: string | null;
          protected: boolean;
          unprotectable: boolean;
          personal: boolean;
          details: null | {
            archivedAt: string | null;
            secretCount: number | null;
          };
        }[];
        secretCount: number | null;
      }[];
    };
  };
  "PUT /projects/:project": {
    input: {
      name?: string;
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
      folder?: string | null;
    };
    output: {
      project: {
        slug: string;
        name: string;
        archivedAt: string | null;
        folder: string | null;
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
        references: {
          holder: string;
          source: string;
        }[];
        stranded: string[];
      };
    };
  };
  "PUT /projects/:project/:environment": {
    input: {
      name?: string;
      from?: string;
      references?: boolean;
      inherit?: boolean;
    };
    output: {
      environment: {
        slug: string;
        name: string;
        archivedAt: string | null;
        protected: boolean;
      };
      created: boolean;
      forked: null | {
        keys: number;
        references: number;
        copied: string[];
        from: string;
        inherits: boolean;
      };
    };
  };
  "PATCH /projects/:project/:environment": {
    input: {
      name?: string;
      slug?: string;
      archived?: boolean;
      protected?: boolean;
    };
    output: {
      environment: {
        slug: string;
        name: string;
        archivedAt: string | null;
        protected: boolean;
      };
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
        references: {
          holder: string;
          source: string;
        }[];
        stranded: string[];
      };
    };
  };
  "PATCH /folders/:folder": {
    input: {
      name: string;
    };
    output: {
      folder: string;
      moved: string[];
    };
  };
  "DELETE /folders/:folder": {
    input: undefined;
    output: {
      folder: null;
      moved: string[];
    };
  };
  "GET /workloads/lookup": {
    input: undefined;
    output: never;
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
      more: boolean;
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
      more: boolean;
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
  "GET /oauth/authorizations": {
    input: {
      client_id?: string;
      redirect_uri?: string;
      response_type?: string;
      code_challenge?: string;
      code_challenge_method?: string;
      state?: string;
      scope?: string;
      resource?: string;
    };
    output: {
      status: "invalid";
      message: string;
    } | {
      status: "refused";
      message: string;
      redirect: string;
    } | {
      status: "ready";
      client: {
        id: string;
        name: string;
        host: string | null;
        registration: "cimd" | "dcr";
      };
      redirectHost: string;
      loopbackOnly: boolean;
      scopes: ("manage-access" | "read" | "reveal" | "write")[];
      connections: ("manage-access" | "read" | "reveal" | "write")[][];
      days: number;
    };
  };
  "POST /oauth/authorizations": {
    input: {
      request: {
        client_id?: string;
        redirect_uri?: string;
        response_type?: string;
        code_challenge?: string;
        code_challenge_method?: string;
        state?: string;
        scope?: string;
        resource?: string;
      };
      approve: boolean;
      scopes?: string[];
    };
    output: {
      redirect: string;
    };
  };
  "GET /apps": {
    input: undefined;
    output: {
      apps: {
        id: string;
        name: string;
        host: string | null;
        registration: "cimd" | "dcr";
        scopes: ("manage-access" | "read" | "reveal" | "write")[];
        createdAt: string;
        lastUsedAt: string | null;
        lastUsedIp: string | null;
        expiresAt: string;
      }[];
    };
  };
  "DELETE /apps/:id": {
    input: undefined;
    output: {
      disconnected: true;
    };
  };
  "GET /audit/keys": {
    input: undefined;
    output: never;
  };
  "GET /approvals/:id": {
    input: undefined;
    output: {
      approval: {
        id: string;
        status: "approved" | "cancelled" | "denied" | "expired" | "failed" | "pending";
        client: {
          name: string;
          host: string | null;
          registration: "cimd" | "dcr";
        };
        tool: string;
        summary: string;
        details: {
          label: string;
          value: string;
          kind?: "mono" | "time";
          note?: string;
          warn?: true;
        }[];
        asks: null | {
          value: {
            label: string;
            note: string;
          };
        };
        kind: "change" | "reveal";
        reveals: boolean;
        digest: string;
        basis: string | null;
        ready: boolean;
        createdAt: string;
        expiresAt: string;
        outcome: null | {
          text: string;
          result?: {
            [key: string]: unknown;
          };
          error?: string;
        };
      };
    };
  };
  "POST /approvals/:id": {
    input: {
      approve: boolean;
      digest: string;
      basis?: string | null;
      value?: string;
    };
    output: {
      status: "approved" | "cancelled" | "denied" | "expired" | "failed" | "pending";
      outcome: {
        text: string;
        result?: {
          [key: string]: unknown;
        };
        error?: string;
      };
      shown: {
        label: string;
        value: string;
        kind?: "mono" | "time";
        note?: string;
        warn?: true;
      }[];
    };
  };
  "PUT /settings": {
    input: {
      serviceAccounts: {
        projects?: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments?: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
    };
    output: {
      serviceAccounts: {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
    };
  };
  "GET /settings": {
    input: undefined;
    output: {
      serviceAccounts: {
        projects: "all" | {
          only: string[];
        } | {
          except: string[];
        };
        environments: "all" | {
          only: string[];
        } | {
          except: string[];
        };
      };
    };
  };
  "GET /workloads/repositories": {
    input: undefined;
    output: never;
  };
  "GET /personal/:project": {
    input: undefined;
    output: {
      configs: {
        of: string;
        owner: string;
        slug: string;
        keys: string[];
        archived: boolean;
        createdAt: string;
      }[];
    };
  };
  "GET /roles": {
    input: undefined;
    output: {
      roles: {
        name: string;
        description: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        id: string;
        builtin: boolean;
        edited: boolean;
        fixed: boolean;
        default: null | {
          name: string;
          description: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
          protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        };
        assignableToEnvironment: boolean;
        grants: number;
      }[];
      instanceRoles: {
        name: string;
        description: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        id: string;
        builtin: boolean;
        edited: boolean;
        fixed: boolean;
        default: null | {
          name: string;
          description: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
          protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        };
        assignableToEnvironment: boolean;
        grants: number;
      }[];
      editable: boolean;
    };
  };
  "PUT /roles/:role": {
    input: {
      name: string;
      description: string;
      permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
      protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    };
    output: {
      impact: {
        change: "narrows" | "widens";
        permission: "audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write";
        protected: boolean;
        people: number;
        services: number;
        environments: number;
        projects: number;
        examples: string[];
      }[];
      sentence: string;
      revision: string;
    } | {
      role: null | {
        fixed: boolean;
        name: string;
        description: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        default: null | {
          name: string;
          description: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
          protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        };
        id: string;
        builtin: boolean;
        edited: boolean;
        assignableToEnvironment: boolean;
        grants: number | null;
      };
    };
  };
  "DELETE /roles/:role": {
    input: undefined;
    output: {
      impact: {
        change: "narrows" | "widens";
        permission: "audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write";
        protected: boolean;
        people: number;
        services: number;
        environments: number;
        projects: number;
        examples: string[];
      }[];
      sentence: string;
      revision: string;
    } | {
      role: null | {
        fixed: boolean;
        name: string;
        description: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        default: null | {
          name: string;
          description: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
          protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        };
        id: string;
        builtin: boolean;
        edited: boolean;
        assignableToEnvironment: boolean;
        grants: number | null;
      };
    };
  };
  "PUT /instance-roles/:role": {
    input: {
      name: string;
      description: string;
      permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
      protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    };
    output: {
      impact: {
        change: "narrows" | "widens";
        permission: "audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write";
        protected: boolean;
        people: number;
        services: number;
        environments: number;
        projects: number;
        examples: string[];
      }[];
      sentence: string;
      revision: string;
    } | {
      role: null | {
        fixed: boolean;
        name: string;
        description: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        default: null | {
          name: string;
          description: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
          protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        };
        id: string;
        builtin: boolean;
        edited: boolean;
        assignableToEnvironment: boolean;
        grants: number | null;
      };
    };
  };
  "DELETE /instance-roles/:role": {
    input: undefined;
    output: {
      impact: {
        change: "narrows" | "widens";
        permission: "audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write";
        protected: boolean;
        people: number;
        services: number;
        environments: number;
        projects: number;
        examples: string[];
      }[];
      sentence: string;
      revision: string;
    } | {
      role: null | {
        fixed: boolean;
        name: string;
        description: string;
        permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        default: null | {
          name: string;
          description: string;
          permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
          protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
        };
        id: string;
        builtin: boolean;
        edited: boolean;
        assignableToEnvironment: boolean;
        grants: number | null;
      };
    };
  };
  "GET /members/:member/bindings/:id/enrollments": {
    input: undefined;
    output: never;
  };
  "POST /members/:member/bindings/:id/enrollments": {
    input: undefined;
    output: never;
  };
  "POST /members/:member/bindings/:id/enrollments/:enrollment/promote": {
    input: undefined;
    output: never;
  };
  "POST /members/:member/tokens/:id/approve": {
    input: undefined;
    output: never;
  };
};

export type AccessValue = string | null | {
  role: string;
  until: string | null;
};

export type ApprovalView = {
  id: string;
  status: "approved" | "cancelled" | "denied" | "expired" | "failed" | "pending";
  client: {
    name: string;
    host: string | null;
    registration: "cimd" | "dcr";
  };
  tool: string;
  summary: string;
  details: {
    label: string;
    value: string;
    kind?: "mono" | "time";
    note?: string;
    warn?: true;
  }[];
  asks: null | {
    value: {
      label: string;
      note: string;
    };
  };
  kind: "change" | "reveal";
  reveals: boolean;
  digest: string;
  basis: string | null;
  ready: boolean;
  createdAt: string;
  expiresAt: string;
  outcome: null | {
    text: string;
    result?: {
      [key: string]: unknown;
    };
    error?: string;
  };
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
  secrets: null | {
    key: string | null;
    version: number | null;
  }[];
  operationId: string | null;
  relatedSeq: number | null;
  requestId: string | null;
  run: null | {
    exchangeSeq: number;
    claims: {
      [key: string]: string | number;
    };
  };
  token: null | {
    id: string;
    label: string;
  };
  metadata: {
    [key: string]: unknown;
  };
  proof: "failed" | "proven" | "unproven";
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

export type AuthorizationView = {
  status: "invalid";
  message: string;
} | {
  status: "refused";
  message: string;
  redirect: string;
} | {
  status: "ready";
  client: {
    id: string;
    name: string;
    host: string | null;
    registration: "cimd" | "dcr";
  };
  redirectHost: string;
  loopbackOnly: boolean;
  scopes: ("manage-access" | "read" | "reveal" | "write")[];
  connections: ("manage-access" | "read" | "reveal" | "write")[][];
  days: number;
};

export type BindingView = {
  id: string;
  profile: "aws" | "azure" | "cloudflare" | "custom" | "enrollment" | "fly" | "gcp" | "github" | "github-reusable" | "github-reusable-organization" | "gitlab" | "kubernetes" | "vercel";
  issuer: string;
  jwksUri: string;
  keys: null | {
    kid: string | null;
    alg: "ES256" | "RS256";
    thumbprint: string;
  }[];
  claims: {
    [key: string]: string | string[];
  };
  scope: null | {
    [key: string]: string;
  };
  policy: null | {
    sources?: string[];
    audience?: string;
    keyAudience?: true;
    sessionHours?: number;
    replicas?: number;
    sessionDays?: number;
    overlapMinutes?: number;
    mintedBy?: string;
    approve?: true;
    onContention?: "alert";
    unsignedUploads?: true;
    reads?: {
      [key: string]: "*" | string[];
    };
  };
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
};

export type ConnectedApp = {
  id: string;
  name: string;
  host: string | null;
  registration: "cimd" | "dcr";
  scopes: ("manage-access" | "read" | "reveal" | "write")[];
  createdAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  expiresAt: string;
};

export type Decision = {
  status: "approved" | "cancelled" | "denied" | "expired" | "failed" | "pending";
  outcome: {
    text: string;
    result?: {
      [key: string]: unknown;
    };
    error?: string;
  };
  shown: {
    label: string;
    value: string;
    kind?: "mono" | "time";
    note?: string;
    warn?: true;
  }[];
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
  references: {
    holder: string;
    source: string;
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
    references: {
      holder: string;
      source: string;
    }[];
    stranded: string[];
  };
};

export type DismissedKey = {
  dismissedBy: string;
  dismissedAt: string;
  key: string;
  in: string[];
  folder: string | null;
};

export type DryRunOutcome = "added" | "archived" | "changed" | "unchanged";

export type DryRunResult = {
  dryRun: true;
  keys: {
    [key: string]: "added" | "archived" | "changed" | "unchanged";
  };
};

export type EnvironmentView = {
  slug: string;
  name: string;
  archivedAt: string | null;
  protected: boolean;
};

export type IdentityRow = {
  id: string;
  provider: string;
  email: string | null;
  createdAt: string;
  lastSignInAt: string | null;
};

export type ImpactLine = {
  change: "narrows" | "widens";
  permission: "audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write";
  protected: boolean;
  people: number;
  services: number;
  environments: number;
  projects: number;
  examples: string[];
};

export type InheritResult = {
  inherit?: boolean;
  folder?: string | null;
  archived?: boolean;
  operationId: string | null;
  key: string;
};

export type ListedReference = {
  readers: null | string[];
  canBreak: boolean;
  holderArchived: boolean;
  id: string;
  holder: string;
  source: string;
  state: "broken" | "live" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
  version: number | null;
  createdBy: null;
  createdAt: null;
  endedBy: null;
  endedAt: null;
};

export type Me = {
  principal: {
    type: "service" | "user";
    id: string;
  };
  registered: boolean;
  tampered: boolean;
  instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
  scope: {
    projects: "all" | {
      only: string[];
    } | {
      except: string[];
    };
    environments: "all" | {
      only: string[];
    } | {
      except: string[];
    };
  };
  runsInstance: boolean;
  canReadAudit: boolean;
  setsUpServices: boolean;
  serviceSetup: null | {
    projects: "all" | {
      only: string[];
    } | {
      except: string[];
    };
    environments: "all" | {
      only: string[];
    } | {
      except: string[];
    };
  };
  features: {
    mcp: string | null;
    workloads: boolean;
  };
  personalToken: null | {
    id: string;
    label: string;
    expiresAt: string;
    scope: {
      [key: string]: string;
    };
  };
  credentialExpiresAt: string | null;
  environments: {
    project: string;
    environment: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
  }[];
};

export type Member = {
  member: string;
  principalType: "service" | "user";
  principalId: string;
  instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
  scope: null | {
    projects: "all" | {
      only: string[];
    } | {
      except: string[];
    };
    environments: "all" | {
      only: string[];
    } | {
      except: string[];
    };
  };
  reachesByRole: boolean;
  managed: boolean;
  tampered: boolean;
  declared: boolean;
  grants: {
    id: string;
    project: string;
    environment: string | null;
    role: string;
    roleName: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    expiresAt: string | null;
  }[];
};

export type MemberAccess = {
  member: string;
  principalType: "service" | "user";
  principalId: string;
  status: "active" | "removed" | "tampered";
  instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
  scope: null | {
    projects: "all" | {
      only: string[];
    } | {
      except: string[];
    };
    environments: "all" | {
      only: string[];
    } | {
      except: string[];
    };
  };
  managed: boolean;
  grants: {
    id: string;
    project: string;
    environment: string | null;
    role: string;
    roleName: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    expiresAt: string | null;
  }[];
};

export type MissingKey = {
  key: string;
  in: string[];
  folder: string | null;
};

export type OffboardingReport = {
  principalType: "service" | "user";
  principalId: string;
  status: "active" | "removed" | "tampered";
  instanceRole: "admin" | "auditor" | "developer" | "member" | "owner";
  scope: {
    projects: "all" | {
      only: string[];
    } | {
      except: string[];
    };
    environments: "all" | {
      only: string[];
    } | {
      except: string[];
    };
  };
  declared: boolean;
  removedAt: string | null;
  removedBy: string | null;
  live: {
    grants: number;
    sessions: number;
    tokens: number;
    identities: number;
    apps: number;
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
  issuedTokens: null | {
    id: string;
    service: string;
    label: string | null;
    hint: string;
    expiresAt: string;
    lastUsedAt: string | null;
    scope: null | {
      [key: string]: string;
    };
  }[];
  apps: null | {
    id: string;
    name: string;
    host: string | null;
    registration: "cimd" | "dcr";
    scopes: ("manage-access" | "read" | "reveal" | "write")[];
    createdAt: string;
    lastUsedAt: string | null;
    lastUsedIp: string | null;
    expiresAt: string;
  }[];
  personalTokens: null | {
    id: string;
    label: string | null;
    hint: string;
    createdAt: string;
    createdBy: string;
    expiresAt: string;
    lastUsedAt: string | null;
    lastUsedIp: string | null;
    scope: null | {
      [key: string]: string;
    };
    session?: {
      bindingId: string | null;
    };
  }[];
  references: null | {
    version: number | null;
    source: string;
    id: string;
    holder: string;
    state: "broken" | "live" | "replaced" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
    createdBy: string;
    createdAt: string;
    endedBy: string | null;
    endedAt: string | null;
  }[];
  personal: {
    project: string;
    of: string;
    slug: string;
  }[];
};

export type PersonalConfig = {
  of: string;
  owner: string;
  slug: string;
  keys: string[];
  archived: boolean;
  createdAt: string;
};

export type ProjectSummary = {
  slug: string;
  name: string;
  archivedAt: string | null;
  folder: string | null;
  permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
  environments: {
    slug: string;
    name: string;
    accessible: boolean;
    parent: string | null;
    protected: boolean;
    unprotectable: boolean;
    personal: boolean;
    details: null | {
      archivedAt: string | null;
      secretCount: number | null;
    };
  }[];
  secretCount: number | null;
};

export type ReferenceView = {
  id: string;
  holder: string;
  source: string;
  state: "broken" | "live" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
  version: number | null;
  createdBy: null;
  createdAt: null;
  endedBy: null;
  endedAt: null;
};

export type RemovedMember = {
  principalType: "service" | "user";
  principalId: string;
  toRotate: number;
};

export type RoleImpact = {
  impact: {
    change: "narrows" | "widens";
    permission: "audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write";
    protected: boolean;
    people: number;
    services: number;
    environments: number;
    projects: number;
    examples: string[];
  }[];
  sentence: string;
  revision: string;
};

export type RoleView = {
  name: string;
  description: string;
  permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
  protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
  id: string;
  builtin: boolean;
  edited: boolean;
  fixed: boolean;
  default: null | {
    name: string;
    description: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
  };
  assignableToEnvironment: boolean;
  grants: number;
};

export type RolesView = {
  roles: {
    name: string;
    description: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    id: string;
    builtin: boolean;
    edited: boolean;
    fixed: boolean;
    default: null | {
      name: string;
      description: string;
      permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
      protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    };
    assignableToEnvironment: boolean;
    grants: number;
  }[];
  instanceRoles: {
    name: string;
    description: string;
    permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    id: string;
    builtin: boolean;
    edited: boolean;
    fixed: boolean;
    default: null | {
      name: string;
      description: string;
      permissions: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
      protected: ("audit.read" | "environment.manage" | "grant.manage" | "project.manage" | "secret.archive" | "secret.read" | "secret.use" | "secret.write")[];
    };
    assignableToEnvironment: boolean;
    grants: number;
  }[];
  editable: boolean;
};

export type SecretKey = {
  key: string;
  reference: null | {
    id: string;
    holder: string;
    source: string;
    state: "broken" | "live" | "source_archived" | "source_deleted" | "source_empty" | "source_is_reference";
    version: number | null;
    createdBy: null;
    createdAt: null;
    endedBy: null;
    endedAt: null;
    sourceId: string;
    canOpenSource: boolean;
  };
  folder: string | null;
  archived: boolean;
  version: number | null;
  versionId: string | null;
  updatedAt: string | null;
  updatedBy: string | null;
  generated: null | {
    recipe: string;
    pair?: {
      private: string;
      public: string;
    };
  };
  value: string | null;
  sensitivity: "plain" | "secret" | "sensitive" | null;
  readable: boolean;
  parent: null | {
    from: string;
    state: "inherited" | "overridden" | "removed";
    changed: boolean;
    reset: boolean;
    held: boolean;
  };
};

export type SecretVersion = {
  version: number;
  createdAt: string;
  createdBy: string;
  current: boolean;
  kek: string;
  recipe: string | null;
  plain: boolean;
  sensitivity: "plain" | "secret" | "sensitive";
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
  operationId: string | null;
  keys: {
    [key: string]: {
      version: number;
      sensitivity: "plain" | "secret" | "sensitive";
    } | {
      archived: true;
    } | {
      reference: string;
    };
  };
};

export type SettingsView = {
  serviceAccounts: {
    projects: "all" | {
      only: string[];
    } | {
      except: string[];
    };
    environments: "all" | {
      only: string[];
    } | {
      except: string[];
    };
  };
};

export type TokenRow = {
  id: string;
  label: string | null;
  hint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  scope: null | {
    [key: string]: string;
  };
  session?: {
    bindingId: string | null;
  };
};
