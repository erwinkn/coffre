-- Instance-level principal directory.
--
-- Project grants answer "what may this identity do in this project?" They are
-- not a user directory and cannot represent a user who currently has no
-- project access. Keep the two concerns separate:
--
--   * principals: identities known to this Coffre instance
--   * grants: project/environment access held by those identities
--
-- Human users may be promoted to instance owner. Owners administer this
-- directory and may read the complete audit log. Service accounts never hold
-- an instance role beyond ordinary user; their authority comes only from
-- project grants.

CREATE TABLE principals (
    principal_type text NOT NULL CHECK (principal_type IN ('user', 'service')),
    principal_id   text NOT NULL,
    instance_role  text NOT NULL DEFAULT 'user'
                   CHECK (instance_role IN ('user', 'owner')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text NOT NULL,
    PRIMARY KEY (principal_type, principal_id),
    CHECK (principal_type = 'user' OR instance_role = 'user')
);

-- Preserve every identity already known through a project grant. This is a
-- directory backfill only; it does not change any project authority.
INSERT INTO principals (principal_type, principal_id, instance_role, created_by)
SELECT DISTINCT principal_type, principal_id, 'user', created_by
  FROM grants
ON CONFLICT DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON principals TO coffre_app;
