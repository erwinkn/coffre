-- Migration 001. Apply once with a migration role. Initialization is separate.
CREATE TABLE coffre_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), instance_id TEXT NOT NULL, revision BIGINT NOT NULL DEFAULT 0, audit_seq BIGINT NOT NULL DEFAULT 0, audit_hash TEXT NOT NULL);
CREATE TABLE coffre_guard (id TEXT PRIMARY KEY, ok INTEGER NOT NULL CONSTRAINT coffre_cas CHECK(ok=1));
CREATE TABLE coffre_projects (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, record TEXT NOT NULL);
CREATE TABLE coffre_environments (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES coffre_projects(id), name TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(project_id,name));
CREATE TABLE coffre_secrets (id TEXT PRIMARY KEY, env_id TEXT NOT NULL REFERENCES coffre_environments(id), secret_key TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(env_id,secret_key));
CREATE TABLE coffre_versions (secret_id TEXT NOT NULL REFERENCES coffre_secrets(id), version INTEGER NOT NULL CHECK(version>0), record TEXT NOT NULL, PRIMARY KEY(secret_id,version));
CREATE TABLE coffre_principals (id TEXT PRIMARY KEY, subject TEXT NOT NULL, kind TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(subject,kind));
CREATE TABLE coffre_grants (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES coffre_principals(id), scope_type TEXT NOT NULL, scope_id TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE coffre_audit (seq BIGINT PRIMARY KEY, id TEXT NOT NULL UNIQUE, actor_id TEXT, project_id TEXT, env_id TEXT, record TEXT NOT NULL);
CREATE TABLE coffre_outbox (seq BIGINT PRIMARY KEY REFERENCES coffre_audit(seq), event_hash TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE coffre_receipts (request_id TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE INDEX coffre_audit_environment ON coffre_audit(env_id,seq);
CREATE INDEX coffre_grants_principal ON coffre_grants(principal_id);
