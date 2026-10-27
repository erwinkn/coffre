-- 0.15's use, whole (docs/design/0.15-plan.md, PR 5; hot-path-one.md, "The use path on main"): use_credential again, reading every input PR 3's `readUse` reads (packages/vault/src/log-replay.ts), in one of two shapes, and answering its row as one JSON value. 0022's version read five inputs; nothing ever called it, so it is replaced, not kept beside. It only adds otherwise: 0.14's code calls none of it.
DROP FUNCTION use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea);
--> statement-breakpoint
DROP TYPE use_view;
--> statement-breakpoint
-- What a use reads, as use_credential returns it, as JSON (`to_json` of this row): one value, where the row itself, about a hundred typed columns, costs a row description and a field each per call, about 0.2 ms more of Postgres CPU a use (measured: hot-path-one.md, "The use path on main"). Its whole numbers come as JSON numbers, which the vault reads exactly (use.postgres.ts). `state` is null when the call did its work; otherwise it did nothing, and the rest is to be ignored: 'late' (past its deadline, or below the floor), 'ahead' (stamped more than a minute past the database's clock), 'unconfigured' (no policy); 'reprobe' and 'lock' never leave the function.
--
-- Each input is its row's columns, its seal (`*_seal`), and, in the probing form, the seal of its object's newest change (`*_last`; null in the cached form, where the isolate holds them). `inputs` is the newest change of any input, what a cover is held to; `probed`, whether the statement probed them (or held to the isolate's). The environments are the four `readUse` may weigh, each read only where the rows name it: e1 the place read through, e2 the key's own, e3 a reference's source's, e4 a personal config's parent. `m_old`: the newest 0.14 access entry the principal's newest change accounts for; `m_access`: the newest one 0.14's log holds (UsesSeeOldWrites, Migration015.tla).
CREATE TYPE use_row AS (
    state text, number bigint, covered bigint, newest bigint, newest_mac bytea, inputs bigint, probed boolean,
    c_principal text, c_kind text, c_scope text, c_revoked boolean, c_expires bigint, c_seal bytea, c_last bytea,
    m_status text, m_owner boolean, m_role text, m_scope text, m_seal bytea, m_last bytea, m_old bigint, m_access bigint,
    g_project uuid[], g_environment uuid[], g_slug text[], g_role text[], g_expires bigint[],
    r_value text, r_seal bytea, r_last bytea,
    p_value text, p_seal bytea, p_last bytea, cap_count integer, cap_window bigint,
    s_project uuid, s_environment uuid, s_version uuid, s_source uuid, s_seal bytea, s_last bytea,
    x_project uuid, x_environment uuid, x_version uuid, x_source uuid, x_seal bytea, x_last bytea,
    v_envelope integer, v_ciphertext bytea, v_iv bytea, v_auth_tag bytea, v_wrapped_dek bytea, v_kek_provider text, v_kek_id text, v_kek_version text, v_sensitive boolean, v_plain boolean,
    e1_id uuid, e1_project uuid, e1_slug text, e1_owner text, e1_parent uuid, e1_protected boolean, e1_archived boolean, e1_seal bytea, e1_last bytea,
    e2_id uuid, e2_project uuid, e2_slug text, e2_owner text, e2_parent uuid, e2_protected boolean, e2_archived boolean, e2_seal bytea, e2_last bytea,
    e3_id uuid, e3_project uuid, e3_slug text, e3_owner text, e3_parent uuid, e3_protected boolean, e3_archived boolean, e3_seal bytea, e3_last bytea,
    e4_id uuid, e4_project uuid, e4_slug text, e4_owner text, e4_parent uuid, e4_protected boolean, e4_archived boolean, e4_seal bytea, e4_last bytea,
    in_set boolean, others integer
);
--> statement-breakpoint
-- A use (hot-path-one.md, "A use"; formal/HotPathOne.tla): the fence shared (UseLocks), then one statement, with a snapshot of its own taken after the lock (StatementSnapshot: each of a volatile function's statements takes a new one under READ COMMITTED; a bare CTE's one snapshot would predate the wait), that reads every input the decision needs and inserts the entry, numbered now (UseNumberUnderLock). The lock goes with the commit (LockToCommit: an xact lock). The Worker decides on what it returns, and releases a value only once the call has returned, after the commit (ReleaseAfterCommit, SyncCommit); the log records the request, not the outcome.
--
-- The deadline (DeadlineChecked, R53, R54): a call that comes after it, or with a deadline more than deadline_max() after its `at`, or an `at` below the floor (FloorChecked; or no floor row), writes nothing and answers 'late', each by clock_timestamp(), never now(), which is the transaction's start, before any lock wait; one that runs past it, waiting for its principal's lock say, rolls back (57014). A replay of a call that wrote fails on (at, request_id), 23505: deciding again on today's state could allow, after a revocation, a use the log has before it.
--
-- The bulk cap (R28, R52), its count and window the policy object's newest change's (CapFromPolicy, CapSealed): probed, or, in the cached form, the isolate's, which it read from that change and passes only with the change it read it at, held here to be still the log's newest. Never the policy's row, nor the deployment's config. A use before the policy is logged, or under one that names no count or window, answers 'unconfigured'. The cap's row moves for every request it admits, whatever the seals say (HotPathOneStaleBulk), under the principal's own lock (PrincipalLocks): a use that may write it takes it and reads again. As 0022's, which says the rule.
--
-- Covers (p_cover, with its entry's at and request id; CoverChecksChanges, CoverChecksAllInputs, CoverExists, CoverFresh): a repeat of an allowed use this isolate wrote, of the same credential and key, with no change to any input numbered after it, its entry still in the log and the key's bulk row fresh, writes nothing; the Worker decides on what was read.
--
-- The seal cache (p_known, p_known_mac; CacheChecked, CacheSameChange): if the log's newest change is still exactly the one the isolate read its seals at, by number and MAC, the statement probes no input's newest change. Otherwise it writes nothing, answers 'reprobe' inside the function, and the probing statement runs. Two statements, not one with its probes skipped: a probe's plan nodes cost most of it even when it does not run (measured, W211).
--
-- The inputs, each one object of W216's (sealed-inputs.md), in `readUse`'s order: the credential, its principal (the member, its grants, the access entries of 0.14 about it), the roles, the policy, the key (a reference's when it has no version of its own: its newest secret_references row names the source), the source, and the environments the decision weighs.
CREATE FUNCTION use_credential(
    p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_purpose smallint, p_place uuid, p_mac bytea, p_deadline bigint,
    p_cover bigint DEFAULT NULL, p_cover_at bigint DEFAULT NULL, p_cover_request bigint DEFAULT NULL, p_known bigint DEFAULT NULL, p_known_mac bytea DEFAULT NULL,
    p_cap_count integer DEFAULT NULL, p_cap_window bigint DEFAULT NULL
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r public.use_row;
    locked boolean := false;
    probe boolean := p_known IS NULL OR p_cap_count IS NULL OR p_cap_window IS NULL;
    -- A use through a place, or of a key with no value of its own (a reference), reads every input; the others, most
    -- uses, the plain shape: no place, no source, none of their joins.
    whole boolean := p_place IS NOT NULL;
BEGIN
    IF p_deadline IS NULL OR p_deadline > p_at + public.deadline_max() THEN r.state := 'late'; RETURN to_json(r); END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): checked here at no cost, and again in the statement.
    IF p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN r.state := 'ahead'; RETURN to_json(r); END IF;
    PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    LOOP
        IF probe AND NOT whole THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last,
                    c.principal AS p, c.kind AS c_kind, c.scope AS c_scope, c.revoked_at IS NOT NULL AS c_revoked,
                    (extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, NULL::uuid AS s_source, s.seal AS s_seal,
                    NULL::uuid AS x_project, NULL::uuid AS x_environment, NULL::uuid AS x_version, NULL::uuid AS x_source, NULL::bytea AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain,
                    NULL::uuid AS e1_id, NULL::uuid AS e1_project, NULL::text AS e1_slug, NULL::text AS e1_owner, NULL::uuid AS e1_parent, NULL::boolean AS e1_protected, NULL::boolean AS e1_archived, NULL::bytea AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, e2.seal AS e2_seal,
                    NULL::uuid AS e3_id, NULL::uuid AS e3_project, NULL::text AS e3_slug, NULL::text AS e3_owner, NULL::uuid AS e3_parent, NULL::boolean AS e3_protected, NULL::boolean AS e3_archived, NULL::bytea AS e3_seal,
                    CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last,
                    -- Each input's object key, computed once: a key in a probe's own condition is computed again for every row it reads (0022, decision 3).
                    public.log_object('credential', p_credential::text) AS k_credential,
                    public.log_object('principal', c.principal) AS k_member,
                    public.log_object('secret', p_secret::text) AS k_secret,
                    public.log_object('environment', s.environment_id::text) AS k_e2,
                    public.log_object('environment', (CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END)::text) AS k_e4
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN public.log_fence f ON f.only_row
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The cap as the policy's newest change says it (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
                  ) lpol ON true
                  LEFT JOIN public.credentials c ON c.id = p_credential
                  LEFT JOIN public.vault_members m ON m.principal = c.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = p_secret AND s.archived_at IS NULL
                  -- The key's own version, its own environment, and that environment's parent when it is a personal config.
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e4 ON e4.id = e2.parent_id AND e2.owner IS NOT NULL
                  LEFT JOIN public.log_bulk b ON b.principal = c.principal AND b.secret = p_secret
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh,
                    CASE WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         WHEN i.p IS NOT NULL AND NOT locked AND coalesce(i.bulk_last <= p_at - cap.refresh, true) THEN 'lock' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, NULL::bytea AS x_last,
                    NULL::bytea AS e1_last, l2.seal AS e2_last, NULL::bytea AS e3_last, l4.seal AS e4_last,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    coalesce(i.bulk_last <= p_at - cap.refresh, true) AS stale,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max()
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others
                  FROM i
                  CROSS JOIN LATERAL (SELECT least(60000, i.cap_window / 10) AS refresh) cap
                  -- Each input's newest change: one index-only probe each (log_changes_object_idx holds the seal), the principal's
                  -- with its payload, which names the 0.14 entry it accounts for.
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON i.k_member IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1) lr ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e2 ORDER BY x.number DESC LIMIT 1) l2 ON i.k_e2 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e4 ORDER BY x.number DESC LIMIT 1) l4 ON i.k_e4 IS NOT NULL
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT (
                      p_cover IS NOT NULL AND v.bulk_last > p_at - v.refresh AND p_cover > coalesce(v.inputs, 0)
                      AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover AND u.credential = p_credential AND u.secret = p_secret))
                RETURNING log_uses.number
            ),
            k AS (
                INSERT INTO public.log_bulk (principal, secret, last)
                SELECT v.p, p_secret, p_at FROM v
                 WHERE v.state IS NULL AND v.p IS NOT NULL AND v.stale AND (v.is_in OR v.n_others < v.cap_count)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = EXCLUDED.last
            )
            SELECT v.state, (SELECT w.number FROM w), NULL::bigint, v.newest, v.newest_mac, v.inputs, true,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, v.c_last,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, v.m_last, v.m_old,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, v.r_last,
                v.p_value, v.p_seal, v.p_last, v.cap_count, v.cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, v.s_last,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, v.x_last,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, v.e1_last,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, v.e2_last,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, v.e3_last,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, v.e4_last,
                v.is_in, v.n_others
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSIF probe THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last,
                    c.principal AS p, c.kind AS c_kind, c.scope AS c_scope, c.revoked_at IS NOT NULL AS c_revoked,
                    (extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, ref.source_secret_id AS s_source, s.seal AS s_seal,
                    src.project_id AS x_project, src.environment_id AS x_environment, src.current_version_id AS x_version, xref.source_secret_id AS x_source, src.seal AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain,
                    ids.e1 AS e1_id, e1.project_id AS e1_project, e1.slug AS e1_slug, e1.owner AS e1_owner, e1.parent_id AS e1_parent, e1.protected AS e1_protected, e1.archived_at IS NOT NULL AS e1_archived, e1.seal AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, e2.seal AS e2_seal,
                    ids.e3 AS e3_id, e3.project_id AS e3_project, e3.slug AS e3_slug, e3.owner AS e3_owner, e3.parent_id AS e3_parent, e3.protected AS e3_protected, e3.archived_at IS NOT NULL AS e3_archived, e3.seal AS e3_seal,
                    CASE WHEN ve.owner IS NOT NULL THEN ve.parent END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last,
                    -- Each input's object key, computed once: a key in a probe's own condition is computed again for every row it reads (0022, decision 3).
                    public.log_object('credential', p_credential::text) AS k_credential,
                    public.log_object('principal', c.principal) AS k_member,
                    public.log_object('secret', p_secret::text) AS k_secret,
                    public.log_object('secret', ref.source_secret_id::text) AS k_source,
                    public.log_object('environment', ids.e1::text) AS k_e1,
                    public.log_object('environment', s.environment_id::text) AS k_e2,
                    public.log_object('environment', ids.e3::text) AS k_e3,
                    public.log_object('environment', (CASE WHEN ve.owner IS NOT NULL THEN ve.parent END)::text) AS k_e4
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN public.log_fence f ON f.only_row
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  -- The cap as the policy's newest change says it (CapSealed): every policy change logs the whole policy as its `value`.
                  LEFT JOIN LATERAL (
                      SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = public.log_object('policy', 'instance') ORDER BY x.number DESC LIMIT 1
                  ) lpol ON true
                  LEFT JOIN public.credentials c ON c.id = p_credential
                  LEFT JOIN public.vault_members m ON m.principal = c.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = p_secret AND s.archived_at IS NULL
                  -- A key with no version of its own is a reference while its newest reference row names a source.
                  LEFT JOIN LATERAL (
                      SELECT y.source_secret_id FROM public.secret_references y WHERE y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1
                  ) ref ON s.current_version_id IS NULL
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT y.source_secret_id FROM public.secret_references y WHERE y.secret_id = src.id ORDER BY y.created_seq DESC LIMIT 1
                  ) xref ON src.current_version_id IS NULL
                  -- The value's version: the key's own, or its source's.
                  LEFT JOIN public.secret_versions sv ON sv.id = CASE WHEN ref.source_secret_id IS NULL THEN s.current_version_id ELSE src.current_version_id END
                  -- The environments `useEnvironments` names, each by the id the rows name, whether or not its row is there: e1 the
                  -- place read through, e2 the key's own, e3 its value's (a reference's source's) where that is another, and e4
                  -- the parent of its value's when that is a personal config.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN p_place IS DISTINCT FROM s.environment_id THEN p_place END AS e1,
                             CASE WHEN src.environment_id IS DISTINCT FROM s.environment_id THEN src.environment_id END AS e3
                  ) ids ON true
                  LEFT JOIN public.environments e1 ON e1.id = ids.e1
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e3 ON e3.id = ids.e3
                  -- The value's environment's row: the key's own, unless it is a reference, whose source is elsewhere or gone.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.owner ELSE e3.owner END AS owner,
                             CASE WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.parent_id ELSE e3.parent_id END AS parent
                  ) ve ON true
                  LEFT JOIN public.environments e4 ON e4.id = ve.parent AND ve.owner IS NOT NULL
                  LEFT JOIN public.log_bulk b ON b.principal = c.principal AND b.secret = p_secret
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh,
                    CASE WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         WHEN i.p IS NOT NULL AND NOT locked AND coalesce(i.bulk_last <= p_at - cap.refresh, true) THEN 'lock' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, lx.seal AS x_last,
                    l1.seal AS e1_last, l2.seal AS e2_last, l3.seal AS e3_last, l4.seal AS e4_last,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    coalesce(i.bulk_last <= p_at - cap.refresh, true) AS stale,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max()
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others
                  FROM i
                  CROSS JOIN LATERAL (SELECT least(60000, i.cap_window / 10) AS refresh) cap
                  -- Each input's newest change: one index-only probe each (log_changes_object_idx holds the seal), the principal's
                  -- with its payload, which names the 0.14 entry it accounts for.
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_credential ORDER BY x.number DESC LIMIT 1) lc ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal, x.payload FROM public.log_changes x WHERE x.object = i.k_member ORDER BY x.number DESC LIMIT 1) lm ON i.k_member IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = public.log_object('roles', 'instance') ORDER BY x.number DESC LIMIT 1) lr ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_secret ORDER BY x.number DESC LIMIT 1) ls ON true
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_source ORDER BY x.number DESC LIMIT 1) lx ON i.k_source IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e1 ORDER BY x.number DESC LIMIT 1) l1 ON i.k_e1 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e2 ORDER BY x.number DESC LIMIT 1) l2 ON i.k_e2 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e3 ORDER BY x.number DESC LIMIT 1) l3 ON i.k_e3 IS NOT NULL
                  LEFT JOIN LATERAL (SELECT x.number, x.seal FROM public.log_changes x WHERE x.object = i.k_e4 ORDER BY x.number DESC LIMIT 1) l4 ON i.k_e4 IS NOT NULL
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT (
                      p_cover IS NOT NULL AND v.bulk_last > p_at - v.refresh AND p_cover > coalesce(v.inputs, 0)
                      AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover AND u.credential = p_credential AND u.secret = p_secret))
                RETURNING log_uses.number
            ),
            k AS (
                INSERT INTO public.log_bulk (principal, secret, last)
                SELECT v.p, p_secret, p_at FROM v
                 WHERE v.state IS NULL AND v.p IS NOT NULL AND v.stale AND (v.is_in OR v.n_others < v.cap_count)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = EXCLUDED.last
            )
            SELECT v.state, (SELECT w.number FROM w), NULL::bigint, v.newest, v.newest_mac, v.inputs, true,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, v.c_last,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, v.m_last, v.m_old,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, v.r_last,
                v.p_value, v.p_seal, v.p_last, v.cap_count, v.cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, v.s_last,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, v.x_last,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, v.e1_last,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, v.e2_last,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, v.e3_last,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, v.e4_last,
                v.is_in, v.n_others
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSIF NOT whole THEN
            -- The isolate's seals, and its cap, read at the change it names: no probe, only whether a change came since
            -- (then nothing is written: 'reprobe').
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor,
                    c.principal AS p, c.kind AS c_kind, c.scope AS c_scope, c.revoked_at IS NOT NULL AS c_revoked,
                    (extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, NULL::uuid AS s_source, s.seal AS s_seal,
                    NULL::uuid AS x_project, NULL::uuid AS x_environment, NULL::uuid AS x_version, NULL::uuid AS x_source, NULL::bytea AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain,
                    NULL::uuid AS e1_id, NULL::uuid AS e1_project, NULL::text AS e1_slug, NULL::text AS e1_owner, NULL::uuid AS e1_parent, NULL::boolean AS e1_protected, NULL::boolean AS e1_archived, NULL::bytea AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, e2.seal AS e2_seal,
                    NULL::uuid AS e3_id, NULL::uuid AS e3_project, NULL::text AS e3_slug, NULL::text AS e3_owner, NULL::uuid AS e3_parent, NULL::boolean AS e3_protected, NULL::boolean AS e3_archived, NULL::bytea AS e3_seal,
                    CASE WHEN e2.owner IS NOT NULL THEN e2.parent_id END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN public.log_fence f ON f.only_row
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  LEFT JOIN public.credentials c ON c.id = p_credential
                  LEFT JOIN public.vault_members m ON m.principal = c.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = p_secret AND s.archived_at IS NULL
                  -- The key's own version, its own environment, and that environment's parent when it is a personal config.
                  LEFT JOIN public.secret_versions sv ON sv.id = s.current_version_id
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e4 ON e4.id = e2.parent_id AND e2.owner IS NOT NULL
                  LEFT JOIN public.log_bulk b ON b.principal = c.principal AND b.secret = p_secret
            ),
            v AS MATERIALIZED (
                SELECT i.*, least(60000, p_cap_window / 10) AS refresh,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.p IS NOT NULL AND NOT locked AND coalesce(i.bulk_last <= p_at - least(60000, p_cap_window / 10), true) THEN 'lock' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - least(60000, p_cap_window / 10), false) AS is_in,
                    coalesce(i.bulk_last <= p_at - least(60000, p_cap_window / 10), true) AS stale,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - least(60000, p_cap_window / 10), false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - p_cap_window - least(60000, p_cap_window / 10) - public.deadline_max()
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT (
                      -- The isolate held its cover to the cached seals' numbers when it read them.
                      p_cover IS NOT NULL AND v.bulk_last > p_at - v.refresh
                      AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover AND u.credential = p_credential AND u.secret = p_secret))
                RETURNING log_uses.number
            ),
            k AS (
                INSERT INTO public.log_bulk (principal, secret, last)
                SELECT v.p, p_secret, p_at FROM v
                 WHERE v.state IS NULL AND v.p IS NOT NULL AND v.stale AND (v.is_in OR v.n_others < p_cap_count)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = EXCLUDED.last
            )
            SELECT v.state, (SELECT w.number FROM w), NULL::bigint, v.newest, v.newest_mac, NULL::bigint, false,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, NULL::bytea,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, NULL::bytea, NULL::bigint,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, NULL::bytea,
                v.p_value, v.p_seal, NULL::bytea, p_cap_count, p_cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, NULL::bytea,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, NULL::bytea,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, NULL::bytea,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, NULL::bytea,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, NULL::bytea,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, NULL::bytea,
                v.is_in, v.n_others
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        ELSE
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor,
                    c.principal AS p, c.kind AS c_kind, c.scope AS c_scope, c.revoked_at IS NOT NULL AS c_revoked,
                    (extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
                    m.status AS m_status, m.owner AS m_owner, m.role AS m_role, m.scope AS m_scope, m.seal AS m_seal,
                    cfg.r_value, cfg.r_seal, cfg.p_value, cfg.p_seal,
                    s.project_id AS s_project, s.environment_id AS s_environment, s.current_version_id AS s_version, ref.source_secret_id AS s_source, s.seal AS s_seal,
                    src.project_id AS x_project, src.environment_id AS x_environment, src.current_version_id AS x_version, xref.source_secret_id AS x_source, src.seal AS x_seal,
                    sv.envelope_version, sv.ciphertext, sv.iv, sv.auth_tag, sv.wrapped_dek, sv.kek_provider, sv.kek_id, sv.kek_version, sv.sensitive, sv.plaintext IS NOT NULL AS v_plain,
                    ids.e1 AS e1_id, e1.project_id AS e1_project, e1.slug AS e1_slug, e1.owner AS e1_owner, e1.parent_id AS e1_parent, e1.protected AS e1_protected, e1.archived_at IS NOT NULL AS e1_archived, e1.seal AS e1_seal,
                    s.environment_id AS e2_id, e2.project_id AS e2_project, e2.slug AS e2_slug, e2.owner AS e2_owner, e2.parent_id AS e2_parent, e2.protected AS e2_protected, e2.archived_at IS NOT NULL AS e2_archived, e2.seal AS e2_seal,
                    ids.e3 AS e3_id, e3.project_id AS e3_project, e3.slug AS e3_slug, e3.owner AS e3_owner, e3.parent_id AS e3_parent, e3.protected AS e3_protected, e3.archived_at IS NOT NULL AS e3_archived, e3.seal AS e3_seal,
                    CASE WHEN ve.owner IS NOT NULL THEN ve.parent END AS e4_id, e4.project_id AS e4_project, e4.slug AS e4_slug, e4.owner AS e4_owner, e4.parent_id AS e4_parent, e4.protected AS e4_protected, e4.archived_at IS NOT NULL AS e4_archived, e4.seal AS e4_seal,
                    b.last AS bulk_last
                  FROM (SELECT 1) one
                  LEFT JOIN LATERAL (SELECT x.number, x.mac FROM public.log_changes x ORDER BY x.number DESC LIMIT 1) n ON true
                  LEFT JOIN public.log_fence f ON f.only_row
                  -- The roles and the policy, both rows in one read of their one-page table.
                  LEFT JOIN LATERAL (
                      SELECT max(g.value) FILTER (WHERE g.name = 'roles') AS r_value, (array_agg(g.seal) FILTER (WHERE g.name = 'roles'))[1] AS r_seal,
                             max(g.value) FILTER (WHERE g.name = 'policy') AS p_value, (array_agg(g.seal) FILTER (WHERE g.name = 'policy'))[1] AS p_seal
                        FROM public.log_config g
                  ) cfg ON true
                  LEFT JOIN public.credentials c ON c.id = p_credential
                  LEFT JOIN public.vault_members m ON m.principal = c.principal
                  -- An archived key is gone (`secret.delete`): no object.
                  LEFT JOIN public.secrets s ON s.id = p_secret AND s.archived_at IS NULL
                  -- A key with no version of its own is a reference while its newest reference row names a source.
                  LEFT JOIN LATERAL (
                      SELECT y.source_secret_id FROM public.secret_references y WHERE y.secret_id = s.id ORDER BY y.created_seq DESC LIMIT 1
                  ) ref ON s.current_version_id IS NULL
                  LEFT JOIN public.secrets src ON src.id = ref.source_secret_id AND src.archived_at IS NULL
                  LEFT JOIN LATERAL (
                      SELECT y.source_secret_id FROM public.secret_references y WHERE y.secret_id = src.id ORDER BY y.created_seq DESC LIMIT 1
                  ) xref ON src.current_version_id IS NULL
                  -- The value's version: the key's own, or its source's.
                  LEFT JOIN public.secret_versions sv ON sv.id = CASE WHEN ref.source_secret_id IS NULL THEN s.current_version_id ELSE src.current_version_id END
                  -- The environments `useEnvironments` names, each by the id the rows name, whether or not its row is there: e1 the
                  -- place read through, e2 the key's own, e3 its value's (a reference's source's) where that is another, and e4
                  -- the parent of its value's when that is a personal config.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN p_place IS DISTINCT FROM s.environment_id THEN p_place END AS e1,
                             CASE WHEN src.environment_id IS DISTINCT FROM s.environment_id THEN src.environment_id END AS e3
                  ) ids ON true
                  LEFT JOIN public.environments e1 ON e1.id = ids.e1
                  LEFT JOIN public.environments e2 ON e2.id = s.environment_id
                  LEFT JOIN public.environments e3 ON e3.id = ids.e3
                  -- The value's environment's row: the key's own, unless it is a reference, whose source is elsewhere or gone.
                  LEFT JOIN LATERAL (
                      SELECT CASE WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.owner ELSE e3.owner END AS owner,
                             CASE WHEN ref.source_secret_id IS NULL OR (src.id IS NOT NULL AND ids.e3 IS NULL) THEN e2.parent_id ELSE e3.parent_id END AS parent
                  ) ve ON true
                  LEFT JOIN public.environments e4 ON e4.id = ve.parent AND ve.owner IS NOT NULL
                  LEFT JOIN public.log_bulk b ON b.principal = c.principal AND b.secret = p_secret
            ),
            v AS MATERIALIZED (
                SELECT i.*, least(60000, p_cap_window / 10) AS refresh,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.p IS NOT NULL AND NOT locked AND coalesce(i.bulk_last <= p_at - least(60000, p_cap_window / 10), true) THEN 'lock' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - least(60000, p_cap_window / 10), false) AS is_in,
                    coalesce(i.bulk_last <= p_at - least(60000, p_cap_window / 10), true) AS stale,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - least(60000, p_cap_window / 10), false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - p_cap_window - least(60000, p_cap_window / 10) - public.deadline_max()
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  FROM v WHERE v.state IS NULL AND NOT (
                      -- The isolate held its cover to the cached seals' numbers when it read them.
                      p_cover IS NOT NULL AND v.bulk_last > p_at - v.refresh
                      AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover AND u.credential = p_credential AND u.secret = p_secret))
                RETURNING log_uses.number
            ),
            k AS (
                INSERT INTO public.log_bulk (principal, secret, last)
                SELECT v.p, p_secret, p_at FROM v
                 WHERE v.state IS NULL AND v.p IS NOT NULL AND v.stale AND (v.is_in OR v.n_others < p_cap_count)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = EXCLUDED.last
            )
            SELECT v.state, (SELECT w.number FROM w), NULL::bigint, v.newest, v.newest_mac, NULL::bigint, false,
                v.p, v.c_kind, v.c_scope, v.c_revoked, v.c_expires, v.c_seal, NULL::bytea,
                v.m_status, v.m_owner, v.m_role, v.m_scope, v.m_seal, NULL::bytea, NULL::bigint,
                (SELECT a.seq FROM public.audit_log a WHERE a.author = 'vault' AND a.subject_principal = v.p AND a.decision = 'allow'
                    AND a.action IN ('member.add', 'member.restore', 'member.owner', 'member.role', 'member.remove', 'access.grant', 'access.revoke') ORDER BY a.seq DESC LIMIT 1),
                gr.g_project, gr.g_environment, gr.g_slug, gr.g_role, gr.g_expires,
                v.r_value, v.r_seal, NULL::bytea,
                v.p_value, v.p_seal, NULL::bytea, p_cap_count, p_cap_window,
                v.s_project, v.s_environment, v.s_version, v.s_source, v.s_seal, NULL::bytea,
                v.x_project, v.x_environment, v.x_version, v.x_source, v.x_seal, NULL::bytea,
                v.envelope_version, v.ciphertext, v.iv, v.auth_tag, v.wrapped_dek, v.kek_provider, v.kek_id, v.kek_version, v.sensitive, v.v_plain,
                v.e1_id, v.e1_project, v.e1_slug, v.e1_owner, v.e1_parent, v.e1_protected, v.e1_archived, v.e1_seal, NULL::bytea,
                v.e2_id, v.e2_project, v.e2_slug, v.e2_owner, v.e2_parent, v.e2_protected, v.e2_archived, v.e2_seal, NULL::bytea,
                v.e3_id, v.e3_project, v.e3_slug, v.e3_owner, v.e3_parent, v.e3_protected, v.e3_archived, v.e3_seal, NULL::bytea,
                v.e4_id, v.e4_project, v.e4_slug, v.e4_owner, v.e4_parent, v.e4_protected, v.e4_archived, v.e4_seal, NULL::bytea,
                v.is_in, v.n_others
              INTO r
              FROM v
              -- The principal's grants as five lists, one entry per grant, lapsed ones included; an environment's grant with its project, which its row finds through `environments`.
              LEFT JOIN LATERAL (
                  SELECT array_agg(coalesce(g.project_id, ge.project_id)) AS g_project, array_agg(g.environment_id) AS g_environment,
                         array_agg(g.environment_slug) AS g_slug, array_agg(g.role) AS g_role, array_agg(g.expires_at) AS g_expires
                    FROM public.vault_grants g LEFT JOIN public.environments ge ON ge.id = g.environment_id
                   WHERE g.principal = v.p
              ) gr ON v.m_status IS NOT NULL;
        END IF;
        -- A repeat on its cover wrote nothing: say which entry it rode on.
        IF r.state IS NULL AND r.number IS NULL THEN r.covered := p_cover; END IF;
        IF r.state = 'reprobe' THEN probe := true; CONTINUE; END IF;
        IF r.state = 'whole' THEN whole := true; CONTINUE; END IF;
        EXIT WHEN r.state IS DISTINCT FROM 'lock';
        -- Its key's bulk row is stale or missing: this use may write it, so it takes its principal's lock and reads again.
        PERFORM pg_advisory_xact_lock(1668244066, hashtext(r.c_principal));
        locked := true;
    END LOOP;
    -- The deadline holds in Postgres to the end: a call that ran past it rolls back and writes nothing. The hot login's lock_timeout and statement_timeout bound the waits.
    IF r.state IS NULL AND (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN
        RAISE EXCEPTION 'past its deadline' USING ERRCODE = '57014';
    END IF;
    RETURN to_json(r);
END
$$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint) FROM PUBLIC;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION use_credential(uuid, uuid, bigint, bigint, smallint, uuid, bytea, bigint, bigint, bigint, bigint, bigint, bytea, integer, bigint) TO coffre_vault;
