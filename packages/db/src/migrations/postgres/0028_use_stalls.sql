-- One hot principal's uses never queue on its own lock, and a new backend plans its statements before it takes the fence (T127, T131; docs/design/0.15-plan.md, "One hot principal, cold backends"; formal/HotPathOne.tla). use_credential as 0024 wrote it, but for the bulk cap's writes and the warm-up below. It replaces a function only 0.15's hot path calls, behind the switch.
--
-- The cap's row (T127, R44). In 0024 a use whose key's row was stale took its principal's lock exclusive, as one entering the set does, and read again: each use of one principal that saw a stale row waited for the one before it to commit. Now:
--   a key that enters the set (no row, or a row out of the window) takes the lock exclusive, counts the other keys and writes (PrincipalLocks), as before;
--   a key in the set whose row is from an earlier refresh period moves it on under the lock shared (RefreshLocks, RefreshShared): a key entering waits for every move numbered before it, and no move waits for another;
--   every write is the start of the use's refresh period, at - at % refresh (RefreshPeriods), and a move only raises the row: moves at once write the same period, or the greater stands, so the row ends where the replay's does whichever commits first. The first use to move a key to a period takes a lock of that key and period's own without waiting, and moves the row; the others take it shared, which waits for that one's end but never for each other, then read the row again, locking none, and leave it moved. (An UPDATE that waits on a row another is moving, and then finds it moved, keeps the row locked to its own commit, as an upsert does: each would queue the next.) If the first rolled back, the others elect another the same way, on the lock's next round;
--   the writes leave the statement every use runs: a call that took the principal's lock makes them in a statement of its own, after the one that read, in the same transaction and under the same locks. The uses that find their key fresh, nearly all, plan and run no write of the cap's row;
--   a key is fresh while its row is from the use's own period, for covers too (CoverFresh). A period starts less than a refresh before its use, the margin the set's bounds already have (BulkCapHolds; Use.lean, periodOf_lags);
--   refresh is at least 1 ms: a tenth of a window under 10 ms was 0;
--   another key counts against one entering a minute longer than before, over window + refresh + deadline + 60 s (AheadSlack): a use is decided up to the deadline after its `at`, and, its Worker's clock up to a minute ahead (the most 'ahead' lets by), up to a minute before it, so one stamped up to deadline + 60 s before another can be decided after it. With deadline alone, TLC let two keys out in one window (HotPathOneBulkSkew, with the clock run longer: 0024 has the hole too).
--
-- The cold plan (T131, R58). A new backend's first call planned its statement holding the fence shared (29 ms against 1.5 ms after), and a barrier queued behind it held every use up meanwhile. Now a session's first call runs each of the four statements once dry, before the fence: each reads and writes nothing (`WHERE NOT dry`, a one-time filter in the generic plan the hot login keeps) and takes no advisory lock (only, as any statement does, each table's AccessShare lock, to the commit), and its plan stays cached for the session. The session then says so in a setting of its own, coffre.use_planned, holding this migration's number, so that a function replaced again plans again; a rollback or RESET ALL (DISCARD ALL) clears it, and the next call plans again, as it must.
--> statement-breakpoint
CREATE OR REPLACE FUNCTION use_credential(
    p_credential uuid, p_secret uuid, p_request bigint, p_at bigint, p_purpose smallint, p_place uuid, p_mac bytea, p_deadline bigint,
    p_cover bigint DEFAULT NULL, p_cover_at bigint DEFAULT NULL, p_cover_request bigint DEFAULT NULL, p_known bigint DEFAULT NULL, p_known_mac bytea DEFAULT NULL,
    p_cap_count integer DEFAULT NULL, p_cap_window bigint DEFAULT NULL
) RETURNS json
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET bytea_output = 'hex' AS $$
DECLARE
    r public.use_row;
    -- The principal's lock held: exclusive (`locked`), to enter its key in the cap's set; shared (`moving`), to move it on.
    locked boolean := false;
    moving boolean := false;
    probe boolean := p_known IS NULL OR p_cap_count IS NULL OR p_cap_window IS NULL;
    -- A use through a place, or of a key with no value of its own (a reference), reads every input; the others, most
    -- uses, the plain shape: no place, no source, none of their joins.
    whole boolean := p_place IS NOT NULL;
    -- The cached forms' refresh and period, from the cap the isolate passes; the probing forms work theirs out from the cap they read.
    c_refresh bigint := greatest(1, least(60000, p_cap_window / 10));
    c_period bigint := p_at - ((p_at % c_refresh) + c_refresh) % c_refresh;
    -- Whether this session has yet to plan the four statements (T131), and the form the warm-up is at.
    dry boolean := current_setting('coffre.use_planned', true) IS DISTINCT FROM '0028';
    form integer := 0;
    first_probe boolean;
    first_whole boolean;
    -- The period this call writes, if it writes the cap's row, and the lock that elects the one use that moves it.
    b_refresh bigint;
    b_period bigint;
    b_lock bigint;
    b_round integer := 0;
BEGIN
    IF p_deadline IS NULL OR p_deadline > p_at + public.deadline_max() THEN r.state := 'late'; RETURN to_json(r); END IF;
    -- Its Worker's clock ahead by over a minute (0022 says why): checked here at no cost, and again in the statement.
    IF p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN r.state := 'ahead'; RETURN to_json(r); END IF;
    IF dry THEN
        -- Each form first runs dry, outside the fence, so that its plan is made before this call holds the fence.
        first_probe := probe;
        first_whole := whole;
        probe := true;
        whole := false;
    ELSE
        PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
    END IF;
    LOOP
        IF probe AND NOT whole THEN
            WITH i AS MATERIALIZED (
                SELECT n.number AS newest, n.mac AS newest_mac, coalesce(n.number = p_known AND n.mac = p_known_mac, false) AS cached,
                    f.at_floor, (lpol.payload::jsonb #>> '{value,bulk,count}')::integer AS cap_count, (lpol.payload::jsonb #>> '{value,bulk,windowMs}')::bigint AS cap_window,
                    lpol.number AS lpol_number, lpol.seal AS p_last,
                    c.principal AS p, c.kind AS c_kind, c.scope AS c_scope, c.revoked_at IS NOT NULL AS c_revoked,
                    floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
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
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh, cap.period,
                    CASE WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND i.bulk_last < cap.period THEN 'share' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, NULL::bytea AS x_last,
                    NULL::bytea AS e1_last, l2.seal AS e2_last, NULL::bytea AS e3_last, l4.seal AS e4_last,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, l2.number, l4.number), 0)
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, i.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, p_at - ((p_at % r0.refresh) + r0.refresh) % r0.refresh AS period) cap
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
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, v.inputs, true,
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
                    floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
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
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, cap.refresh, cap.period,
                    CASE WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.cap_count IS NULL OR i.cap_window IS NULL THEN 'unconfigured'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND i.bulk_last < cap.period THEN 'share' END AS state,
                    greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number) AS inputs,
                    lc.seal AS c_last, lm.seal AS m_last, (lm.payload::jsonb ->> 'old')::bigint AS m_old, lr.seal AS r_last, ls.seal AS s_last, lx.seal AS x_last,
                    l1.seal AS e1_last, l2.seal AS e2_last, l3.seal AS e3_last, l4.seal AS e4_last,
                    coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - i.cap_window - cap.refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - i.cap_window - cap.refresh - public.deadline_max() - 60000
                             LIMIT i.cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= cap.period AND p_cover > coalesce(greatest(lc.number, lm.number, lr.number, i.lpol_number, ls.number, lx.number, l1.number, l2.number, l3.number, l4.number), 0)
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
                  CROSS JOIN LATERAL (SELECT greatest(1, least(60000, i.cap_window / 10)) AS refresh) r0
                  CROSS JOIN LATERAL (SELECT r0.refresh, p_at - ((p_at % r0.refresh) + r0.refresh) % r0.refresh AS period) cap
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
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, v.inputs, true,
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
                    floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
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
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, c_refresh AS refresh, c_period AS period,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         WHEN i.s_project IS NOT NULL AND i.s_version IS NULL THEN 'whole'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND i.bulk_last < c_period THEN 'share' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - p_cap_window - c_refresh - public.deadline_max() - 60000
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= c_period
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  -- The isolate held its cover to the cached seals' numbers when it read them.
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, NULL::bigint, false,
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
                    floor(extract(epoch FROM least(c.expires_at, c.not_after)) * 1000)::bigint AS c_expires, c.seal AS c_seal,
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
                 WHERE NOT dry
            ),
            v AS MATERIALIZED (
                SELECT i.*, c_refresh AS refresh, c_period AS period,
                    CASE WHEN NOT i.cached THEN 'reprobe'
                         WHEN i.at_floor IS NULL OR p_at < i.at_floor OR (extract(epoch FROM clock_timestamp()) * 1000)::bigint > p_deadline THEN 'late'
                         WHEN p_at > (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000 THEN 'ahead'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN 'lock'
                         WHEN i.p IS NOT NULL AND NOT locked AND NOT moving AND i.bulk_last < c_period THEN 'share' END AS state,
                    coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) AS is_in,
                    -- The other keys in the set, up to the cap: read only under the principal's lock, for a key not in it.
                    CASE WHEN locked AND i.p IS NOT NULL AND NOT coalesce(i.bulk_last > p_at - p_cap_window - c_refresh, false) THEN (
                        SELECT count(*)::integer FROM (
                            SELECT 1 FROM public.log_bulk o
                             WHERE o.principal = i.p AND o.secret <> p_secret AND o.last > p_at - p_cap_window - c_refresh - public.deadline_max() - 60000
                             LIMIT p_cap_count
                        ) z
                    ) ELSE 0 END AS n_others,
                    -- A repeat rides its cover only while every part of this holds: never on a key whose bulk row is missing (CoverFresh).
                    coalesce(p_cover IS NOT NULL AND i.bulk_last >= c_period
                        AND EXISTS (SELECT 1 FROM public.log_uses u WHERE u.at = p_cover_at AND u.request_id = p_cover_request AND u.number = p_cover
                            AND u.credential = p_credential AND u.secret = p_secret AND u.purpose = p_purpose AND u.place IS NOT DISTINCT FROM p_place), false) AS is_covered
                  FROM i
            ),
            w AS (
                INSERT INTO public.log_uses (number, at, request_id, credential, secret, purpose, mac, place)
                SELECT nextval('public.log_number'), p_at, p_request, p_credential, p_secret, p_purpose, p_mac, p_place
                  -- The isolate held its cover to the cached seals' numbers when it read them.
                  FROM v WHERE v.state IS NULL AND NOT v.is_covered
                RETURNING log_uses.number
            )
            SELECT v.state, (SELECT w.number FROM w), CASE WHEN v.state IS NULL AND v.is_covered THEN p_cover END, v.newest, v.newest_mac, NULL::bigint, false,
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
        IF dry THEN
            -- The forms in turn: probing plain, probing whole, cached plain, cached whole; then the call itself, under the fence.
            form := form + 1;
            IF form < 4 THEN
                probe := form < 2;
                whole := form % 2 = 1;
                CONTINUE;
            END IF;
            PERFORM set_config('coffre.use_planned', '0028', false);
            dry := false;
            probe := first_probe;
            whole := first_whole;
            PERFORM pg_advisory_xact_lock_shared(1668244070, 0);
            CONTINUE;
        END IF;
        -- A use the statement took writes its entry or rides its cover, never neither.
        IF r.state IS NULL AND r.number IS NULL AND r.covered IS NULL THEN
            RAISE EXCEPTION 'a use wrote no entry and rode no cover' USING ERRCODE = 'XX000';
        END IF;
        IF r.state = 'reprobe' THEN probe := true; CONTINUE; END IF;
        IF r.state = 'whole' THEN whole := true; CONTINUE; END IF;
        EXIT WHEN r.state IS DISTINCT FROM 'lock' AND r.state IS DISTINCT FROM 'share';
        -- Its key's bulk row is missing or out of the set: this use may enter it, so it takes its principal's lock exclusive
        -- and reads again. Or the row is in the set, from an earlier period: this use may move it on, so it takes the lock
        -- shared, beside the principal's other uses that move a key on, and reads again.
        -- Holding it shared, a key never leaves the set (SharedStaysInSet) unless a row was put back under it: then the
        -- call ends, refused as late, rather than ask for the lock exclusive while it holds it shared (two such would
        -- deadlock).
        IF r.state = 'lock' AND moving THEN
            RAISE EXCEPTION 'its key left the cap''s set under the principal''s lock: a row put back' USING ERRCODE = '57014';
        END IF;
        IF r.state = 'lock' THEN
            PERFORM pg_advisory_xact_lock(1668244066, hashtext(r.c_principal));
            locked := true;
        ELSE
            PERFORM pg_advisory_xact_lock_shared(1668244066, hashtext(r.c_principal));
            moving := true;
        END IF;
    END LOOP;
    -- The cap's row, written only by a call that took the principal's lock, in a statement of its own after the one that
    -- read, in the same transaction, under the same locks: the uses that read their key fresh, nearly all, run no write.
    -- A key in the set moves on to this use's period, only ever up. A key entering the set, under the lock exclusive, is
    -- made or moved on from a window past. Every request counts, whatever the Worker then decides but the cap (HotPathOneStaleBulk).
    IF r.state IS NULL AND (locked OR moving) THEN
        b_refresh := greatest(1, least(60000, r.cap_window / 10));
        b_period := p_at - ((p_at % b_refresh) + b_refresh) % b_refresh;
        IF r.in_set THEN
            -- One use moves the key to this period: the one that takes a lock of the key and period's own without waiting.
            -- The others take it shared, which waits only for that one's end, never for each other, and read the row again,
            -- locking none: moved, they leave it. An UPDATE that waits on a row another is moving, then finds it moved,
            -- keeps the row locked to its own commit, and queues the next. If the one moving it rolled back, the others
            -- elect another the same way, on the lock's next round.
            LOOP
                b_lock := hashtextextended(r.c_principal || '/' || p_secret::text || '/' || b_period::text || '/' || b_round::text, 1668244066);
                IF pg_try_advisory_xact_lock(b_lock) THEN
                    UPDATE public.log_bulk SET last = b_period WHERE principal = r.c_principal AND secret = p_secret AND last < b_period;
                    EXIT;
                END IF;
                PERFORM pg_advisory_xact_lock_shared(b_lock);
                EXIT WHEN NOT EXISTS (SELECT 1 FROM public.log_bulk WHERE principal = r.c_principal AND secret = p_secret AND last < b_period);
                b_round := b_round + 1;
            END LOOP;
        ELSIF r.others < r.cap_count THEN
            INSERT INTO public.log_bulk (principal, secret, last) VALUES (r.c_principal, p_secret, b_period)
                ON CONFLICT ON CONSTRAINT log_bulk_pkey DO UPDATE SET last = greatest(log_bulk.last, EXCLUDED.last);
        END IF;
    END IF;
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
