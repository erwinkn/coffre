-- Per-call backend CPU, without protocol or parse cost (as W386's use-bench/bench_loop.sql): `calls` calls of one
-- function in a PL/pgSQL loop, on one pair of the seeded instance. Compare only within this tool.
CREATE OR REPLACE FUNCTION public.bench_pair(OUT cred uuid, OUT sec uuid, OUT ver uuid, OUT objects uuid[]) LANGUAGE sql AS $$
  SELECT c.id, s.id, s.current_version_id,
         ARRAY[log_object('credential', c.id::text), log_object('principal', c.principal), log_object('roles', 'instance'), log_object('policy', 'instance'),
               log_object('secret', s.id::text), log_object('environment', s.environment_id::text)]::uuid[]
    FROM credentials c JOIN grants g ON g.principal = c.principal JOIN secrets s ON s.environment_id = g.environment_id AND s.current_version_id IS NOT NULL
   ORDER BY c.id, s.id LIMIT 1 $$;
CREATE OR REPLACE FUNCTION public.bench_loop_w396(fn text, calls integer) RETURNS text LANGUAGE plpgsql AS $$
DECLARE p record; n bigint; m bytea; at0 bigint; st text; k int; cn bigint; creq bigint := (random()*1e15)::bigint;
BEGIN
  SELECT * INTO p FROM bench_pair();
  SELECT number, mac INTO n, m FROM log_changes ORDER BY number DESC LIMIT 1;
  at0 := (extract(epoch from clock_timestamp())*1000)::bigint;
  IF fn = 'use_ride' THEN
    SELECT h.number INTO cn FROM use_hot(ROW(NULL, at0, creq, p.cred, p.sec, 4::smallint, gen_random_bytes(16), NULL::uuid, NULL::text, true)::log_uses, p.ver, n, m, p.objects, at0 + 3000) h;
  END IF;
  FOR k IN 1..calls LOOP
    IF fn LIKE 'use_credential%' THEN
      EXECUTE format('SELECT %I($1,$2,$3,$4,4::smallint,NULL,$5,$6,NULL,NULL,NULL,$7,$8,1000,900000,p_decided=>true)->>''state''', fn)
        INTO st USING p.cred, p.sec, (random()*1e15)::bigint, at0, gen_random_bytes(16), at0 + 3000, n, m;
    ELSIF fn = 'use_ride' THEN
      EXECUTE 'SELECT state FROM use_ride(ROW($1, $2, $3, $4, $5, 4::smallint, NULL::bytea, NULL::uuid, NULL::text, true)::log_uses, $2, $6, $7, $8, $9, $2 + 3000)'
        INTO st USING cn, at0, creq, p.cred, p.sec, p.ver, n, m, p.objects;
    ELSE
      EXECUTE format('SELECT state FROM %I(ROW(NULL, $1, $2, $3, $4, 4::smallint, $5, NULL::uuid, NULL::text, true)::log_uses, $6, $7, $8, $9, $1 + 3000)', fn)
        INTO st USING at0, (random()*1e15)::bigint, p.cred, p.sec, gen_random_bytes(16), p.ver, n, m, p.objects;
    END IF;
  END LOOP;
  RETURN coalesce(st, 'made');
END $$;
