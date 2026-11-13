-- A database's schema, one line per column, constraint, index, trigger, function and policy, sorted: what scripts/test-upgrade.sh
-- compares between a database upgraded from 0.14, one migrated from nothing and one made from schema.ts.
SELECT line FROM (
  SELECT format('column %s.%s %s%s%s%s', c.relname, a.attname, format_type(a.atttypid, a.atttypmod),
           CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END,
           coalesce(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), ''),
           CASE WHEN a.attidentity <> '' THEN ' IDENTITY ' || a.attidentity::text ELSE '' END || CASE WHEN a.attgenerated <> '' THEN ' GENERATED' ELSE '' END) AS line
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
   WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT format('constraint %s.%s %s', c.relname, k.conname, pg_get_constraintdef(k.oid))
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
  UNION ALL
  SELECT format('index %s', pg_get_indexdef(i.indexrelid))
    FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.indexrelid)
  UNION ALL
  SELECT format('trigger %s', tgname) FROM pg_trigger WHERE NOT tgisinternal
  UNION ALL
  SELECT format('function %s', p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
  UNION ALL
  SELECT format('policy %s', polname) FROM pg_policy
  UNION ALL
  SELECT format('rls %s', relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND relrowsecurity
) AS lines ORDER BY line;
