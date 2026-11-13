-- What schema.ts does not say of a database, one line each, sorted: every privilege on a table, a column or a
-- sequence, and each table's storage settings. scripts/test-upgrade.sh requires a database upgraded from 0.14 and one
-- migrated from nothing to agree on them.
SELECT line FROM (
  SELECT format('table %s.%s %s options %s', n.nspname, c.relname, coalesce((SELECT string_agg(acl::text, ' ' ORDER BY acl::text) FROM unnest(c.relacl) AS acl), '-'), coalesce(array_to_string(c.reloptions, ','), '-')) AS line
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'S')
  UNION ALL
  SELECT format('column %s.%s %s', c.relname, a.attname, (SELECT string_agg(acl::text, ' ' ORDER BY acl::text) FROM unnest(a.attacl) AS acl))
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND a.attacl IS NOT NULL
) AS lines ORDER BY line;
