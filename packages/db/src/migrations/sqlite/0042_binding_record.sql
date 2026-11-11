-- 0.17, T253 (docs/design/oidc.md, section 9.3): the claims a binding records, as on Postgres (0083_binding_record). Additive: a nullable column the previous release never reads. The vault's `change_bindings` is TypeScript on SQLite, which writes it.
ALTER TABLE `service_bindings` ADD `record` text;
