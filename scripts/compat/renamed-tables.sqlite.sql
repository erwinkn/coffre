-- pnpm test:compat (compat-check.sh), for a release from before 0.16.0's
-- table renames (T178) only, on SQLite: the tables back under the names that
-- release knows. Postgres keeps those names one release as views of the
-- renamed tables, and the release's code runs through them; SQLite, which no
-- deployment runs, keeps none (sqlite/0036_table_renames.sql says why), so the
-- release is held to everything else of this schema under its own names.
-- Each rename moves every reference to the table, as 0036's did. Delete this,
-- and its use, once 0.16.0 is the newest release.
ALTER TABLE `principals` RENAME TO `vault_members`;
ALTER TABLE `grants` RENAME TO `vault_grants`;
ALTER TABLE `device_logins` RENAME TO `device_authorizations`;
ALTER TABLE `enrollment_codes` RENAME TO `enrollments`;
ALTER TABLE `spent_id_tokens` RENAME TO `consumed_tokens`;
ALTER TABLE `bulk_cap` RENAME TO `log_bulk`;
ALTER TABLE `checkpoint_fence` RENAME TO `log_fence`;
