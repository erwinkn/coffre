-- 0.16.0, T204: postgres/0074_bulk_phase.sql's column. Whether the use's decision started its key's refresh periods at the key's phase (`phaseOf`, packages/vault/src/bulk.ts): 1 from this release's on, null before, whose periods all start together; the log's replay moves the cap as the decision did.
ALTER TABLE `log_uses` ADD `phased` integer;
