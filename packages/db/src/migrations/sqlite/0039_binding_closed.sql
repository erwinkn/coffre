-- 0.16.0, W331: postgres/0079_sign_in_shares.sql's columns: a binding closed by a removal under way, in batches, which signs nobody in, and by whom, for the scheduled run to name. Nullable; the previous release never reads them.
ALTER TABLE `service_bindings` ADD `closed_at` integer;--> statement-breakpoint
ALTER TABLE `service_bindings` ADD `closed_by` text;
