-- An issuer's keys, uploaded with a binding where coffre fetches none. The app inserts them with the binding, under its table-wide INSERT, and no UPDATE grant names them: they never change in place.
ALTER TABLE "service_bindings" ADD COLUMN "jwks" text;
