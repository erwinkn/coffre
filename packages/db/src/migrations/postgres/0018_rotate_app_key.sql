-- The app key's rotation (T105) signs every enrollment code again under the new key, as it does every other signed row. It only adds a grant: the release before writes no enrollment's MAC but at its insert.
GRANT UPDATE (auth_mac) ON enrollments TO coffre_app;
