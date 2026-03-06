-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected
-- state.
DROP TABLE IF EXISTS tx_replacements;
