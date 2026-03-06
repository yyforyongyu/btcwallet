-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if view is already dropped or database is in unexpected
-- state.
DROP VIEW IF EXISTS spendable_utxos;
