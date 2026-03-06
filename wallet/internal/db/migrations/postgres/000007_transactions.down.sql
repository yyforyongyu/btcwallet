-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected
-- state.
DROP TRIGGER IF EXISTS trg_set_coinbase_orphaned_on_disconnect ON transactions;
DROP TABLE IF EXISTS transactions;
DROP FUNCTION IF EXISTS set_coinbase_orphaned_on_disconnect();
