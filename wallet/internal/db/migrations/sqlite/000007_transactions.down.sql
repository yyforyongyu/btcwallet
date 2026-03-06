-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected
-- state.
DROP TRIGGER IF EXISTS trg_disconnect_transactions_before_block_delete;
DROP TABLE IF EXISTS transactions;
