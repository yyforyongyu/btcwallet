-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- spendable_utxos is the wallet's spend-candidate base view over the live
-- unspent set.
--
-- It exposes parent transaction metadata (`block_height`, `is_coinbase`,
-- `tx_status`) but deliberately leaves caller policy out of the view:
--   - pending parents remain visible for zero-latency chaining use cases
--   - active leases are NOT excluded here
--   - coinbase maturity is NOT enforced here
CREATE VIEW spendable_utxos AS
SELECT
    u.wallet_id,
    u.id,
    u.tx_id,
    u.output_index,
    u.amount,
    u.address_id,
    t.block_height,
    t.is_coinbase,
    t.status AS tx_status
FROM utxos AS u
INNER JOIN transactions AS t
    ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
WHERE
    u.spent_by_tx_id IS NULL
    AND t.status IN ('pending', 'published');
