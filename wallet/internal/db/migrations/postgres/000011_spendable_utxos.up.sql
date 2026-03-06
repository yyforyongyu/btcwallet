-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Spendable UTXOs view joins unspent utxos with parent transaction metadata.
--
-- NOTE: The view intentionally does not bake in policy decisions such as
-- pending chaining, lease exclusion, or maturity filtering. Callers should use
-- tx_status, block_height, and is_coinbase to apply those rules explicitly.
-- It is currently a convenience view for ad-hoc inspection and simple helper
-- queries rather than the canonical source for sqlc-generated reads.
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
    u.spent_by_tx_id IS NULL;
