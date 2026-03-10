-- name: AcquireUtxoLease :one
-- Acquires or renews a lease for an outpoint and returns the resulting
-- expiration time.
--
-- How:
-- - Resolves the outpoint to a current UTXO row and writes the lease in the
--   same statement.
-- - Rechecks that the outpoint is still unspent and its parent transaction is
--   still in a live state (`pending` or `published`) at write time.
-- - Uses one `INSERT .. ON CONFLICT DO UPDATE` statement so creation, renewal,
--   and expired-lease takeover all happen atomically.
-- Lease semantics:
-- - If the UTXO has no lease row, insert a new lease.
-- - If the UTXO has an expired lease, steal it.
-- - If the UTXO has an active lease with the same lock_id, renew it.
-- - If the UTXO has an active lease with a different lock_id, return no
--   rows (caller should treat this as "already leased").
--
-- NOTE: expires_at is computed by the caller as time.Now().UTC()+duration.
-- NewSqliteStore sets `_time_format=sqlite`, so the stored timestamp layout
-- matches SQLite's `current_timestamp` output for lexical comparisons.
-- Performance:
-- - SQLite executes the resolution and lease write atomically inside one
--   statement, which avoids stale-ID races between separate helper calls.
INSERT INTO utxo_leases (
    wallet_id,
    utxo_id,
    lock_id,
    expires_at
)
SELECT
    sqlc.arg('wallet_id') AS wallet_id,
    u.id AS utxo_id,
    sqlc.arg('lock_id') AS lock_id,
    sqlc.arg('expires_at') AS expires_at
FROM utxos AS u
INNER JOIN transactions AS t
    ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
WHERE
    u.wallet_id = sqlc.arg('wallet_id')
    AND t.tx_hash = sqlc.arg('tx_hash')
    AND u.output_index = sqlc.arg('output_index')
    AND u.spent_by_tx_id IS NULL
    AND t.status IN ('pending', 'published')
ON CONFLICT (wallet_id, utxo_id) DO UPDATE
SET
    lock_id = excluded.lock_id,
    expires_at = excluded.expires_at
WHERE
utxo_leases.expires_at <= current_timestamp
OR utxo_leases.lock_id = excluded.lock_id
RETURNING expires_at;

-- name: ReleaseUtxoLease :execrows
-- Releases a lease for a UTXO ID if the lock_id matches.
--
-- How:
-- - Deletes by wallet, utxo ID, and lock ID so one caller cannot release
--   another caller's active lease accidentally.
-- Performance:
-- - Targets at most one row through the unique lease key.
DELETE FROM utxo_leases
WHERE
    utxo_leases.wallet_id = ?1
    AND utxo_leases.utxo_id = ?2
    AND utxo_leases.lock_id = ?3;

-- name: GetActiveUtxoLeaseLockID :one
-- Returns the lock ID for the current active lease on a UTXO ID.
--
-- How:
-- - Reads only non-expired lease rows so callers can distinguish an active
--   lock-ID mismatch from an already-unlocked output.
-- Performance:
-- - Targets at most one row through the unique lease key.
SELECT lock_id
FROM utxo_leases
WHERE
    wallet_id = ?1
    AND utxo_id = ?2
    AND expires_at > current_timestamp;

-- name: ListActiveUtxoLeases :many
-- Lists all currently active leases for a wallet.
--
-- How:
-- - Starts from utxo_leases, then joins utxos and transactions on
--   `(wallet_id, id)` so the result can be returned as network outpoints.
-- - Filters out expired rows inside the query.
-- - Restricts the result to outputs that are still unspent and whose parent
--   transaction is still in a live state (`pending` or `published`).
-- Performance:
-- - Restricts first by wallet and expiration, then joins only the surviving
--   lease rows back to utxos/transactions.
SELECT
    t.tx_hash,
    u.output_index,
    l.lock_id,
    l.expires_at
FROM utxo_leases AS l
INNER JOIN utxos AS u
    ON l.wallet_id = u.wallet_id AND l.utxo_id = u.id
INNER JOIN transactions AS t
    ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
WHERE
    l.wallet_id = ?1
    AND l.expires_at > current_timestamp
    AND u.spent_by_tx_id IS NULL
    AND t.status IN ('pending', 'published')
ORDER BY l.expires_at;

-- name: DeleteExpiredUtxoLeases :execrows
-- Deletes all expired lease rows for a wallet.
--
-- How:
-- - Removes only rows whose expiration has passed, leaving active leases
--   untouched.
-- Performance:
-- - Uses the expiration predicate together with wallet scoping to bound the
--   cleanup pass.
DELETE FROM utxo_leases
WHERE wallet_id = ?1 AND expires_at <= current_timestamp;
