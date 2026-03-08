-- name: InsertTransaction :one
-- Inserts a wallet-scoped transaction row and returns its database ID.
--
-- How:
-- - Writes only the transactions table.
-- - Expects the caller to have already resolved wallet scope and any optional
--   block reference.
-- - Expects the caller to supply the initial status explicitly so unmined rows
--   do not have to guess between `pending` and `published`.
-- Performance:
-- - Single-row insert. The cost is dominated by the wallet/hash uniqueness
--   checks and any optional block foreign-key validation.
INSERT INTO transactions (
    wallet_id,
    tx_hash,
    raw_tx,
    block_height,
    status,
    received_time,
    is_coinbase,
    label
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING id;

-- name: GetTransactionMetaByHash :one
-- Retrieves the primary key and lightweight transaction metadata.
--
-- How:
-- - Reads only the transactions table because callers only need row identity
--   plus lightweight status/label fields.
-- Performance:
-- - Uses the wallet-scoped unique `(wallet_id, tx_hash)` lookup path.
SELECT
    id,
    block_height,
    is_coinbase,
    status,
    label
FROM transactions
WHERE wallet_id = ? AND tx_hash = ?;

-- name: GetTransactionByHash :one
-- Retrieves the full transaction row along with optional block metadata.
--
-- How:
-- - Looks up the transaction by `(wallet_id, tx_hash)`.
-- - LEFT JOINs blocks on `block_height` so the same query handles mined and
--   unmined rows.
-- Performance:
-- - The unique transaction lookup limits the join fanout to at most one block
--   row.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.status,
    t.label
FROM transactions AS t
LEFT JOIN blocks AS b ON t.block_height = b.block_height
WHERE t.wallet_id = ? AND t.tx_hash = ?;

-- name: ListUnminedTransactions :many
-- Lists all unconfirmed transactions for a wallet.
--
-- How:
-- - Reads from transactions only and returns every blockless row, including
--   invalid history states such as `failed`, `replaced`, and `orphaned`.
-- - Leaves it to higher layers to decide whether they want the full blockless
--   history view or only the live mempool subset.
-- - Returns NULL block metadata explicitly because unmined rows have no
--   block.
-- Performance:
-- - Matches the partial unconfirmed index and orders by received time for a
--   wallet-scoped blockless-history read.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.status,
    t.label
FROM transactions AS t
-- The always-false join projects typed NULL block columns for SQLite.
LEFT JOIN blocks AS b ON 1 = 0
WHERE
    t.wallet_id = ?
    AND t.block_height IS NULL
ORDER BY t.received_time DESC, t.id DESC;

-- name: ListTransactionsByHeightRange :many
-- Lists all confirmed transactions for a wallet in the provided height range.
--
-- How:
-- - Reads transactions in a wallet-scoped block-height range.
-- - INNER JOINs blocks on the natural `block_height` key to hydrate block hash
--   and timestamp for confirmed rows.
-- Performance:
-- - The `(wallet_id, block_height)` index bounds the scan before the single-row
--   block join.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.status,
    t.label
FROM transactions AS t
INNER JOIN blocks AS b ON t.block_height = b.block_height
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND t.block_height >= sqlc.arg('start_height')
    AND t.block_height <= sqlc.arg('end_height')
ORDER BY t.block_height, t.id;

-- name: UpdateTransactionLabelByHash :execrows
-- Updates only the user-visible transaction label.
--
-- How:
-- - Leaves block assignment and status untouched.
-- - Exists for user-facing metadata edits only; wallet-internal state
--   transitions use dedicated helper queries.
-- Performance:
-- - Updates at most one row through the wallet-scoped unique tx-hash lookup.
UPDATE transactions
SET label = sqlc.arg('label')
WHERE
    wallet_id = sqlc.arg('wallet_id')
    AND tx_hash = sqlc.arg('tx_hash');

-- name: UpdateTransactionStatusByIDs :execrows
-- Updates the wallet-relative status for a set of transaction row IDs.
--
-- How:
-- - Exists for wallet-internal replacement and invalidation flows after the
--   caller has already identified the affected rows.
-- - Leaves block assignment untouched; rollback/disconnect continues to use the
--   dedicated rewind helpers below.
-- Performance:
-- - Restricts by wallet scope first, then matches only the provided ID set.
UPDATE transactions
SET status = sqlc.arg('status')
WHERE
    wallet_id = sqlc.arg('wallet_id')
    AND id IN (sqlc.slice('tx_ids'));

-- name: ReconfirmOrphanedCoinbaseByHash :execrows
-- Restores one orphaned coinbase transaction to the best chain.
--
-- How:
-- - Updates `block_height` and `status` in the same statement so coinbase rows
--   never pass through an invalid unconfirmed state.
-- - Restricts the update to rows that are already orphaned coinbase
--   transactions within the requested wallet.
-- Performance:
-- - Targets at most one row through the wallet-scoped unique tx-hash lookup.
UPDATE transactions
SET
    block_height = ?1,
    status = 'published'
WHERE
    wallet_id = ?2
    AND tx_hash = ?3
    AND is_coinbase
    AND block_height IS NULL
    AND status = 'orphaned';

-- name: DeleteUnminedTransactionByHash :execrows
-- Deletes an unconfirmed transaction row.
--
-- How:
-- - Deletes only rows whose `block_height` is still NULL and whose status is
--   still in a live unconfirmed state (`pending` or `published`).
-- - Preserves orphaned/replaced/failed history; those rows must remain visible
--   for audit/reorg handling instead of being treated as ordinary mempool data.
-- - The caller must delete or restore dependent UTXO rows first.
-- Performance:
-- - Targets at most one row by `(wallet_id, tx_hash)`.
DELETE FROM transactions
WHERE
    wallet_id = ?
    AND tx_hash = ?
    AND block_height IS NULL
    AND status IN ('pending', 'published');

-- name: ClampWalletSyncStateHeightsForRollback :execrows
-- Rewrites wallet sync-state heights so they stop referencing blocks that are
-- about to be deleted during RollbackToBlock.
--
-- How:
-- - Updates wallet_sync_states directly without joining other tables.
-- - Rewrites both synced_height and birthday_height in one statement so the
--   subsequent block delete does not violate `ON DELETE RESTRICT`.
-- Performance:
-- - Touches only wallet_sync_states rows whose heights are at or above the
--   rollback boundary.
UPDATE wallet_sync_states
SET
    synced_height = CASE
        WHEN
            synced_height IS NOT NULL
            AND synced_height >= sqlc.arg('rollback_height')
            THEN sqlc.arg('new_height')
        ELSE synced_height
    END,
    birthday_height = CASE
        WHEN
            birthday_height IS NOT NULL
            AND birthday_height >= sqlc.arg('rollback_height')
            THEN sqlc.arg('new_height')
        ELSE birthday_height
    END,
    updated_at = current_timestamp
WHERE
    (
        synced_height IS NOT NULL
        AND synced_height >= sqlc.arg('rollback_height')
    )
    OR (
        birthday_height IS NOT NULL
        AND birthday_height >= sqlc.arg('rollback_height')
    );

-- name: ListCoinbaseRollbackRootsAtOrAboveHeight :many
-- Lists the coinbase transaction rows that will become orphan roots during
-- rollback.
--
-- How:
-- - Reads only wallet scope and row identity for confirmed coinbase
--   transactions at or above the rollback height.
-- - Lets RollbackToBlock collect the orphan roots before block deletion and
--   then run descendant invalidation in the same SQL transaction.
-- Performance:
-- - Rare rollback helper. The scan is bounded by the rollback height and only
--   returns lightweight row identifiers.
SELECT
    wallet_id,
    id
FROM transactions
WHERE
    is_coinbase
    AND block_height >= ?
ORDER BY wallet_id, id;

-- name: DeleteBlocksAtOrAboveHeight :execrows
-- Deletes blocks at and after the provided height.
--
-- How:
-- - Deletes directly from blocks by the natural height key.
-- - Relies on FK/trigger side effects to null transaction block references and
--   orphan coinbase roots.
-- - Expects RollbackToBlock to collect those roots before the delete and then
--   recursively fail descendants in the same transaction.
-- Performance:
-- - Executes as a range delete over the block-height primary key.
DELETE FROM blocks
WHERE block_height >= ?;
