-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Transactions table stores wallet-scoped blockchain transactions and their
-- wallet-relative validity/confirmation state.
CREATE TABLE transactions (
    -- Reference to the wallet that owns this transaction row.
    wallet_id BIGINT NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- DB ID of the transaction, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Secondary unique constraint used for wallet-scoped foreign keys.
    CONSTRAINT uidx_transactions_wallet_id_id UNIQUE (wallet_id, id),

    -- Transaction hash (txid) (32 bytes). Unique per wallet.
    tx_hash BYTEA NOT NULL CHECK (length(tx_hash) = 32),

    -- Raw serialized transaction bytes.
    --
    -- NOTE: Hot-path queries (balance/coin selection) SHOULD avoid selecting
    -- this column.
    raw_tx BYTEA NOT NULL,

    -- Confirmation state:
    -- NULL = Unconfirmed (mempool)
    -- INT  = Confirmed (mined)
    --
    -- ON DELETE SET NULL: If a block is reorged, the transaction becomes
    -- unconfirmed.
    block_height INTEGER REFERENCES blocks (block_height) ON DELETE SET NULL,

    -- Validity state (soft deletion).
    --
    -- NOTE: `status` is the intentional schema/API name from ADR 0006 and the
    -- Go TxStatus types. Keep the local `-- noqa: RF04` SQLFluff suppression so
    -- linting does not force a rename away from that shared contract.
    -- Regular store writes still pass status explicitly; this default is only a
    -- defensive fallback for raw SQL paths that omit the column.
    status TEXT NOT NULL DEFAULT 'pending', -- noqa: RF04

    -- Absolute wall clock time, supplied by the caller and stored in UTC
    -- without timezone info.
    --
    -- NOTE: There is intentionally no DEFAULT current_timestamp here because
    -- import/recovery flows may need to preserve the wallet-observed receive
    -- time instead of the row insertion time.
    received_time TIMESTAMP NOT NULL,

    -- Whether this transaction is a coinbase transaction.
    is_coinbase BOOLEAN NOT NULL DEFAULT FALSE,

    -- Optional user-provided label. Empty string means "no label".
    --
    -- NOTE: `label` is kept to match the existing TxInfo contract, so the
    -- local `-- noqa: RF04` SQLFluff suppression is intentional rather than a
    -- generic lint skip.
    label TEXT NOT NULL DEFAULT '', -- noqa: RF04

    -- Wallet-scoped uniqueness lets different wallets record the same network
    -- txid independently while keeping every child lookup anchored to one
    -- wallet.
    CONSTRAINT uidx_transactions_hash UNIQUE (wallet_id, tx_hash),

    -- Keep the persisted validity state closed over the finite set of states
    -- the store knows how to interpret and transition between.
    CONSTRAINT valid_status CHECK (
        status IN ('pending', 'published', 'replaced', 'failed', 'orphaned')
    ),

    -- Non-coinbase transactions cannot enter the orphaned state. That state is
    -- reserved for coinbase rows that were disconnected from the best chain.
    CONSTRAINT check_orphaned_coinbase_only CHECK (
        status != 'orphaned' OR is_coinbase
    ),

    -- A transaction attached to a block must still be part of the wallet's
    -- active best-chain view.
    CONSTRAINT check_confirmed_published CHECK (
        block_height IS NULL OR status = 'published'
    ),

    -- Coinbase transactions cannot exist in the local-only pre-broadcast state
    -- because they are created by mining, not by wallet authorship.
    CONSTRAINT check_coinbase_not_pending CHECK (
        NOT (is_coinbase AND status = 'pending')
    ),

    -- Coinbase rows may only be recorded in their mined form or in the
    -- orphaned form produced by a disconnect/reorg transition.
    CONSTRAINT check_coinbase_confirmation_state CHECK (
        NOT is_coinbase
        OR (block_height IS NOT NULL AND status = 'published')
        OR (block_height IS NULL AND status = 'orphaned')
    )
);

-- Optimization for mempool lookups.
CREATE INDEX idx_transactions_unconfirmed
ON transactions (wallet_id, block_height)
WHERE block_height IS NULL;

-- Optimization for "all transactions in block X" queries.
CREATE INDEX idx_transactions_by_block
ON transactions (wallet_id, block_height)
WHERE block_height IS NOT NULL;

-- Optimization for "latest transactions" queries.
CREATE INDEX idx_transactions_by_received_time
ON transactions (wallet_id, received_time DESC);

-- Reorg handling for coinbase transactions.
--
-- PostgreSQL checks CHECK constraints immediately. When a block is deleted, the
-- ON DELETE SET NULL action updates referencing transactions.block_height to
-- NULL. For coinbase transactions, we must also rewrite status to 'orphaned'
-- atomically to satisfy check_coinbase_confirmation_state.
--
-- NOTE: This trigger only rewrites the disconnected coinbase root. Rollback
-- code must still collect those roots and recursively fail descendants in the
-- surrounding SQL transaction.
CREATE FUNCTION set_coinbase_orphaned_on_disconnect() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.block_height IS NULL AND OLD.block_height IS NOT NULL
        AND NEW.is_coinbase THEN
        NEW.status := 'orphaned';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_coinbase_orphaned_on_disconnect
BEFORE UPDATE OF block_height ON transactions
FOR EACH ROW
EXECUTE FUNCTION set_coinbase_orphaned_on_disconnect();
