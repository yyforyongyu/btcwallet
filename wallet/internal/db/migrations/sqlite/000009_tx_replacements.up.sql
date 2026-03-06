-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Tx replacements audit table tracks RBF/double-spend edges.
CREATE TABLE tx_replacements (
    -- Reference to the wallet that owns this audit row.
    wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- DB ID of the replacement edge, primary key (rowid-backed).
    id INTEGER PRIMARY KEY,

    -- Replaced transaction ID.
    replaced_tx_id INTEGER NOT NULL,

    -- Replacement transaction ID.
    replacement_tx_id INTEGER NOT NULL,

    -- Timestamp when the edge was created. Stored in UTC without timezone info.
    --
    -- NOTE: SQLite `current_timestamp` is already UTC, so the default is
    -- intentionally left unwrapped here.
    created_at DATETIME NOT NULL DEFAULT current_timestamp,

    -- Secondary unique constraint used for wallet-scoped foreign keys.
    CONSTRAINT uidx_tx_replacements_wallet_id_id UNIQUE (wallet_id, id),

    -- When the victim transaction is physically removed, its audit edges should
    -- disappear with it so traversal never points at dead rows.
    CONSTRAINT fkey_tx_replacements_replaced
    FOREIGN KEY (wallet_id, replaced_tx_id)
    REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,

    -- When the replacing transaction is removed, the edge is no longer
    -- meaningful and should be deleted atomically with that row.
    CONSTRAINT fkey_tx_replacements_replacement
    FOREIGN KEY (wallet_id, replacement_tx_id)
    REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,

    -- Self-replacement would collapse the edge graph and break descendant /
    -- victim traversal logic, so reject it at write time.
    CONSTRAINT check_not_self_replacement CHECK (
        replaced_tx_id != replacement_tx_id
    ),

    -- The audit table records a directed edge exactly once per wallet so graph
    -- traversals remain deterministic and idempotent inserts stay cheap.
    CONSTRAINT uidx_tx_replacements_edge UNIQUE (
        wallet_id, replaced_tx_id, replacement_tx_id
    )
);

-- Optimization for inverse replacement-edge traversal by replacement tx.
CREATE INDEX idx_tx_replacements_by_replacement
ON tx_replacements (wallet_id, replacement_tx_id);
