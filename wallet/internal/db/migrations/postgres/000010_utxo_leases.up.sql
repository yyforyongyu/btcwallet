-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- UTXO leases table provides time-based output locks.
CREATE TABLE utxo_leases (
    -- Reference to the wallet that owns this lease row.
    wallet_id BIGINT NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- DB ID of the lease row, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Secondary unique constraint used for wallet-scoped foreign keys.
    CONSTRAINT uidx_utxo_leases_wallet_id_id UNIQUE (wallet_id, id),

    -- Reference to the leased UTXO.
    utxo_id BIGINT NOT NULL,

    -- External lease ID (32 bytes).
    lock_id BYTEA NOT NULL CHECK (length(lock_id) = 32),

    -- Lease expiration timestamp stored in UTC without timezone metadata.
    --
    -- NOTE: Read/write queries normalize both inputs and current-time
    -- comparisons to UTC explicitly because this column intentionally uses
    -- TIMESTAMP rather than TIMESTAMPTZ.
    expires_at TIMESTAMP NOT NULL,

    -- Enforce at most one active lease row per UTXO.
    CONSTRAINT uidx_utxo_leases_utxo UNIQUE (wallet_id, utxo_id),

    -- Delete lease rows with their parent UTXO so lock state never outlives
    -- the output it refers to.
    CONSTRAINT fkey_utxo_leases_utxo
    FOREIGN KEY (wallet_id, utxo_id)
    REFERENCES utxos (wallet_id, id) ON DELETE CASCADE
);

-- Optimization for lease expiration checks.
CREATE INDEX idx_utxo_leases_expires_at ON utxo_leases (expires_at);
