-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- utxo_leases stores transient application-level locks over wallet-owned UTXOs.
CREATE TABLE utxo_leases (
    -- Reference to the wallet that owns the leased UTXO.
    wallet_id BIGINT NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- The leased UTXO row.
    utxo_id BIGINT NOT NULL,

    -- Caller-provided lock ID. It must stay fixed-width so lease ownership can
    -- be compared without decoding application-specific payloads.
    lock_id BYTEA NOT NULL CHECK (length(lock_id) = 32),

    -- UTC-normalized lease expiration timestamp.
    expires_at TIMESTAMPTZ NOT NULL,

    -- Composite primary key is intentional: one wallet may hold at most one
    -- active lease row for a given UTXO.
    CONSTRAINT pidx_utxo_leases PRIMARY KEY (wallet_id, utxo_id),

    -- The leased output must belong to the same wallet-scoped UTXO set.
    CONSTRAINT fkey_utxo_leases_utxo FOREIGN KEY (wallet_id, utxo_id)
    REFERENCES utxos (wallet_id, id) ON DELETE CASCADE
);

-- Optimization for wallet-scoped lease cleanup and active-lease scans.
CREATE INDEX idx_utxo_leases_wallet_expires_at
ON utxo_leases (wallet_id, expires_at);
