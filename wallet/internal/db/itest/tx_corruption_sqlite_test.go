//go:build itest && !test_db_postgres

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// corruptTransactionStatus overwrites one stored transaction status while
// temporarily disabling sqlite check constraints.
func corruptTransactionStatus(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash, status int64) {
	t.Helper()

	tx, err := store.DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON")
	require.NoError(t, err)

	result, err := tx.ExecContext(
		t.Context(),
		"UPDATE transactions SET tx_status = ? WHERE wallet_id = ? AND tx_hash = ?",
		status, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = OFF")
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	require.NoError(t, tx.Commit())
}

// corruptTransactionHash overwrites one stored transaction hash while
// temporarily disabling sqlite check constraints.
func corruptTransactionHash(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash, hash []byte) {
	t.Helper()

	tx, err := store.DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON")
	require.NoError(t, err)

	result, err := tx.ExecContext(
		t.Context(),
		"UPDATE transactions SET tx_hash = ? WHERE wallet_id = ? AND tx_hash = ?",
		hash, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = OFF")
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	require.NoError(t, tx.Commit())
}

// corruptTransactionBlockHeight overwrites one stored transaction block height
// while temporarily disabling sqlite check constraints.
func corruptTransactionBlockHeight(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash, height int64) {
	t.Helper()

	tx, err := store.DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON")
	require.NoError(t, err)

	blockHash := RandomHash()
	_, err = tx.ExecContext(
		t.Context(),
		"INSERT INTO blocks (block_height, header_hash, block_timestamp) VALUES (?, ?, ?) "+
			"ON CONFLICT(block_height) DO UPDATE SET header_hash = excluded.header_hash, "+
			"block_timestamp = excluded.block_timestamp",
		height, blockHash[:], time.Now().Unix(),
	)
	require.NoError(t, err)

	result, err := tx.ExecContext(
		t.Context(),
		"UPDATE transactions SET block_height = ? WHERE wallet_id = ? AND tx_hash = ?",
		height, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = OFF")
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	require.NoError(t, tx.Commit())
}

// corruptUtxoOutputIndex overwrites one stored UTXO output index while
// temporarily disabling sqlite check constraints.
func corruptUtxoOutputIndex(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash, oldIndex uint32, newIndex int64) {
	t.Helper()

	tx, err := store.DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON")
	require.NoError(t, err)

	result, err := tx.ExecContext(
		t.Context(),
		"UPDATE utxos SET output_index = ? WHERE output_index = ? "+
			"AND tx_id = (SELECT id FROM transactions WHERE wallet_id = ? AND tx_hash = ?)",
		newIndex, int64(oldIndex), int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = OFF")
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	require.NoError(t, tx.Commit())
}

// corruptActiveLeaseLockID overwrites one active lease lock ID while
// temporarily disabling sqlite check constraints.
func corruptActiveLeaseLockID(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32, lockID []byte) {
	t.Helper()

	tx, err := store.DB().BeginTx(t.Context(), nil)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON")
	require.NoError(t, err)

	result, err := tx.ExecContext(
		t.Context(),
		"UPDATE utxo_leases SET lock_id = ? WHERE wallet_id = ? AND utxo_id = ("+
			"SELECT u.id FROM utxos u JOIN transactions t ON t.id = u.tx_id "+
			"WHERE t.wallet_id = ? AND t.tx_hash = ? AND u.output_index = ?)",
		lockID, int64(walletID), int64(walletID), txHash[:], int64(outputIndex),
	)
	require.NoError(t, err)

	_, err = tx.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = OFF")
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	require.NoError(t, tx.Commit())
}
