//go:build itest && !test_db_postgres

package itest

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
	"github.com/stretchr/testify/require"
)

// NewTestStore creates a new SQLite database for testing with migrations
// applied. Each test gets its own temporary database file.
func NewTestStore(t *testing.T) *db.SqliteStore {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := db.SqliteConfig{
		DBPath:         dbPath,
		MaxConnections: 0,
	}

	store, err := db.NewSqliteStore(t.Context(), cfg)
	require.NoError(t, err, "failed to create sqlite store")

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

// childSpendingTxIDs returns the direct child transaction IDs recorded for the
// provided parent transaction hash.
func childSpendingTxIDs(t *testing.T, store *db.SqliteStore, walletID uint32,
	txHash chainhash.Hash) []int64 {

	t.Helper()

	meta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	require.NoError(t, err)

	childIDs, err := store.Queries().ListSpendingTxIDsByParentTxID(
		t.Context(), sqlcsqlite.ListSpendingTxIDsByParentTxIDParams{
			WalletID: int64(walletID),
			TxID:     meta.ID,
		},
	)
	require.NoError(t, err)

	ids := make([]int64, 0, len(childIDs))
	for _, childID := range childIDs {
		require.True(t, childID.Valid)
		ids = append(ids, childID.Int64)
	}

	return ids
}

// insertConflictingRegularTx inserts one live regular transaction row plus any
// credited wallet-owned outputs without claiming wallet spend edges.
func insertConflictingRegularTx(t *testing.T, store *db.SqliteStore,
	walletID uint32, tx *wire.MsgTx, received time.Time, status db.TxStatus,
	credits map[uint32]btcutil.Address) {

	t.Helper()

	var raw bytes.Buffer
	err := tx.Serialize(&raw)
	require.NoError(t, err)

	err = store.ExecuteTx(t.Context(), func(qtx *sqlcsqlite.Queries) error {
		txHash := tx.TxHash()
		txID, err := qtx.InsertTransaction(
			t.Context(), sqlcsqlite.InsertTransactionParams{
				WalletID:     int64(walletID),
				TxHash:       txHash[:],
				RawTx:        raw.Bytes(),
				BlockHeight:  sql.NullInt64{},
				TxStatus:     int64(status),
				ReceivedTime: received.UTC(),
				IsCoinbase:   false,
				TxLabel:      "",
			},
		)
		if err != nil {
			return err
		}

		for index := range credits {
			addressID := getAddressID(
				t, qtx, tx.TxOut[index].PkScript, walletID,
			)

			_, err = qtx.InsertUtxo(
				t.Context(), sqlcsqlite.InsertUtxoParams{
					WalletID:    int64(walletID),
					TxID:        txID,
					OutputIndex: int64(index),
					Amount:      tx.TxOut[index].Value,
					AddressID:   addressID,
				},
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	require.NoError(t, err)
}

func insertReplacementEdge(t *testing.T, store *db.SqliteStore, walletID uint32,
	replacedTxid chainhash.Hash, replacementTxid chainhash.Hash) {

	t.Helper()

	replacedMeta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   replacedTxid[:],
		},
	)
	require.NoError(t, err)

	replacementMeta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   replacementTxid[:],
		},
	)
	require.NoError(t, err)

	_, err = store.Queries().InsertTxReplacementEdge(
		t.Context(), sqlcsqlite.InsertTxReplacementEdgeParams{
			WalletID:        int64(walletID),
			ReplacedTxID:    replacedMeta.ID,
			ReplacementTxID: replacementMeta.ID,
		},
	)
	require.NoError(t, err)
}

func forceOrphanedCoinbaseTx(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET block_height = NULL, tx_status = ? "+
			"WHERE wallet_id = ? AND tx_hash = ?",
		int64(db.TxStatusOrphaned), int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

func corruptTransactionRawTx(t *testing.T, store *db.SqliteStore,
	walletID uint32, txHash chainhash.Hash, rawTx []byte) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET raw_tx = ? WHERE wallet_id = ? AND tx_hash = ?",
		rawTx, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

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
