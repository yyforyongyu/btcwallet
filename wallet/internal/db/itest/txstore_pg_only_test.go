//go:build itest && test_db_postgres

package itest

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/stretchr/testify/require"
)

// TestConcurrentTxAdmissionPostgres verifies that overlapping observations of
// one hash replay the first committed row instead of failing its unique key.
func TestConcurrentTxAdmissionPostgres(t *testing.T) {
	t.Parallel()

	for _, method := range []string{
		"CreateTx",
		"ApplyTxBatch",
		"ApplyScanBatch",
	} {
		t.Run(method, func(t *testing.T) {
			// Arrange: Hold an uncommitted matching transaction behind the
			// existing Wallet-row lock. Each public entry point must wait
			// before deciding whether that hash needs a new row.
			store := NewTestStore(t)
			walletID := newWallet(t, store, "concurrent-admission")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)

			var (
				barrier  *sql.Tx
				finished chan struct{}
			)
			defer func() {
				// Release partial setup and join any admitted operation on
				// fail-fast exits, including a failed readiness assertion.
				cancel()

				if barrier != nil {
					_ = barrier.Rollback()
				}

				if finished != nil {
					<-finished
				}
			}()

			barrier, err := store.DB().BeginTx(ctx, nil)
			require.NoError(t, err)

			queries := store.Queries().WithTx(barrier)
			_, err = queries.GetWalletForAccountCreation(
				ctx, int64(walletID),
			)
			require.NoError(t, err)

			tx := newRegularTx(
				[]wire.OutPoint{randomOutPoint()},
				[]*wire.TxOut{
					{
						Value:    1000,
						PkScript: []byte{0x51},
					},
				},
			)

			var raw bytes.Buffer
			require.NoError(t, tx.Serialize(&raw))
			hash := tx.TxHash()
			received := time.Unix(1710006000, 0).UTC()
			_, err = queries.InsertTransaction(
				ctx, sqlc.InsertTransactionParams{
					WalletID:     int64(walletID),
					TxHash:       hash[:],
					RawTx:        raw.Bytes(),
					TxStatus:     int16(db.TxStatusPending),
					ReceivedTime: received,
				},
			)
			require.NoError(t, err)

			params := db.CreateTxParams{
				WalletID: walletID,
				Tx:       tx,
				Received: received,
				Status:   db.TxStatusPending,
			}

			// Act: Overlap the public observation with the first writer,
			// using actual SQL lock activity to release it only after the
			// observation reaches the conflicting write boundary.
			result := make(chan error, 1)

			finished = make(chan struct{})
			go func() {
				defer close(finished)

				var admissionErr error
				switch method {
				case "CreateTx":
					admissionErr = store.CreateTx(ctx, params)
				case "ApplyTxBatch":
					admissionErr = store.ApplyTxBatch(
						ctx, db.TxBatchParams{
							WalletID:     walletID,
							Transactions: []db.CreateTxParams{params},
						},
					)
				case "ApplyScanBatch":
					admissionErr = store.ApplyScanBatch(
						ctx, db.ScanBatchParams{
							WalletID:     walletID,
							Transactions: []db.CreateTxParams{params},
						},
					)
				}

				result <- admissionErr
			}()

			require.Eventually(t, func() bool {
				var waiting int

				err := store.DB().QueryRowContext(ctx, `
					SELECT count(*) FROM pg_stat_activity
					WHERE datname = current_database()
					AND wait_event_type = 'Lock'`,
				).Scan(&waiting)

				return err == nil && waiting > 0
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, barrier.Commit())

			admissionErr := <-result

			// Assert: The public replay succeeds with exactly one intact
			// transaction; a blocked unique insert must not escape as an
			// error that would stall lnd's chain notification loop.
			require.NoError(t, admissionErr)

			stored, err := store.GetTx(ctx, db.GetTxQuery{
				WalletID: walletID,
				Txid:     hash,
			})
			require.NoError(t, err)
			require.Equal(t, db.TxStatusPending, stored.Status)
			require.Equal(t, raw.Bytes(), stored.SerializedTx)
			require.Equal(t, received, stored.Received)

			var count int

			err = store.DB().QueryRowContext(ctx, `
				SELECT count(*) FROM transactions
				WHERE wallet_id = $1 AND tx_hash = $2`,
				int64(walletID), hash[:],
			).Scan(&count)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}

// TestCreateTxRejectsBlockHeightOverflowPostgres verifies postgres-specific
// block-height conversion failures surface before insert.
func TestCreateTxRejectsBlockHeightOverflowPostgres(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-overflow-height-pg")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710005000, 0),
			Block: &db.Block{
				Height:    ^uint32(0),
				Hash:      RandomHash(),
				Timestamp: time.Unix(1710005001, 0),
			},
			Status: db.TxStatusPublished,
		},
	)
	require.ErrorContains(t, err, "convert block height")
}

// TestListTxnsRejectHeightOverflowPostgres verifies postgres-specific height
// conversion failures for confirmed transaction listings.
func TestListTxnsRejectHeightOverflowPostgres(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-height-overflow-pg")

	_, err := store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: ^uint32(0),
			EndHeight:   0,
		},
	)
	require.ErrorContains(t, err, "convert start height")

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: 0,
			EndHeight:   ^uint32(0),
		},
	)
	require.ErrorContains(t, err, "convert end height")
}

// TestRollbackToBlockRejectsHeightOverflowPostgres verifies postgres-specific
// rollback height conversion failures.
func TestRollbackToBlockRejectsHeightOverflowPostgres(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	err := store.RollbackToBlock(t.Context(), ^uint32(0))
	require.ErrorContains(t, err, "convert rollback height")
}
