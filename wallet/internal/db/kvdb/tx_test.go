package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestInvalidateUnminedTxSuccess verifies that kvdb.Store forwards unmined
// invalidation to the legacy wtxmgr removal path.
func TestInvalidateUnminedTxSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{1},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(t.Context(), db.InvalidateUnminedTxParams{
		WalletID: 0,
		Txid:     rec.Hash,
	})
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.Nil(t, details)

		return nil
	})
	require.NoError(t, err)
}

// TestInvalidateUnminedTxRejectsConfirmed verifies that kvdb.Store only allows
// invalidation of current unmined non-coinbase transactions.
func TestInvalidateUnminedTxRejectsConfirmed(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{2},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 1},
			Time:  time.Now(),
		})
	})
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(t.Context(), db.InvalidateUnminedTxParams{
		WalletID: 0,
		Txid:     rec.Hash,
	})
	require.ErrorIs(t, err, db.ErrInvalidateRequiresUnmined)
}
