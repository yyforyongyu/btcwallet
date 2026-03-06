//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestTxStoreLifecycle verifies the baseline SQL TxStore behavior for creating,
// reading, listing, updating, deleting, and rolling back transactions.
func TestTxStoreLifecycle(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-tx-store")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()

	pendingReceived := time.Unix(1710000000, 0).In(
		time.FixedZone("pending", 3600),
	)
	pendingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    5000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       pendingTx,
		Received: pendingReceived,
		Status:   db.TxStatusPending,
		Label:    "pending",
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	pendingInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     pendingTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, pendingTx.TxHash(), pendingInfo.Hash)
	require.Equal(t, db.TxStatusPending, pendingInfo.Status)
	require.Equal(t, "pending", pendingInfo.Label)
	require.Nil(t, pendingInfo.Block)
	require.Equal(t, time.UTC, pendingInfo.Received.Location())

	unminedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, unminedTxs, 1)
	require.Equal(t, pendingInfo.Hash, unminedTxs[0].Hash)

	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: walletID,
		Txid:     pendingTx.TxHash(),
		Label:    "renamed",
	})
	require.NoError(t, err)

	pendingInfo, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     pendingTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, "renamed", pendingInfo.Label)

	pendingOutPoint := wire.OutPoint{Hash: pendingTx.TxHash(), Index: 0}
	pendingUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: pendingOutPoint,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(5000), pendingUtxo.Amount)
	require.Equal(t, db.UnminedHeight, pendingUtxo.Height)
	require.Equal(t, addr.ScriptPubKey, pendingUtxo.PkScript)

	spendTx := newRegularTx(
		[]wire.OutPoint{pendingOutPoint},
		[]*wire.TxOut{{
			Value:    4000,
			PkScript: []byte{0x51},
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       spendTx,
		Received: time.Unix(1710000100, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: pendingOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     spendTx.TxHash(),
	})
	require.NoError(t, err)

	restoredUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: pendingOutPoint,
	})
	require.NoError(t, err)
	require.Equal(t, pendingUtxo.OutPoint, restoredUtxo.OutPoint)

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     spendTx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)

	_ = CreateBlockFixture(t, queries, 54)
	confirmedBlock := CreateBlockFixture(t, queries, 55)
	err = store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &confirmedBlock,
	})
	require.NoError(t, err)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    7000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedTx,
		Received: time.Unix(1710000200, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	confirmedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: confirmedBlock.Height,
		EndHeight:   confirmedBlock.Height,
	})
	require.NoError(t, err)
	require.Len(t, confirmedTxs, 1)
	require.Equal(t, confirmedTx.TxHash(), confirmedTxs[0].Hash)
	require.NotNil(t, confirmedTxs[0].Block)
	require.Equal(t, confirmedBlock.Height, confirmedTxs[0].Block.Height)

	err = store.RollbackToBlock(t.Context(), confirmedBlock.Height)
	require.NoError(t, err)

	rolledBackInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     confirmedTx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, rolledBackInfo.Block)
	require.Equal(t, db.TxStatusPublished, rolledBackInfo.Status)

	unminedTxs, err = store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, unminedTxs, 2)
}

// TestUtxoStoreLeaseAndBalance verifies listing, leasing, releasing, and
// balance filtering across confirmed, unconfirmed, and coinbase outputs.
func TestUtxoStoreLeaseAndBalance(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-utxo-store")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "savings")

	defaultAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	savingsAddr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "savings", false,
	)
	queries := store.Queries()

	tipBlock := CreateBlockFixture(t, queries, 200)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	confirmedBlock := CreateBlockFixture(t, queries, 190)
	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    10000,
			PkScript: defaultAddr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedTx,
		Received: time.Unix(1710001000, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	unconfirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    2000,
			PkScript: savingsAddr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       unconfirmedTx,
		Received: time.Unix(1710001100, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	coinbaseBlock := CreateBlockFixture(t, queries, 199)
	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: defaultAddr.ScriptPubKey,
	}})

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710001200, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	allUtxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		MinConfs: 0,
		MaxConfs: 1000,
	})
	require.NoError(t, err)
	require.Len(t, allUtxos, 3)

	defaultAccount := uint32(0)
	defaultUtxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Account:  &defaultAccount,
		MinConfs: 1,
		MaxConfs: 1000,
	})
	require.NoError(t, err)
	require.Len(t, defaultUtxos, 2)

	savingsAccount := uint32(1)
	unconfirmedSavings, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Account:  &savingsAccount,
		MinConfs: 0,
		MaxConfs: 0,
	})
	require.NoError(t, err)
	require.Len(t, unconfirmedSavings, 1)
	require.Equal(t, btcutil.Amount(2000), unconfirmedSavings[0].Amount)
	require.Equal(t, db.UnminedHeight, unconfirmedSavings[0].Height)

	totalBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(62000), totalBalance)

	defaultBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
		Account:  &defaultAccount,
		MinConfs: int32Ptr(1),
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(60000), defaultBalance)

	strictCoinbaseBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID:         walletID,
		Account:          &defaultAccount,
		MinConfs:         int32Ptr(1),
		CoinbaseMaturity: int32Ptr(3),
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(10000), strictCoinbaseBalance)

	leaseOutPoint := wire.OutPoint{Hash: confirmedTx.TxHash(), Index: 0}
	leaseID := lockIDFixture(1)
	lease, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: leaseOutPoint,
		Duration: time.Hour,
	})
	require.NoError(t, err)
	require.Equal(t, leaseOutPoint, lease.OutPoint)
	require.Equal(t, db.LockID(leaseID), lease.LockID)

	leasedOutputs, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)
	require.Len(t, leasedOutputs, 1)
	require.Equal(t, leaseOutPoint, leasedOutputs[0].OutPoint)

	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(2),
		OutPoint: leaseOutPoint,
		Duration: time.Hour,
	})
	require.ErrorContains(t, err, "output already leased")

	excludeLeasedBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID:      walletID,
		Account:       &defaultAccount,
		MinConfs:      int32Ptr(1),
		ExcludeLeased: true,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50000), excludeLeasedBalance)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(9),
		OutPoint: leaseOutPoint,
	})
	require.ErrorContains(t, err, "output unlock not allowed")

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: leaseOutPoint,
	})
	require.NoError(t, err)

	leasedOutputs, err = store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)
	require.Empty(t, leasedOutputs)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: randomHash(), Index: 9},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

func newRegularTx(inputs []wire.OutPoint, outputs []*wire.TxOut) *wire.MsgTx {
	tx := wire.NewMsgTx(2)

	for _, prevOut := range inputs {
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevOut})
	}

	for _, txOut := range outputs {
		tx.AddTxOut(txOut)
	}

	return tx
}

func newCoinbaseTx(outputs []*wire.TxOut) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)},
		SignatureScript:  []byte{0x01},
	})

	for _, txOut := range outputs {
		tx.AddTxOut(txOut)
	}

	return tx
}

func randomOutPoint() wire.OutPoint {
	return wire.OutPoint{Hash: randomHash(), Index: 0}
}

func randomHash() chainhash.Hash {
	return RandomHash()
}

func int32Ptr(value int32) *int32 {
	return &value
}

func lockIDFixture(firstByte byte) [32]byte {
	var lockID [32]byte
	lockID[0] = firstByte

	return lockID
}
