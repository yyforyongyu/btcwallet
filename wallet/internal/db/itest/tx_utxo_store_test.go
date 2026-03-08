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
//
// Scenario:
//   - One wallet receives an unconfirmed credit, spends it, deletes the spend,
//     then confirms and rolls back a later credit.
//
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Seed blocks so a later transaction can be confirmed and then rolled back.
// Action:
//   - Exercise CreateTx, GetTx, ListTxns, UpdateTx, GetUtxo, DeleteTx, and
//     RollbackToBlock against the same wallet history.
//
// Assertions:
// - Labels, spend state, and restored wallet-owned UTXOs stay coherent.
// - Rolled-back confirmed transactions return to the blockless published set.
func TestTxStoreLifecycle(t *testing.T) {
	t.Parallel()

	// Arrange: Build one wallet history with an unconfirmed credit, a temporary
	// spend, and a later confirmed credit that can be rolled back.
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

	// Act: Read, list, update, spend, delete, confirm, and roll back the wallet
	// transaction history.
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

	// Assert: Labels, spend state, restored UTXOs, and rolled-back transaction
	// visibility all remain coherent.
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

// TestDeleteTxRejectsNonLeafTransaction verifies that DeleteTx refuses to erase
// an unconfirmed transaction that still has direct child spenders.
//
// Scenario:
//   - One pending parent creates a wallet-owned output and one pending child
//     spends that output.
//
// Setup:
//   - Create one wallet, one default account, and one wallet-owned address.
//   - Insert both transactions so the parent is no longer a leaf in the local
//     unconfirmed graph.
//
// Action:
// - Attempt to delete the parent transaction while its child still exists.
// Assertions:
// - DeleteTx rejects the request with the leaf-only invariant error.
// - Both the parent and child rows remain present and keep their live status.
func TestDeleteTxRejectsNonLeafTransaction(t *testing.T) {
	t.Parallel()

	// Arrange: Create one pending parent and one pending child that spends the
	// parent's wallet-owned output.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-non-leaf")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    5000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000300, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{
			Value:    4000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710000310, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	// Act: Attempt to delete the non-leaf parent transaction.
	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.ErrorContains(t, err, "delete requires a leaf transaction")

	// Assert: Both parent and child remain present with their live status.
	parentInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, parentInfo.Status)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, childInfo.Status)
}

// TestUtxoStoreLeaseAndBalance verifies listing, leasing, releasing, and
// balance filtering across confirmed, unconfirmed, and coinbase outputs.
//
// Scenario:
//   - One wallet owns confirmed, unconfirmed, and coinbase outputs across two
//     accounts.
//
// Setup:
//   - Create default and savings accounts plus one address in each account.
//   - Insert one confirmed transaction, one unconfirmed transaction, and one
//     coinbase transaction while advancing wallet sync state.
//
// Action:
//   - Query UTXOs and balances with account/confirmation filters, then acquire
//     and release a lease on one confirmed output.
//
// Assertions:
//   - Zero-value UTXO queries return the full live set while explicit bounds
//     narrow it correctly.
//   - Balance and lease reads honor account, maturity, and active-lock filters.
func TestUtxoStoreLeaseAndBalance(t *testing.T) {
	t.Parallel()

	// Arrange: Create one wallet with confirmed, unconfirmed, and coinbase UTXOs
	// across two accounts.
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

	// Act: Query balances and UTXO views, then lease and release one confirmed
	// output.
	allUtxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.Len(t, allUtxos, 3)

	defaultAccount := uint32(0)
	defaultUtxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Account:  &defaultAccount,
		MinConfs: int32Ptr(1),
	})
	require.NoError(t, err)
	require.Len(t, defaultUtxos, 2)

	savingsAccount := uint32(1)
	unconfirmedSavings, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: walletID,
		Account:  &savingsAccount,
		MinConfs: int32Ptr(0),
		MaxConfs: int32Ptr(0),
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

	coinbaseMaturityOnlyBalance, err := store.Balance(
		t.Context(), db.BalanceParams{
			WalletID:         walletID,
			Account:          &defaultAccount,
			CoinbaseMaturity: int32Ptr(3),
		},
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(10000), coinbaseMaturityOnlyBalance)

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

	// Assert: Account filters, maturity rules, and active lease checks all match
	// the expected public store behavior.
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// newRegularTx builds a simple fixture transaction with the provided inputs and
// outputs.
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

// newCoinbaseTx builds a minimal coinbase fixture transaction with the provided
// outputs.
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

// randomOutPoint returns one fixture outpoint backed by a random hash.
func randomOutPoint() wire.OutPoint {
	return wire.OutPoint{Hash: randomHash(), Index: 0}
}

// randomHash returns one fixture transaction hash.
func randomHash() chainhash.Hash {
	return RandomHash()
}

// int32Ptr returns the address of the provided int32 fixture value.
func int32Ptr(value int32) *int32 {
	return &value
}

// lockIDFixture builds a deterministic lease lock ID with the requested prefix
// byte.
func lockIDFixture(firstByte byte) [32]byte {
	var lockID [32]byte
	lockID[0] = firstByte

	return lockID
}
