//go:build itest

package itest

import (
	"math"
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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

	err = store.UpdateTxLabel(t.Context(), db.UpdateTxLabelParams{
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	// Act: Attempt to delete the non-leaf parent transaction.
	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrDeleteRequiresLeaf)

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

// TestCreateTxRejectsDeadWalletParents verifies that CreateTx rejects a child
// that spends a wallet-owned output whose parent branch is already dead.
//
// Scenario:
//   - One wallet-owned coinbase output is orphaned by rollback and a later child
//     transaction references that outpoint.
//
// Setup:
//   - Create one wallet, one default account, and one wallet-owned address.
//   - Insert a confirmed coinbase credit, then roll its block back so the parent
//     becomes orphaned and blockless.
//
// Action:
// - Insert a new pending transaction that references the orphaned outpoint.
// Assertions:
// - CreateTx fails with ErrTxInputDeadWalletParent.
// - The orphaned parent remains orphaned and child-edge enumeration stays empty.
func TestCreateTxRejectsDeadWalletParents(t *testing.T) {
	t.Parallel()

	// Arrange: Create one confirmed coinbase credit and roll it back so the
	// wallet-owned parent becomes orphaned before the child is inserted.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-dead-parent")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()

	coinbaseBlock := CreateBlockFixture(t, queries, 144)
	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: addr.ScriptPubKey,
	}})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710000400, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.NoError(t, err)

	orphanedParent, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, orphanedParent.Block)
	require.Equal(t, db.TxStatusOrphaned, orphanedParent.Status)

	// Act: Insert a new pending transaction that references the orphaned
	// wallet-owned outpoint.
	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: coinbaseTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{
			Value:    49000,
			PkScript: []byte{0x51},
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710000410, 0),
		Status:   db.TxStatusPending,
	})

	// Assert: The dead wallet parent is rejected and no spend edge is attached.
	require.ErrorIs(t, err, db.ErrTxInputDeadWalletParent)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, coinbaseTx.TxHash()))

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.Nil(t, childInfo)
	require.ErrorIs(t, err, db.ErrTxNotFound)

	orphanedParent, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, orphanedParent.Block)
	require.Equal(t, db.TxStatusOrphaned, orphanedParent.Status)
}

// TestCreateTxConfirmsExistingUnmined verifies that CreateTx reuses one live
// unmined row when the same transaction later arrives with a confirming block.
func TestCreateTxConfirmsExistingUnmined(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-confirm-existing-unmined")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 250)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    7000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000500, 0),
		Status:   db.TxStatusPending,
		Label:    "seed",
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000600, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Label:    "replacement-label-is-ignored",
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, info.Block)
	require.Equal(t, confirmedBlock.Height, info.Block.Height)
	require.Equal(t, db.TxStatusPublished, info.Status)
	require.Equal(t, "seed", info.Label)

	unminedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Empty(t, unminedTxs)

	confirmedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: confirmedBlock.Height,
		EndHeight:   confirmedBlock.Height,
	})
	require.NoError(t, err)
	require.Len(t, confirmedTxs, 1)
	require.Equal(t, tx.TxHash(), confirmedTxs[0].Hash)

	utxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: tx.TxHash(), Index: 0},
	})
	require.NoError(t, err)
	require.Equal(t, confirmedBlock.Height, utxo.Height)
}

// TestCreateTxRejectsDoubleSpendConflict verifies that CreateTx refuses to
// attach a second live wallet spender to the same wallet-owned outpoint.
func TestCreateTxRejectsDoubleSpendConflict(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-double-spend-conflict")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    9000,
			PkScript: addr.ScriptPubKey,
		}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710000700, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	firstSpender := newRegularTx(
		[]wire.OutPoint{parentOutPoint},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       firstSpender,
		Received: time.Unix(1710000710, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	conflictingSpender := newRegularTx(
		[]wire.OutPoint{parentOutPoint},
		[]*wire.TxOut{{Value: 3000, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       conflictingSpender,
		Received: time.Unix(1710000720, 0),
		Status:   db.TxStatusPending,
	})
	require.ErrorIs(t, err, db.ErrTxInputConflict)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: parentOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	firstInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     firstSpender.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, firstInfo.Status)

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     conflictingSpender.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestCreateTxRejectsUnknownCreditAddress verifies that credited outputs must
// resolve to one wallet-owned address.
func TestCreateTxRejectsUnknownCreditAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-unknown-credit-address")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    2500,
			PkScript: []byte{0x51},
		}},
	)

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000800, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.ErrorIs(t, err, db.ErrAddressNotFound)

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestCreateTxRejectsInvalidParams verifies that CreateTx wraps shared
// validation failures before opening any backend transaction.
func TestCreateTxRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalid-create-tx-params")

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Status:   db.TxStatusPending,
	})
	require.ErrorContains(t, err, "validate create tx params")
}

// TestCreateTxRejectsDuplicateConfirmedTransaction verifies that duplicate
// confirmed inserts fail through the backend insert path instead of silently
// creating a second row.
func TestCreateTxRejectsDuplicateConfirmedTransaction(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-duplicate-confirmed-tx")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 261)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 4500, PkScript: addr.ScriptPubKey}},
	)
	params := db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000850, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	}

	err := store.CreateTx(t.Context(), params)
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), params)
	require.ErrorContains(t, err, "insert transaction")
}

// TestUpdateTxNotFound verifies the public not-found error for missing labels.
func TestUpdateTxNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-update-missing-tx")

	err := store.UpdateTxLabel(t.Context(), db.UpdateTxLabelParams{
		WalletID: walletID,
		Txid:     randomHash(),
		Label:    "missing",
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestGetAndListTxRejectCorruptedStatus verifies that transaction reads fail
// loudly when the stored status escapes the supported enum.
func TestGetAndListTxRejectCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-tx-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 265)

	pendingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2100, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       pendingTx,
		Received: time.Unix(1710000895, 0),
		Status:   db.TxStatusPending,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 3100, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedTx,
		Received: time.Unix(1710000896, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, pendingTx.TxHash(), 99)

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     pendingTx.TxHash(),
	})
	require.ErrorContains(t, err, "invalid transaction status")

	_, err = store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.ErrorContains(t, err, "invalid transaction status")

	corruptTransactionStatus(t, store, walletID, confirmedTx.TxHash(), 99)

	_, err = store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: confirmedBlock.Height,
		EndHeight:   confirmedBlock.Height,
	})
	require.ErrorContains(t, err, "invalid transaction status")
}

// TestDeleteTxRejectsCorruptedStatus verifies that DeleteTx rejects stored rows
// with an invalid wallet-visible status code.
func TestDeleteTxRejectsCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-corrupted-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2300, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710000897, 0),
		Status:   db.TxStatusPending,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, tx.TxHash(), 99)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     tx.TxHash(),
	})
	require.ErrorContains(t, err, "invalid transaction status")
}

// TestTxReadsReturnQueryErrorsWhenClosed verifies that transaction read/update
// methods wrap backend query errors when the underlying connection is closed.
func TestTxReadsReturnQueryErrorsWhenClosed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-closed-tx-reads")
	err := store.Close()
	require.NoError(t, err)

	err = store.UpdateTxLabel(t.Context(), db.UpdateTxLabelParams{
		WalletID: walletID,
		Txid:     randomHash(),
		Label:    "closed",
	})
	require.ErrorContains(t, err, "update transaction label")

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     randomHash(),
	})
	require.ErrorContains(t, err, "get transaction")

	_, err = store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.ErrorContains(t, err, "list unmined transactions")

	_, err = store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		StartHeight: 1,
		EndHeight:   1,
	})
	require.ErrorContains(t, err, "list transactions by height")
}

// TestUtxoReadsReturnQueryErrorsWhenClosed verifies that UTXO read methods wrap
// backend query errors when the underlying connection is closed.
func TestUtxoReadsReturnQueryErrorsWhenClosed(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-closed-utxo-reads")
	err := store.Close()
	require.NoError(t, err)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: randomHash(), Index: 0},
	})
	require.ErrorContains(t, err, "get utxo")

	_, err = store.ListUTXOs(t.Context(), db.ListUtxosQuery{WalletID: walletID})
	require.ErrorContains(t, err, "list utxos")

	_, err = store.ListLeasedOutputs(t.Context(), walletID)
	require.ErrorContains(t, err, "list active utxo leases")

	_, err = store.Balance(t.Context(), db.BalanceParams{WalletID: walletID})
	require.ErrorContains(t, err, "balance")
}

// TestDeleteTxRejectsConfirmedAndMissing verifies DeleteTx's live-unconfirmed
// precondition and not-found handling.
func TestDeleteTxRejectsConfirmedAndMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-confirmed-or-missing")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 260)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    5000,
			PkScript: addr.ScriptPubKey,
		}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       confirmedTx,
		Received: time.Unix(1710000900, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     confirmedTx.TxHash(),
	})
	require.ErrorContains(t, err, "live unconfirmed transaction required")

	confirmedInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     confirmedTx.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, confirmedInfo.Block)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     randomHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestDeleteTxRejectsNonLeafExternalChild verifies that DeleteTx scans the raw
// unmined graph, not only wallet-owned credit edges, when enforcing leaf-only
// deletion.
func TestDeleteTxRejectsNonLeafExternalChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-non-leaf-external-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 6000, PkScript: addr.ScriptPubKey},
			{Value: 500, PkScript: []byte{0x51}},
		},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001000, 0),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]btcutil.Address{0: nil},
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 1}},
		[]*wire.TxOut{{Value: 300, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001010, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrDeleteRequiresLeaf)

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

// TestDeleteTxRejectsCorruptedLiveChild verifies that DeleteTx surfaces child
// decode failures while checking the live leaf invariant.
func TestDeleteTxRejectsCorruptedLiveChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-corrupted-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       parentTx,
		Received: time.Unix(1710001015, 0),
		Status:   db.TxStatusPending,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710001020, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	corruptTransactionRawTx(t, store, walletID, childTx.TxHash(), []byte{})

	err = store.DeleteTx(t.Context(), db.DeleteTxParams{
		WalletID: walletID,
		Txid:     parentTx.TxHash(),
	})
	require.ErrorContains(t, err, "decode live transaction")
}

// TestLeaseOutputMissingUtxo verifies that leasing one missing outpoint returns
// the public not-found error.
func TestLeaseOutputMissingUtxo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-lease-missing-utxo")

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(3),
		OutPoint: wire.OutPoint{Hash: randomHash(), Index: 0},
		Duration: time.Minute,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReleaseOutputMissingUtxo verifies that releasing one missing outpoint
// returns the public not-found error.
func TestReleaseOutputMissingUtxo(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-release-missing-utxo")

	err := store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(4),
		OutPoint: wire.OutPoint{Hash: randomHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReleaseOutputTwiceIsNoOp verifies that a second release with the same lock
// becomes a no-op after the original lease has already been removed.
func TestReleaseOutputTwiceIsNoOp(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-release-output-twice")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 270)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
		Received: time.Unix(1710001300, 0),
		Block:    &confirmedBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	leaseOutPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	leaseID := lockIDFixture(5)
	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: leaseOutPoint,
		Duration: time.Hour,
	})
	require.NoError(t, err)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: leaseOutPoint,
	})
	require.NoError(t, err)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       leaseID,
		OutPoint: leaseOutPoint,
	})
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), walletID)
	require.NoError(t, err)
	require.Empty(t, leases)
}

// TestGetUtxoAndLeaseRejectLargeOutputIndex verifies backend-specific handling
// for outpoint indexes that exceed the supported signed SQL range.
func TestGetUtxoAndLeaseRejectLargeOutputIndex(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-large-output-index")
	outPoint := wire.OutPoint{Hash: randomHash(), Index: math.MaxUint32}

	_, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: outPoint,
	})
	requireLargeOutputIndexError(t, err)

	_, err = store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(6),
		OutPoint: outPoint,
		Duration: time.Minute,
	})
	requireLargeOutputIndexError(t, err)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(6),
		OutPoint: outPoint,
	})
	requireLargeOutputIndexError(t, err)
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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
	require.Equal(t, btcutil.Amount(62000), totalBalance.Total)
	require.Zero(t, totalBalance.Locked)

	coinbaseMaturityOnlyBalance, err := store.Balance(
		t.Context(), db.BalanceParams{
			WalletID:         walletID,
			Account:          &defaultAccount,
			CoinbaseMaturity: int32Ptr(3),
		},
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(10000), coinbaseMaturityOnlyBalance.Total)
	require.Zero(t, coinbaseMaturityOnlyBalance.Locked)

	defaultBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
		Account:  &defaultAccount,
		MinConfs: int32Ptr(1),
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(60000), defaultBalance.Total)
	require.Zero(t, defaultBalance.Locked)

	strictCoinbaseBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID:         walletID,
		Account:          &defaultAccount,
		MinConfs:         int32Ptr(1),
		CoinbaseMaturity: int32Ptr(3),
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(10000), strictCoinbaseBalance.Total)
	require.Zero(t, strictCoinbaseBalance.Locked)

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
	require.ErrorIs(t, err, db.ErrOutputAlreadyLeased)

	leasedBalance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
		Account:  &defaultAccount,
		MinConfs: int32Ptr(1),
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(60000), leasedBalance.Total)
	require.Equal(t, btcutil.Amount(10000), leasedBalance.Locked)

	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: walletID,
		ID:       lockIDFixture(9),
		OutPoint: leaseOutPoint,
	})
	require.ErrorIs(t, err, db.ErrOutputUnlockNotAllowed)

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
