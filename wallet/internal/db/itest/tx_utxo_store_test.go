//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

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

	// Assert: The delete is rejected and both transactions remain live.
	require.ErrorContains(t, err, "delete requires a leaf transaction")

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

// TestCreateTxDoesNotAttachDeadWalletParents verifies that CreateTx only marks
// wallet-owned inputs spent when the parent transaction is still live.
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
// - CreateTx succeeds but does not attach a spend edge to the dead parent.
// - The orphaned parent remains orphaned and child-edge enumeration stays empty.
func TestCreateTxDoesNotAttachDeadWalletParents(t *testing.T) {
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
		Credits: []db.CreditData{{
			Index: 0,
		}},
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

	// Assert: The child is stored, but the dead parent keeps no spend edge.
	require.NoError(t, err)
	require.Empty(t, childSpendingTxIDs(t, store, walletID, coinbaseTx.TxHash()))

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, childInfo.Status)

	orphanedParent, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, orphanedParent.Block)
	require.Equal(t, db.TxStatusOrphaned, orphanedParent.Status)
}

// TestCreateTxRejectsConflictingLiveWalletSpend verifies that CreateTx rejects
// a second live spender of the same wallet-owned output.
//
// Scenario:
//   - One pending parent creates a wallet-owned output and one pending child
//     already spends that output.
//
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert the pending parent and the first live child spend.
// Action:
// - Attempt to insert a second pending child that spends the same outpoint.
// Assertions:
// - CreateTx returns ErrTxInputConflict.
// - The first child remains the only recorded spender.
// - The conflicting second child is not persisted.
func TestCreateTxRejectsConflictingLiveWalletSpend(t *testing.T) {
	t.Parallel()

	// Arrange: Create one pending parent and one first live child spend.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-live-spend-conflict")
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
		Received: time.Unix(1710000500, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	spentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}
	firstChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{
			Value:    4000,
			PkScript: []byte{0x51},
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       firstChild,
		Received: time.Unix(1710000510, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	// Act: Attempt to insert a second live child spend for the same outpoint.
	secondChild := newRegularTx(
		[]wire.OutPoint{spentOutPoint},
		[]*wire.TxOut{{
			Value:    3000,
			PkScript: []byte{0x52},
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       secondChild,
		Received: time.Unix(1710000520, 0),
		Status:   db.TxStatusPending,
	})

	// Assert: The first child remains the sole live spender and the second
	// child is rejected.
	require.ErrorIs(t, err, db.ErrTxInputConflict)

	childIDs := childSpendingTxIDs(t, store, walletID, parentTx.TxHash())
	require.Len(t, childIDs, 1)

	firstChildInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     firstChild.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, firstChildInfo.Status)

	_, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     secondChild.TxHash(),
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
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
