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

// TestApplyTxReplacement verifies that direct victims become replaced,
// descendants become failed, replacement edges are recorded, and the winner's
// inputs are reclaimed as the live spend path.
func TestApplyTxReplacement(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-apply-replacement")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 50)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 40)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    10000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTx,
		Received: time.Unix(1710002000, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	victimTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    6000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       victimTx,
		Received: time.Unix(1710002010, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	victimOutPoint := wire.OutPoint{Hash: victimTx.TxHash(), Index: 0}
	descendantTx := newRegularTx(
		[]wire.OutPoint{victimOutPoint},
		[]*wire.TxOut{{
			Value:    5000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       descendantTx,
		Received: time.Unix(1710002020, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	replacementTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    7000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       replacementTx,
		Received: time.Unix(1710002030, 0),
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: replacementTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimTx.TxHash()},
	})
	require.NoError(t, err)

	requireReplacementEdge(
		t, queries, walletID, victimTx.TxHash(), replacementTx.TxHash(),
	)

	victimInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     victimTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, victimInfo.Status)

	descendantInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     descendantTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, descendantInfo.Status)

	replacementInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     replacementTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, replacementInfo.Status)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: victimOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: descendantTx.TxHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	replacementUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: replacementTx.TxHash(), Index: 0},
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(7000), replacementUtxo.Amount)

	balance, err := store.Balance(t.Context(), db.BalanceParams{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(7000), balance)
}

// TestApplyTxFailure verifies that direct losers and their descendants become
// failed while the conflicting winner reclaims the shared wallet input.
func TestApplyTxFailure(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-apply-failure")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 80)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 70)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    9000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTx,
		Received: time.Unix(1710003000, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	failedTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    4000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       failedTx,
		Received: time.Unix(1710003010, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	failedOutPoint := wire.OutPoint{Hash: failedTx.TxHash(), Index: 0}
	descendantTx := newRegularTx(
		[]wire.OutPoint{failedOutPoint},
		[]*wire.TxOut{{
			Value:    3000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       descendantTx,
		Received: time.Unix(1710003020, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    6500,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710003030, 0),
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	err = store.ApplyTxFailure(t.Context(), db.ApplyTxFailureParams{
		WalletID:        walletID,
		ConflictingTxid: winnerTx.TxHash(),
		FailedTxids:     []chainhash.Hash{failedTx.TxHash()},
	})
	require.NoError(t, err)

	failedInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     failedTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, failedInfo.Status)

	descendantInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     descendantTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, descendantInfo.Status)

	winnerUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: winnerTx.TxHash(), Index: 0},
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(6500), winnerUtxo.Amount)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: failedOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: descendantTx.TxHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestApplyTxReplacementRejectsIncompleteVictimSet verifies that replacement
// flows fail when the caller omits a conflicting loser for another wallet-owned
// input of the winner transaction.
func TestApplyTxReplacementRejectsIncompleteVictimSet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-replacement-incomplete")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 95)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlockOne := CreateBlockFixture(t, queries, 90)
	fundingTxOne := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 11000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTxOne,
		Received: time.Unix(1710005000, 0),
		Block:    &fundingBlockOne,
		Status:   db.TxStatusPublished,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	fundingBlockTwo := CreateBlockFixture(t, queries, 91)
	fundingTxTwo := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 12000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTxTwo,
		Received: time.Unix(1710005010, 0),
		Block:    &fundingBlockTwo,
		Status:   db.TxStatusPublished,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	victimOne := newRegularTx(
		[]wire.OutPoint{{Hash: fundingTxOne.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 6000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       victimOne,
		Received: time.Unix(1710005020, 0),
		Status:   db.TxStatusPending,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	victimTwo := newRegularTx(
		[]wire.OutPoint{{Hash: fundingTxTwo.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       victimTwo,
		Received: time.Unix(1710005030, 0),
		Status:   db.TxStatusPending,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	winnerTx := newRegularTx(
		[]wire.OutPoint{
			{Hash: fundingTxOne.TxHash(), Index: 0},
			{Hash: fundingTxTwo.TxHash(), Index: 0},
		},
		[]*wire.TxOut{{Value: 15000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710005040, 0),
		Status:   db.TxStatusPublished,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimOne.TxHash()},
	})
	require.ErrorContains(t, err, "winner input was not reclaimed")

	victimOneInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     victimOne.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, victimOneInfo.Status)

	victimTwoInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     victimTwo.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, victimTwoInfo.Status)
}

// TestApplyTxFailureRejectsIncompleteLoserSet verifies that failure flows fail
// when a winner has another wallet-owned input still claimed by an omitted
// loser transaction.
func TestApplyTxFailureRejectsIncompleteLoserSet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-failure-incomplete")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 105)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlockOne := CreateBlockFixture(t, queries, 100)
	fundingTxOne := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 13000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTxOne,
		Received: time.Unix(1710005100, 0),
		Block:    &fundingBlockOne,
		Status:   db.TxStatusPublished,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	fundingBlockTwo := CreateBlockFixture(t, queries, 101)
	fundingTxTwo := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 14000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTxTwo,
		Received: time.Unix(1710005110, 0),
		Block:    &fundingBlockTwo,
		Status:   db.TxStatusPublished,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	loserOne := newRegularTx(
		[]wire.OutPoint{{Hash: fundingTxOne.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       loserOne,
		Received: time.Unix(1710005120, 0),
		Status:   db.TxStatusPending,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	loserTwo := newRegularTx(
		[]wire.OutPoint{{Hash: fundingTxTwo.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       loserTwo,
		Received: time.Unix(1710005130, 0),
		Status:   db.TxStatusPending,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	winnerTx := newRegularTx(
		[]wire.OutPoint{
			{Hash: fundingTxOne.TxHash(), Index: 0},
			{Hash: fundingTxTwo.TxHash(), Index: 0},
		},
		[]*wire.TxOut{{Value: 18000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710005140, 0),
		Status:   db.TxStatusPublished,
		Credits:  []db.CreditData{{Index: 0}},
	})
	require.NoError(t, err)

	err = store.ApplyTxFailure(t.Context(), db.ApplyTxFailureParams{
		WalletID:        walletID,
		ConflictingTxid: winnerTx.TxHash(),
		FailedTxids:     []chainhash.Hash{loserOne.TxHash()},
	})
	require.ErrorContains(t, err, "winner input was not reclaimed")

	loserOneInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     loserOne.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, loserOneInfo.Status)

	loserTwoInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     loserTwo.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, loserTwoInfo.Status)
}

// TestOrphanTxChainAndReconfirmOrphanedCoinbase verifies that rollback-created
// orphaned coinbase roots fail their descendants and can later be restored to a
// new confirming block atomically.
func TestOrphanTxChainAndReconfirmOrphanedCoinbase(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-orphan-chain")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	_ = CreateBlockFixture(t, queries, 99)
	coinbaseBlock := CreateBlockFixture(t, queries, 100)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &coinbaseBlock,
	})
	require.NoError(t, err)

	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: addr.ScriptPubKey,
	}})

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004000, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	coinbaseOutPoint := wire.OutPoint{Hash: coinbaseTx.TxHash(), Index: 0}
	childTx := newRegularTx(
		[]wire.OutPoint{coinbaseOutPoint},
		[]*wire.TxOut{{
			Value:    45000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710004010, 0),
		Status:   db.TxStatusPending,
		Credits: []db.CreditData{{
			Index: 0,
		}},
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.NoError(t, err)

	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)

	err = store.OrphanTxChain(t.Context(), db.OrphanTxChainParams{
		WalletID: walletID,
		Txids:    []chainhash.Hash{coinbaseTx.TxHash()},
	})
	require.NoError(t, err)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: childTx.TxHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: coinbaseOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	reconfirmBlock := CreateBlockFixture(t, queries, 101)
	err = store.ReconfirmOrphanedCoinbase(
		t.Context(), db.ReconfirmOrphanedCoinbaseParams{
			WalletID: walletID,
			Txid:     coinbaseTx.TxHash(),
			Block:    reconfirmBlock,
		},
	)
	require.NoError(t, err)

	coinbaseInfo, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, coinbaseInfo.Status)
	require.NotNil(t, coinbaseInfo.Block)
	require.Equal(t, reconfirmBlock.Height, coinbaseInfo.Block.Height)

	restoredCoinbase, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: coinbaseOutPoint,
	})
	require.NoError(t, err)
	require.Equal(t, reconfirmBlock.Height, restoredCoinbase.Height)
}
