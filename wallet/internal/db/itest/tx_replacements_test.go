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

// TestApplyTxReplacement verifies the replacement flow for one direct victim and
// its descendant chain.
//
// Scenario:
// - One confirmed funding output is first spent by a pending victim.
// - A pending descendant then spends the victim's wallet-owned output.
// - A published replacement spends the original funding output.
// Setup:
//   - Create one wallet, one default account, and one wallet-owned address.
//   - Insert the confirmed funding tx, the direct victim, the descendant, and the
//     published replacement.
//
// Action:
//   - ApplyTxReplacement is called with the replacement as winner and the direct
//     victim as the only replaced root.
//
// Assertions:
// - The direct victim becomes `replaced`.
// - Descendants become `failed`.
// - The replacement edge is recorded and the winner owns the surviving UTXO.
func TestApplyTxReplacement(t *testing.T) {
	t.Parallel()

	// Arrange: Build one wallet history with a funding tx, one direct victim,
	// one descendant, and one published replacement.
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
		Credits:  walletCredits(0),
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
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	replacementTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    7000,
			PkScript: addr.ScriptPubKey,
		}},
	)

	insertConflictingRegularTx(
		t, store, walletID, replacementTx, time.Unix(1710002030, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	// Act: Apply the replacement against the direct victim root.
	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: replacementTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimTx.TxHash()},
	})
	require.NoError(t, err)

	// Assert: The victim is replaced, descendants fail, and the winner owns the
	// surviving wallet UTXO and balance.
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

	unminedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, unminedTxs, 3)
	require.Equal(t, replacementTx.TxHash(), unminedTxs[0].Hash)
	require.Equal(t, db.TxStatusPublished, unminedTxs[0].Status)
	require.Equal(t, descendantTx.TxHash(), unminedTxs[1].Hash)
	require.Equal(t, db.TxStatusFailed, unminedTxs[1].Status)
	require.Equal(t, victimTx.TxHash(), unminedTxs[2].Hash)
	require.Equal(t, db.TxStatusReplaced, unminedTxs[2].Status)

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
	require.Equal(t, btcutil.Amount(7000), balance.Total)
	require.Zero(t, balance.Locked)
}

// TestApplyTxReplacementAcceptsWinnerFirstVictim verifies the supported
// winner-first replacement ordering.
//
// Scenario:
//   - A published winner and a later pending loser spend the same wallet-owned
//     funding output.
//
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert the confirmed funding tx, then record the winner before the victim.
// Action:
// - ApplyTxReplacement is called with the winner and the later victim root.
// Assertions:
// - Direct-root validation still accepts the real victim.
// - The victim becomes replaced and the winner keeps the live UTXO.
func TestApplyTxReplacementAcceptsWinnerFirstVictim(t *testing.T) {
	t.Parallel()

	// Arrange: Record the confirmed funding tx, then insert the winner before the
	// later conflicting victim.
	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-replacement-winner-first")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 65)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 60)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 12000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTx,
		Received: time.Unix(1710002100, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710002110, 0),
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	victimTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)
	insertConflictingRegularTx(
		t, store, walletID, victimTx, time.Unix(1710002120, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	// Act: Apply the replacement even though the winner claimed the input first.
	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimTx.TxHash()},
	})
	require.NoError(t, err)

	// Assert: Direct-root validation still accepts the real victim and leaves the
	// winner owning the live output.
	requireReplacementEdge(
		t, queries, walletID, victimTx.TxHash(), winnerTx.TxHash(),
	)

	victimInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     victimTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, victimInfo.Status)

	winnerUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: winnerTx.TxHash(), Index: 0},
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(9000), winnerUtxo.Amount)
}

// TestConfirmedConflictUsesFailureFlow verifies that confirmed winners are not
// treated as unconfirmed replacements.
//
// Scenario:
//   - A confirmed winner and a later pending loser spend the same wallet-owned
//     funding output.
//
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert the confirmed funding tx, a confirmed winner, and the later loser.
// Action:
// - Call ApplyTxReplacement with the confirmed winner.
// - Then call ApplyTxFailure with the same winner and loser.
// Assertions:
// - ApplyTxReplacement rejects the confirmed winner.
// - ApplyTxFailure accepts the conflict and marks the loser failed.
func TestConfirmedConflictUsesFailureFlow(t *testing.T) {
	t.Parallel()

	// Arrange: Record the confirmed funding tx, a confirmed direct-conflict
	// winner, and a later pending loser.
	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-confirmed-conflict")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 85)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 70)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 15000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTx,
		Received: time.Unix(1710002500, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	winnerBlock := CreateBlockFixture(t, queries, 75)
	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 10000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710002510, 0),
		Block:    &winnerBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	loserTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	insertConflictingRegularTx(
		t, store, walletID, loserTx, time.Unix(1710002520, 0),
		db.TxStatusPending, walletCredits(0),
	)

	// Act: Replacement semantics reject a confirmed winner.
	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{loserTx.TxHash()},
	})
	require.ErrorContains(
		t, err,
		"replacement transaction must be live, unconfirmed, and non-coinbase",
	)

	// Act: Failure semantics accept the same confirmed winner.
	err = store.ApplyTxFailure(t.Context(), db.ApplyTxFailureParams{
		WalletID:        walletID,
		ConflictingTxid: winnerTx.TxHash(),
		FailedTxids:     []chainhash.Hash{loserTx.TxHash()},
	})
	require.NoError(t, err)

	// Assert: The loser fails while the confirmed winner keeps its block-backed
	// live output.
	loserInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     loserTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, loserInfo.Status)
	require.Nil(t, loserInfo.Block)

	winnerInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     winnerTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, winnerInfo.Status)
	require.NotNil(t, winnerInfo.Block)
	require.Equal(t, winnerBlock.Height, winnerInfo.Block.Height)

	winnerUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: winnerTx.TxHash(), Index: 0},
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(10000), winnerUtxo.Amount)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: loserTx.TxHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestApplyTxFailure verifies the failure flow for one direct loser and its
// descendant chain.
//
// Scenario:
// - One confirmed funding output is first spent by a pending loser.
// - A pending descendant then spends the loser's wallet-owned output.
// - A published conflicting winner spends the original funding output.
// Setup:
//   - Create one wallet, one default account, and one wallet-owned address.
//   - Insert the confirmed funding tx, the direct loser, the descendant, and the
//     published conflicting winner.
//
// Action:
// - ApplyTxFailure is called with the conflicting winner and the direct loser.
// Assertions:
// - The direct loser and descendants become `failed`.
// - The conflicting winner reclaims the live wallet-owned spend path.
func TestApplyTxFailure(t *testing.T) {
	t.Parallel()

	// Arrange: Build one wallet history with a funding tx, one direct loser,
	// one descendant, and one published conflicting winner.
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
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    6500,
			PkScript: addr.ScriptPubKey,
		}},
	)

	insertConflictingRegularTx(
		t, store, walletID, winnerTx, time.Unix(1710003030, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	// Act: Apply the failure flow against the direct loser root.
	err = store.ApplyTxFailure(t.Context(), db.ApplyTxFailureParams{
		WalletID:        walletID,
		ConflictingTxid: winnerTx.TxHash(),
		FailedTxids:     []chainhash.Hash{failedTx.TxHash()},
	})
	require.NoError(t, err)

	// Assert: The loser branch fails and the winner owns the surviving wallet
	// spend path.
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

// TestApplyTxFailureAcceptsWinnerFirstLoser verifies the supported winner-first
// failure ordering.
//
// Scenario:
//   - A published winner and a later pending loser spend the same wallet-owned
//     funding output.
//
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert the confirmed funding tx, then record the winner before the loser.
// Action:
// - ApplyTxFailure is called with the winner and the later loser root.
// Assertions:
// - Direct-root validation still accepts the real loser.
// - The loser becomes failed and the winner keeps the live UTXO.
func TestApplyTxFailureAcceptsWinnerFirstLoser(t *testing.T) {
	t.Parallel()

	// Arrange: Record the confirmed funding tx, then insert the winner before the
	// later conflicting loser.
	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-failure-winner-first")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	tipBlock := CreateBlockFixture(t, queries, 75)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 70)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 13000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTx,
		Received: time.Unix(1710003100, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 9500, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710003110, 0),
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	loserTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 8500, PkScript: addr.ScriptPubKey}},
	)
	insertConflictingRegularTx(
		t, store, walletID, loserTx, time.Unix(1710003120, 0),
		db.TxStatusPending, walletCredits(0),
	)

	// Act: Apply the failure flow even though the winner claimed the input first.
	err = store.ApplyTxFailure(t.Context(), db.ApplyTxFailureParams{
		WalletID:        walletID,
		ConflictingTxid: winnerTx.TxHash(),
		FailedTxids:     []chainhash.Hash{loserTx.TxHash()},
	})
	require.NoError(t, err)

	// Assert: Direct-root validation still accepts the real loser and preserves
	// the winner's live output.
	loserInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     loserTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, loserInfo.Status)

	winnerUtxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: winnerTx.TxHash(), Index: 0},
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(9500), winnerUtxo.Amount)
}

// TestApplyTxReplacementRejectsIncompleteVictimSet verifies that replacement
// flows fail when the caller omits a conflicting loser for another wallet-owned
// input of the winner transaction.
//
// Scenario:
// - A winner conflicts with two direct victims across two wallet-owned inputs.
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert two confirmed funding txs, two direct victims, and the winner.
// Action:
// - ApplyTxReplacement is called with only one of the two direct victims.
// Assertions:
// - The flow fails with the incomplete direct-victim error.
// - Both omitted and supplied victims remain live and unchanged.
func TestApplyTxReplacementRejectsIncompleteVictimSet(t *testing.T) {
	t.Parallel()

	// Arrange: Create two funding outputs, two direct victims, and a winner that
	// conflicts with both wallet-owned inputs.
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
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
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
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
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
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	winnerTx := newRegularTx(
		[]wire.OutPoint{
			{Hash: fundingTxOne.TxHash(), Index: 0},
			{Hash: fundingTxTwo.TxHash(), Index: 0},
		},
		[]*wire.TxOut{{Value: 15000, PkScript: addr.ScriptPubKey}},
	)
	insertConflictingRegularTx(
		t, store, walletID, winnerTx, time.Unix(1710005040, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	// Act: Omit one direct victim when applying the replacement flow.
	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimOne.TxHash()},
	})

	// Assert: The flow fails early and leaves both direct victims unchanged.
	require.ErrorContains(
		t, err, "replacement must include every direct victim",
	)

	victimOneInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     victimOne.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, victimOneInfo.Status)

	victimTwoInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     victimTwo.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, victimTwoInfo.Status)
}

// TestApplyTxFailureRejectsIncompleteLoserSet verifies that failure flows fail
// when a winner has another wallet-owned input still claimed by an omitted
// loser transaction.
//
// Scenario:
// - A winner conflicts with two direct losers across two wallet-owned inputs.
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert two confirmed funding txs, two direct losers, and the winner.
// Action:
// - ApplyTxFailure is called with only one of the two direct losers.
// Assertions:
// - The flow fails with the incomplete direct-loser error.
// - Both omitted and supplied losers remain live and unchanged.
func TestApplyTxFailureRejectsIncompleteLoserSet(t *testing.T) {
	t.Parallel()

	// Arrange: Create two funding outputs, two direct losers, and a winner that
	// conflicts with both wallet-owned inputs.
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
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
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
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	winnerTx := newRegularTx(
		[]wire.OutPoint{
			{Hash: fundingTxOne.TxHash(), Index: 0},
			{Hash: fundingTxTwo.TxHash(), Index: 0},
		},
		[]*wire.TxOut{{Value: 18000, PkScript: addr.ScriptPubKey}},
	)
	insertConflictingRegularTx(
		t, store, walletID, winnerTx, time.Unix(1710005140, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	// Act: Omit one direct loser when applying the failure flow.
	err = store.ApplyTxFailure(t.Context(), db.ApplyTxFailureParams{
		WalletID:        walletID,
		ConflictingTxid: winnerTx.TxHash(),
		FailedTxids:     []chainhash.Hash{loserOne.TxHash()},
	})

	// Assert: The flow fails early and leaves both direct losers unchanged.
	require.ErrorContains(
		t, err, "failure must include every direct loser",
	)

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

// TestRollbackToBlockInvalidatesOrphanedCoinbaseDescendants verifies that block
// rollback recursively fails descendants of newly orphaned coinbase roots.
//
// Scenario:
// - A mature coinbase output has a confirmed child and confirmed grandchild.
// - A deep rollback disconnects the coinbase block and every later block.
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert the coinbase root plus a two-deep descendant chain in later blocks.
// Action:
// - RollbackToBlock disconnects the coinbase block.
// Assertions:
// - The coinbase root becomes orphaned blockless history.
// - The child and grandchild become failed blockless history.
// - None of the branch outputs remain in the live UTXO set.
func TestRollbackToBlockInvalidatesOrphanedCoinbaseDescendants(t *testing.T) {
	t.Parallel()

	// Arrange: Create one mature coinbase branch with confirmed descendants.
	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-rollback-orphan-descendants")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	_ = CreateBlockFixture(t, queries, 99)
	tipBlock := CreateBlockFixture(t, queries, 205)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	coinbaseBlock := CreateBlockFixture(t, queries, 100)
	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: addr.ScriptPubKey,
	}})
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004200, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	coinbaseOutPoint := wire.OutPoint{Hash: coinbaseTx.TxHash(), Index: 0}
	childBlock := CreateBlockFixture(t, queries, 201)
	childTx := newRegularTx(
		[]wire.OutPoint{coinbaseOutPoint},
		[]*wire.TxOut{{Value: 30000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710004210, 0),
		Block:    &childBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	childOutPoint := wire.OutPoint{Hash: childTx.TxHash(), Index: 0}
	descendantBlock := CreateBlockFixture(t, queries, 202)
	descendantTx := newRegularTx(
		[]wire.OutPoint{childOutPoint},
		[]*wire.TxOut{{Value: 20000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       descendantTx,
		Received: time.Unix(1710004220, 0),
		Block:    &descendantBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	// Act: Disconnect the coinbase block and every later block.
	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.NoError(t, err)

	// Assert: The orphaned root and both descendants now appear as blockless
	// invalid history, and none of their outputs remain live.
	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)
	require.Nil(t, childInfo.Block)

	descendantInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     descendantTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, descendantInfo.Status)
	require.Nil(t, descendantInfo.Block)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: coinbaseOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: childOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: descendantTx.TxHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestApplyTxReplacementRejectsMissingWinner verifies that replacement flows
// fail when the winner transaction cannot be loaded.
func TestApplyTxReplacementRejectsMissingWinner(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-replacement-missing-winner")

	err := store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: RandomHash(),
		ReplacedTxids:   []chainhash.Hash{RandomHash()},
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestApplyTxReplacementRejectsMissingVictim verifies that replacement flows
// fail when any requested victim transaction cannot be loaded.
func TestApplyTxReplacementRejectsMissingVictim(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-replacement-missing-victim")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	winnerTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710003200, 0),
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{RandomHash()},
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestApplyTxReplacementRejectsCorruptedConflictCandidate verifies that direct
// root discovery fails loudly when one conflicting candidate cannot be decoded.
func TestApplyTxReplacementRejectsCorruptedConflictCandidate(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-corrupted-replacement-candidate")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tipBlock := CreateBlockFixture(t, queries, 310)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 300)
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
		Received: time.Unix(1710003210, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	victimTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)
	insertConflictingRegularTx(
		t, store, walletID, victimTx, time.Unix(1710003220, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{Value: 7900, PkScript: []byte{0x51}}},
	)
	insertConflictingRegularTx(
		t, store, walletID, winnerTx, time.Unix(1710003230, 0),
		db.TxStatusPublished, walletCredits(),
	)

	corruptTransactionRawTx(t, store, walletID, victimTx.TxHash(), []byte{})

	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimTx.TxHash()},
	})
	require.ErrorContains(t, err, "deserialize transaction")
}

// TestRollbackToBlockAndReconfirmOrphanedCoinbase verifies the supported
// root-only rollback and reconfirmation flow for an immature coinbase.
//
// Scenario:
// - A mined coinbase creates one wallet-owned output.
// - A rollback disconnects the coinbase block.
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert the coinbase tx in a mined block and advance wallet sync state.
// Action:
// - RollbackToBlock disconnects the coinbase block.
// - ReconfirmOrphanedCoinbase later reattaches the root to a new block.
// Assertions:
// - The orphaned coinbase stays visible as orphaned history after rollback.
// - The root remains absent from the live UTXO set while orphaned.
// - Reconfirmation restores the root output without any descendant replay.
func TestRollbackToBlockAndReconfirmOrphanedCoinbase(t *testing.T) {
	t.Parallel()

	// Arrange: Create one mined coinbase for a wallet-owned address and advance
	// wallet sync state past its confirming block.
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
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	coinbaseOutPoint := wire.OutPoint{Hash: coinbaseTx.TxHash(), Index: 0}

	// Act: Roll back the confirming block so the coinbase becomes orphaned.
	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.NoError(t, err)

	// Assert: Rollback leaves the coinbase visible as orphaned unmined history.
	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)

	unminedTxs, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, unminedTxs, 1)
	require.Equal(t, coinbaseTx.TxHash(), unminedTxs[0].Hash)
	require.Equal(t, db.TxStatusOrphaned, unminedTxs[0].Status)

	// Assert: The orphaned coinbase root no longer appears in the live UTXO set.
	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: coinbaseOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)

	reconfirmBlock := CreateBlockFixture(t, queries, 101)

	// Act: Reconfirm the orphaned coinbase against a new block.
	err = store.ReconfirmOrphanedCoinbase(
		t.Context(), db.ReconfirmOrphanedCoinbaseParams{
			WalletID: walletID,
			Txid:     coinbaseTx.TxHash(),
			Block:    reconfirmBlock,
		},
	)
	require.NoError(t, err)

	// Assert: Reconfirmation restores the root tx and its live wallet-owned UTXO.
	coinbaseInfo, err = store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, coinbaseInfo.Status)
	require.NotNil(t, coinbaseInfo.Block)
	require.Equal(t, reconfirmBlock.Height, coinbaseInfo.Block.Height)

	unminedTxs, err = store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    walletID,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Empty(t, unminedTxs)

	restoredCoinbase, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: coinbaseOutPoint,
	})
	require.NoError(t, err)
	require.Equal(t, reconfirmBlock.Height, restoredCoinbase.Height)
}

// TestReconfirmOrphanedCoinbaseRejectsStoredDescendants verifies that the
// root-only reconfirmation path rejects an orphaned coinbase once a descendant
// branch has been recorded and later invalidated by rollback.
func TestReconfirmOrphanedCoinbaseRejectsStoredDescendants(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-reconfirm-stored-descendants")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	_ = CreateBlockFixture(t, queries, 99)
	tipBlock := CreateBlockFixture(t, queries, 205)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	coinbaseBlock := CreateBlockFixture(t, queries, 100)
	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: addr.ScriptPubKey,
	}})
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004250, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	coinbaseOutPoint := wire.OutPoint{Hash: coinbaseTx.TxHash(), Index: 0}
	childBlock := CreateBlockFixture(t, queries, 201)
	childTx := newRegularTx(
		[]wire.OutPoint{coinbaseOutPoint},
		[]*wire.TxOut{{Value: 30000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710004260, 0),
		Block:    &childBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	childOutPoint := wire.OutPoint{Hash: childTx.TxHash(), Index: 0}
	descendantBlock := CreateBlockFixture(t, queries, 202)
	descendantTx := newRegularTx(
		[]wire.OutPoint{childOutPoint},
		[]*wire.TxOut{{Value: 20000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       descendantTx,
		Received: time.Unix(1710004270, 0),
		Block:    &descendantBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.NoError(t, err)

	reconfirmBlock := CreateBlockFixture(t, queries, 101)
	err = store.ReconfirmOrphanedCoinbase(
		t.Context(), db.ReconfirmOrphanedCoinbaseParams{
			WalletID: walletID,
			Txid:     coinbaseTx.TxHash(),
			Block:    reconfirmBlock,
		},
	)
	require.ErrorContains(
		t, err, "coinbase reconfirmation requires no stored descendants",
	)

	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)
	require.Nil(t, childInfo.Block)

	descendantInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     descendantTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, descendantInfo.Status)
	require.Nil(t, descendantInfo.Block)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: coinbaseOutPoint,
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestReconfirmOrphanedCoinbaseRejectsMismatchedExistingBlock verifies that
// reconfirmation fails when the target height is already occupied by different
// block metadata.
//
// Scenario:
//   - One orphaned coinbase root is later rebound to a height that already has a
//     different block row.
//
// Setup:
// - Create one wallet, one default account, and one wallet-owned address.
// - Insert and roll back one coinbase transaction so it becomes orphaned.
// - Insert a stale block row at the would-be reconfirmation height.
// Action:
//   - ReconfirmOrphanedCoinbase attempts to reuse that height with different hash
//     and timestamp metadata.
//
// Assertions:
// - Reconfirmation fails before rewriting the orphaned coinbase root.
// - The root remains orphaned blockless history.
func TestReconfirmOrphanedCoinbaseRejectsMismatchedExistingBlock(t *testing.T) {
	t.Parallel()

	// Arrange: Create one orphaned coinbase root and one stale block row at the
	// target reconfirmation height.
	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-reconfirm-conflicting-block")
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
		Received: time.Unix(1710004300, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.NoError(t, err)

	staleBlock := CreateBlockFixture(t, queries, 101)
	conflictingBlock := db.Block{
		Hash:      RandomHash(),
		Height:    staleBlock.Height,
		Timestamp: staleBlock.Timestamp.Add(time.Second),
	}

	// Act: Attempt to reconfirm the orphaned coinbase against mismatched block
	// metadata for an occupied height.
	err = store.ReconfirmOrphanedCoinbase(
		t.Context(), db.ReconfirmOrphanedCoinbaseParams{
			WalletID: walletID,
			Txid:     coinbaseTx.TxHash(),
			Block:    conflictingBlock,
		},
	)

	// Assert: The mismatch is rejected and the root stays orphaned.
	require.ErrorContains(t, err, "block height")

	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)
}

// TestOrphanTxGraph verifies the direct orphan wrapper for already-orphaned
// coinbase roots with still-live descendants.
func TestOrphanTxGraph(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-direct-orphan-chain")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	coinbaseBlock := CreateBlockFixture(t, queries, 300)

	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: addr.ScriptPubKey,
	}})
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004400, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: coinbaseTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{
			Value:    49000,
			PkScript: addr.ScriptPubKey,
		}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       childTx,
		Received: time.Unix(1710004410, 0),
		Status:   db.TxStatusPending,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	descendantTx := newRegularTx(
		[]wire.OutPoint{{Hash: childTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{
			Value:    48000,
			PkScript: []byte{0x51},
		}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       descendantTx,
		Received: time.Unix(1710004420, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	forceOrphanedCoinbaseTx(t, store, walletID, coinbaseTx.TxHash())

	err = store.OrphanTxGraph(t.Context(), db.OrphanTxGraphParams{
		WalletID: walletID,
		Txids:    []chainhash.Hash{coinbaseTx.TxHash()},
	})
	require.NoError(t, err)

	coinbaseInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, coinbaseInfo.Status)
	require.Nil(t, coinbaseInfo.Block)

	childInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     childTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)

	descendantInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     descendantTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, descendantInfo.Status)

	_, err = store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: walletID,
		OutPoint: wire.OutPoint{Hash: childTx.TxHash(), Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestOrphanTxGraphRejectsLiveRoot verifies that orphan propagation requires an
// already-orphaned coinbase root.
func TestOrphanTxGraphRejectsLiveRoot(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-orphan-live-root")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	liveTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       liveTx,
		Received: time.Unix(1710004500, 0),
		Status:   db.TxStatusPending,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	err = store.OrphanTxGraph(t.Context(), db.OrphanTxGraphParams{
		WalletID: walletID,
		Txids:    []chainhash.Hash{liveTx.TxHash()},
	})
	require.ErrorContains(t, err, "orphan root must be an orphaned coinbase transaction")

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     liveTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, info.Status)
}

// TestOrphanTxGraphRejectsMissingRoot verifies the direct wrapper's not-found
// path when one requested orphan root does not exist.
func TestOrphanTxGraphRejectsMissingRoot(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-orphan-missing-root")

	err := store.OrphanTxGraph(t.Context(), db.OrphanTxGraphParams{
		WalletID: walletID,
		Txids:    []chainhash.Hash{RandomHash()},
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestApplyTxReplacementRejectsCorruptedWinnerRawTx verifies that direct-root
// validation fails loudly when the stored winner transaction cannot be decoded.
func TestApplyTxReplacementRejectsCorruptedWinnerRawTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-replacement-corrupted-winner")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tipBlock := CreateBlockFixture(t, queries, 305)
	err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
		WalletID: walletID,
		SyncedTo: &tipBlock,
	})
	require.NoError(t, err)

	fundingBlock := CreateBlockFixture(t, queries, 300)
	fundingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{
			Value:    8000,
			PkScript: addr.ScriptPubKey,
		}},
	)
	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       fundingTx,
		Received: time.Unix(1710004650, 0),
		Block:    &fundingBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	fundingOutPoint := wire.OutPoint{Hash: fundingTx.TxHash(), Index: 0}
	victimTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    7000,
			PkScript: addr.ScriptPubKey,
		}},
	)
	insertConflictingRegularTx(
		t, store, walletID, victimTx, time.Unix(1710004660, 0),
		db.TxStatusPublished, walletCredits(0),
	)

	winnerTx := newRegularTx(
		[]wire.OutPoint{fundingOutPoint},
		[]*wire.TxOut{{
			Value:    6900,
			PkScript: []byte{0x51},
		}},
	)
	insertConflictingRegularTx(
		t, store, walletID, winnerTx, time.Unix(1710004670, 0),
		db.TxStatusPublished, walletCredits(),
	)

	corruptTransactionRawTx(t, store, walletID, winnerTx.TxHash(), []byte{})

	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimTx.TxHash()},
	})
	require.ErrorContains(t, err, "deserialize transaction")
}

// TestApplyTxReplacementRejectsCorruptedWinnerStatus verifies that replacement
// flows reject a stored winner row whose status no longer decodes.
// TestApplyTxReplacementRejectsCorruptedWinnerStatus verifies that replacement
// validation fails when the stored winner status no longer decodes.
func TestApplyTxReplacementRejectsCorruptedWinnerStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-replacement-corrupted-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	winnerTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 4000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       winnerTx,
		Received: time.Unix(1710004680, 0),
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, winnerTx.TxHash(), 99)

	err = store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{RandomHash()},
	})
	require.ErrorContains(t, err, "invalid transaction status")
}

// TestApplyTxReplacementRejectsLargeWinnerInputIndex verifies that direct-root
// discovery rejects winner inputs that exceed the signed SQL outpoint range.
func TestApplyTxReplacementRejectsLargeWinnerInputIndex(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-replacement-large-winner-index")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	victimTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2000, PkScript: []byte{0x51}}},
	)
	insertConflictingRegularTx(
		t, store, walletID, victimTx, time.Unix(1710004690, 0),
		db.TxStatusPublished, walletCredits(),
	)

	winnerTx := newRegularTx(
		[]wire.OutPoint{{Hash: randomHash(), Index: ^uint32(0)}},
		[]*wire.TxOut{{Value: 1900, PkScript: []byte{0x52}}},
	)
	insertConflictingRegularTx(
		t, store, walletID, winnerTx, time.Unix(1710004700, 0),
		db.TxStatusPublished, walletCredits(),
	)

	err := store.ApplyTxReplacement(t.Context(), db.ApplyTxReplacementParams{
		WalletID:        walletID,
		ReplacementTxid: winnerTx.TxHash(),
		ReplacedTxids:   []chainhash.Hash{victimTx.TxHash()},
	})
	require.ErrorContains(t, err, "convert input outpoint index 0")
}

// TestReconfirmOrphanedCoinbaseRejectsMissingTx verifies the direct wrapper's
// not-found path before any block mutation occurs.
func TestReconfirmOrphanedCoinbaseRejectsMissingTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-reconfirm-missing")

	err := store.ReconfirmOrphanedCoinbase(
		t.Context(), db.ReconfirmOrphanedCoinbaseParams{
			WalletID: walletID,
			Txid:     RandomHash(),
			Block:    NewBlockFixture(301),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestReconfirmOrphanedCoinbaseRejectsLiveTx verifies that reconfirmation only
// accepts already-orphaned coinbase rows.
func TestReconfirmOrphanedCoinbaseRejectsLiveTx(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-reconfirm-live-tx")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	coinbaseBlock := CreateBlockFixture(t, queries, 302)
	coinbaseTx := newCoinbaseTx([]*wire.TxOut{{
		Value:    50000,
		PkScript: addr.ScriptPubKey,
	}})
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: walletID,
		Tx:       coinbaseTx,
		Received: time.Unix(1710004600, 0),
		Block:    &coinbaseBlock,
		Status:   db.TxStatusPublished,
		Credits:  walletCredits(0),
	})
	require.NoError(t, err)

	err = store.ReconfirmOrphanedCoinbase(
		t.Context(), db.ReconfirmOrphanedCoinbaseParams{
			WalletID: walletID,
			Txid:     coinbaseTx.TxHash(),
			Block:    NewBlockFixture(303),
		},
	)
	require.ErrorContains(t, err, "coinbase reconfirmation requires an orphaned coinbase transaction")

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: walletID,
		Txid:     coinbaseTx.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, info.Status)
	require.NotNil(t, info.Block)
	require.Equal(t, coinbaseBlock.Height, info.Block.Height)
}

// walletCredits builds the credited-output map expected by CreateTx helpers.
func walletCredits(indexes ...uint32) map[uint32]btcutil.Address {
	credits := make(map[uint32]btcutil.Address, len(indexes))
	for _, index := range indexes {
		credits[index] = nil
	}

	return credits
}
