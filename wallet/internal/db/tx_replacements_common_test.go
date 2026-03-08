package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

var errUnexpectedTraversalCall = errors.New("unexpected traversal call")

// TestCollectDescendantTxIDs verifies the shared descendant graph walk.
//
// Scenario:
// - One spend graph contains a shared descendant reachable from two parents.
// Setup:
// - Build one in-memory child map that models the wallet spend graph.
// Action:
// - Traverse descendants from the root with collectDescendantTxIDs.
// Assertions:
// - Each descendant is returned once in breadth-first discovery order.
func TestCollectDescendantTxIDs(t *testing.T) {
	t.Parallel()

	children := map[int64][]int64{
		1: {2, 3},
		2: {4},
		3: {4, 5},
		4: nil,
		5: nil,
	}

	descendants, err := collectDescendantTxIDs(
		t.Context(), []int64{1},
		func(_ context.Context, parentID int64) ([]int64, error) {
			return children[parentID], nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, []int64{2, 3, 4, 5}, descendants)
}

// TestApplyTxChainInvalidation verifies the shared invalidation walk.
//
// Scenario:
// - One root transaction has a two-level descendant chain.
// Setup:
// - Provide hooks that record traversal, clearing, and status updates.
// Action:
// - Invalidate the root as replaced.
// Assertions:
// - Root and descendant inputs are cleared in graph order.
// - Roots receive the requested status while descendants become failed.
func TestApplyTxChainInvalidation(t *testing.T) {
	t.Parallel()

	var cleared []int64

	statusUpdates := make(map[TxStatus][]int64)

	err := applyTxChainInvalidation(
		t.Context(), []int64{1}, TxStatusReplaced, txChainHooks{
			ListChildren: func(_ context.Context, txID int64) ([]int64, error) {
				switch txID {
				case 1:
					return []int64{2}, nil
				case 2:
					return []int64{3}, nil
				default:
					return nil, nil
				}
			},
			ClearSpentByTx: func(_ context.Context, txID int64) error {
				cleared = append(cleared, txID)
				return nil
			},
			UpdateStatus: func(_ context.Context, status TxStatus,
				txIDs []int64) error {

				statusUpdates[status] = append([]int64(nil), txIDs...)
				return nil
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, []int64{1, 2, 3}, cleared)
	require.Equal(t, []int64{1}, statusUpdates[TxStatusReplaced])
	require.Equal(t, []int64{2, 3}, statusUpdates[TxStatusFailed])
}

// TestValidateReplacementPlan verifies shared replacement root validation.
//
// Scenario:
// - Replacement plans include valid roots plus several invalid edge cases.
// Setup:
//   - Build winner and victim metadata covering live, confirmed, and terminal
//     states.
//
// Action:
// - Validate each replacement plan through validateReplacementPlan.
// Assertions:
//   - Valid plans pass.
//   - Missing victims, self-replacement, and invalid winner or victim states
//     fail.
func TestValidateReplacementPlan(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		Txid:   chainhash.Hash{1},
		Status: TxStatusPublished,
	}
	victim := txChainMeta{
		Txid:   chainhash.Hash{2},
		Status: TxStatusPending,
	}

	err := validateReplacementPlan(winner, []txChainMeta{victim})
	require.NoError(t, err)

	err = validateReplacementPlan(winner, nil)
	require.ErrorIs(t, err, errReplacementRequiresVictims)

	err = validateReplacementPlan(winner, []txChainMeta{winner})
	require.ErrorIs(t, err, errSelfReplacement)

	err = validateReplacementPlan(txChainMeta{Txid: chainhash.Hash{3}},
		[]txChainMeta{victim})
	require.ErrorIs(t, err, errReplacementWinnerInvalid)

	err = validateReplacementPlan(txChainMeta{
		Txid:     chainhash.Hash{6},
		Status:   TxStatusPublished,
		HasBlock: true,
	}, []txChainMeta{victim})
	require.ErrorIs(t, err, errReplacementWinnerInvalid)

	err = validateReplacementPlan(winner, []txChainMeta{{
		Txid:     chainhash.Hash{4},
		Status:   TxStatusPublished,
		HasBlock: true,
	}})
	require.ErrorIs(t, err, errReplacementVictimInvalid)

	err = validateReplacementPlan(winner, []txChainMeta{{
		Txid:   chainhash.Hash{5},
		Status: TxStatusReplaced,
	}})
	require.ErrorIs(t, err, errReplacementVictimInvalid)
}

// TestValidateFailureAndOrphanPlans verifies shared failure and orphan
// validation helpers.
//
// Scenario:
//   - Failure, orphan, and coinbase reconfirmation plans cover valid and
//     invalid transaction states.
//
// Setup:
// - Build metadata for live roots, orphaned coinbase roots, and invalid rows.
// Action:
// - Validate each plan through the shared helpers.
// Assertions:
// - Valid failure and orphan flows pass.
// - Invalid coinbase, failed, and non-orphan roots are rejected.
func TestValidateFailureAndOrphanPlans(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{Txid: chainhash.Hash{1}, Status: TxStatusPublished}
	failedRoot := txChainMeta{Txid: chainhash.Hash{2}, Status: TxStatusPending}
	orphanRoot := txChainMeta{
		Txid:       chainhash.Hash{3},
		Status:     TxStatusOrphaned,
		IsCoinbase: true,
	}

	require.NoError(t, validateFailurePlan(winner, []txChainMeta{failedRoot}))
	require.ErrorIs(
		t, validateFailurePlan(winner, nil), errFailureRequiresRoots,
	)
	require.NoError(t, validateOrphanPlan([]txChainMeta{orphanRoot}))
	require.NoError(t, validateCoinbaseReconfirmation(orphanRoot))

	err := validateFailurePlan(winner, []txChainMeta{{
		Txid:       chainhash.Hash{4},
		Status:     TxStatusPending,
		IsCoinbase: true,
	}})
	require.ErrorIs(t, err, errFailureRootInvalid)

	err = validateFailurePlan(winner, []txChainMeta{{
		Txid:   chainhash.Hash{5},
		Status: TxStatusFailed,
	}})
	require.ErrorIs(t, err, errFailureRootInvalid)

	err = validateOrphanPlan([]txChainMeta{failedRoot})
	require.ErrorIs(t, err, errOrphanRootInvalid)

	err = validateCoinbaseReconfirmation(failedRoot)
	require.ErrorIs(t, err, errCoinbaseReconfirmationInvalid)
}

// TestApplyTxReplacementCommonRejectsDescendantRoot verifies direct replacement
// root validation.
//
// Scenario:
//   - A caller submits one real direct victim plus one descendant as another
//     root.
//
// Setup:
//   - Build winner, victim, and descendant metadata plus hooks that expose only
//     the real direct victim.
//
// Action:
// - Run applyTxReplacementCommon with the invalid root set.
// Assertions:
// - The flow fails with errReplacementVictimNotDirect.
// - No replacement edge is recorded.
func TestApplyTxReplacementCommonRejectsDescendantRoot(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID:     1,
		Txid:   chainhash.Hash{1},
		Status: TxStatusPublished,
	}
	victim := txChainMeta{
		ID:     2,
		Txid:   chainhash.Hash{2},
		Status: TxStatusPending,
	}
	descendant := txChainMeta{
		ID:     3,
		Txid:   chainhash.Hash{3},
		Status: TxStatusPending,
	}

	called := false
	err := applyTxReplacementCommon(
		t.Context(),
		ApplyTxReplacementParams{ReplacementTxid: winner.Txid},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{victim, descendant}, nil
		},
		txChainHooks{
			ListDirectConflictRootsByTxid: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{victim}, nil
			},
			RecordReplacementEdge: func(context.Context, int64, int64) error {
				called = true
				return nil
			},
		},
	)
	require.ErrorIs(t, err, errReplacementVictimNotDirect)
	require.False(t, called)
}

// TestApplyTxReplacementCommonRejectsIncompleteRootSet verifies that
// replacement callers must provide the full direct victim set.
//
// Scenario:
//   - A winner conflicts with two direct victims, but the caller supplies only
//     one.
//
// Setup:
// - Build winner and victim metadata plus hooks that report both direct roots.
// Action:
// - Run applyTxReplacementCommon with the incomplete root set.
// Assertions:
// - The flow fails with errReplacementVictimSetIncomplete.
// - No replacement edge is recorded.
func TestApplyTxReplacementCommonRejectsIncompleteRootSet(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID:     1,
		Txid:   chainhash.Hash{1},
		Status: TxStatusPublished,
	}
	victimOne := txChainMeta{
		ID:     2,
		Txid:   chainhash.Hash{2},
		Status: TxStatusPending,
	}
	victimTwo := txChainMeta{
		ID:     3,
		Txid:   chainhash.Hash{3},
		Status: TxStatusPending,
	}

	called := false
	err := applyTxReplacementCommon(
		t.Context(),
		ApplyTxReplacementParams{ReplacementTxid: winner.Txid},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{victimOne}, nil
		},
		txChainHooks{
			ListDirectConflictRootsByTxid: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{victimOne, victimTwo}, nil
			},
			RecordReplacementEdge: func(context.Context, int64, int64) error {
				called = true
				return nil
			},
		},
	)
	require.ErrorIs(t, err, errReplacementVictimSetIncomplete)
	require.False(t, called)
}

// TestApplyTxFailureCommonRejectsUnrelatedRoot verifies direct failure root
// validation.
//
// Scenario:
// - A caller submits one real direct loser plus one unrelated live tx.
// Setup:
//   - Build winner, loser, and unrelated metadata plus hooks that expose only
//     the real direct loser.
//
// Action:
// - Run applyTxFailureCommon with the invalid root set.
// Assertions:
// - The flow fails with errFailureRootNotDirect.
// - Winner input reclamation does not run.
func TestApplyTxFailureCommonRejectsUnrelatedRoot(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID:     1,
		Txid:   chainhash.Hash{1},
		Status: TxStatusPublished,
	}
	loser := txChainMeta{
		ID:     2,
		Txid:   chainhash.Hash{2},
		Status: TxStatusPending,
	}
	unrelated := txChainMeta{
		ID:     3,
		Txid:   chainhash.Hash{3},
		Status: TxStatusPending,
	}

	called := false
	err := applyTxFailureCommon(
		t.Context(),
		ApplyTxFailureParams{ConflictingTxid: winner.Txid},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{loser, unrelated}, nil
		},
		txChainHooks{
			ListDirectConflictRootsByTxid: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{loser}, nil
			},
			ReclaimInputsByTxid: func(context.Context,
				chainhash.Hash, int64) error {

				called = true
				return nil
			},
		},
	)
	require.ErrorIs(t, err, errFailureRootNotDirect)
	require.False(t, called)
}

// TestApplyTxFailureCommonRejectsIncompleteRootSet verifies that failure
// callers must provide the full direct loser set.
//
// Scenario:
// - A winner conflicts with two direct losers but the caller supplies only one.
// Setup:
// - Build winner and loser metadata plus hooks that report both direct roots.
// Action:
// - Run applyTxFailureCommon with the incomplete root set.
// Assertions:
// - The flow fails with errFailureRootSetIncomplete.
// - Winner input reclamation does not run.
func TestApplyTxFailureCommonRejectsIncompleteRootSet(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID:     1,
		Txid:   chainhash.Hash{1},
		Status: TxStatusPublished,
	}
	loserOne := txChainMeta{
		ID:     2,
		Txid:   chainhash.Hash{2},
		Status: TxStatusPending,
	}
	loserTwo := txChainMeta{
		ID:     3,
		Txid:   chainhash.Hash{3},
		Status: TxStatusPending,
	}

	called := false
	err := applyTxFailureCommon(
		t.Context(),
		ApplyTxFailureParams{ConflictingTxid: winner.Txid},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{loserOne}, nil
		},
		txChainHooks{
			ListDirectConflictRootsByTxid: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{loserOne, loserTwo}, nil
			},
			ReclaimInputsByTxid: func(context.Context,
				chainhash.Hash, int64) error {

				called = true
				return nil
			},
		},
	)
	require.ErrorIs(t, err, errFailureRootSetIncomplete)
	require.False(t, called)
}

// TestCollectDescendantTxIDsContext verifies traversal cancellation handling.
//
// Scenario:
// - The caller context is already canceled before traversal begins.
// Setup:
// - Create one canceled context and one child callback that must not run.
// Action:
// - Start collectDescendantTxIDs with the canceled context.
// Assertions:
// - The walk returns context.Canceled without visiting any nodes.
func TestCollectDescendantTxIDsContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := collectDescendantTxIDs(
		ctx, []int64{1},
		func(_ context.Context, _ int64) ([]int64, error) {
			return nil, errUnexpectedTraversalCall
		},
	)
	require.ErrorIs(t, err, context.Canceled)
}
