package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

var errUnexpectedTraversalCall = errors.New("unexpected traversal call")

// TestCollectDescendantTxIDs verifies that the shared graph walk visits each
// descendant once and preserves breadth-first discovery order.
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

// TestApplyTxChainInvalidation verifies that the common invalidation helper
// clears inputs for roots and descendants while applying root/descendant
// statuses separately.
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

// TestValidateReplacementPlan verifies the shared root validation for direct
// replacement victims and their winning transaction.
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

	err = validateReplacementPlan(winner, []txChainMeta{{
		Txid:     chainhash.Hash{4},
		Status:   TxStatusPublished,
		HasBlock: true,
	}})
	require.ErrorIs(t, err, errReplacementVictimInvalid)
}

// TestValidateFailureAndOrphanPlans verifies the shared validation for failure,
// orphan propagation, and coinbase reconfirmation flows.
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
	require.ErrorIs(t, validateFailurePlan(winner, nil), errFailureRequiresRoots)
	require.NoError(t, validateOrphanPlan([]txChainMeta{orphanRoot}))
	require.NoError(t, validateCoinbaseReconfirmation(orphanRoot))

	err := validateFailurePlan(winner, []txChainMeta{{
		Txid:       chainhash.Hash{4},
		Status:     TxStatusPending,
		IsCoinbase: true,
	}})
	require.ErrorIs(t, err, errFailureRootInvalid)

	err = validateOrphanPlan([]txChainMeta{failedRoot})
	require.ErrorIs(t, err, errOrphanRootInvalid)

	err = validateCoinbaseReconfirmation(failedRoot)
	require.ErrorIs(t, err, errCoinbaseReconfirmationInvalid)
}

// TestCollectDescendantTxIDsContext verifies that the traversal stops when the
// caller context has already been canceled.
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
