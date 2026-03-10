package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

var errUnexpectedTraversalCall = errors.New("unexpected traversal call")

// TestCollectTxChainDescendantIDs verifies the shared descendant graph walk.
//
// Scenario:
// - One spend graph contains a shared descendant reachable from two parents.
// Setup:
// - Build one in-memory child map that models the wallet spend graph.
// Action:
// - Traverse descendants from the root with collectTxChainDescendantIDs.
// Assertions:
// - Each descendant is returned once in breadth-first discovery order.
func TestCollectTxChainDescendantIDs(t *testing.T) {
	t.Parallel()

	children := map[int64][]int64{
		1: {2, 3},
		2: {4},
		3: {4, 5},
		4: nil,
		5: nil,
	}

	descendants, err := collectTxChainDescendantIDs(
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
		Status: TxStatusPublished,
	}

	tests := []struct {
		name    string
		winner  txChainMeta
		victims []txChainMeta
		wantErr error
	}{
		{
			name:    "valid plan",
			winner:  winner,
			victims: []txChainMeta{victim},
		},
		{
			name:    "missing victims",
			winner:  winner,
			wantErr: errReplacementRequiresVictims,
		},
		{
			name:    "self replacement",
			winner:  winner,
			victims: []txChainMeta{winner},
			wantErr: errSelfConflict,
		},
		{
			name:    "winner missing live status",
			winner:  txChainMeta{Txid: chainhash.Hash{3}, Status: TxStatus(9)},
			victims: []txChainMeta{victim},
			wantErr: errReplacementWinnerInvalid,
		},
		{
			name: "winner already confirmed",
			winner: txChainMeta{
				Txid:     chainhash.Hash{6},
				Status:   TxStatusPublished,
				HasBlock: true,
			},
			victims: []txChainMeta{victim},
			wantErr: errReplacementWinnerInvalid,
		},
		{
			name:   "victim already confirmed",
			winner: winner,
			victims: []txChainMeta{{
				Txid:     chainhash.Hash{4},
				Status:   TxStatusPublished,
				HasBlock: true,
			}},
			wantErr: errReplacementVictimInvalid,
		},
		{
			name:   "victim already terminal",
			winner: winner,
			victims: []txChainMeta{{
				Txid:   chainhash.Hash{5},
				Status: TxStatusReplaced,
			}},
			wantErr: errReplacementVictimInvalid,
		},
		{
			name:   "victim still pending",
			winner: winner,
			victims: []txChainMeta{{
				Txid:   chainhash.Hash{7},
				Status: TxStatusPending,
			}},
			wantErr: errReplacementVictimInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Reuse the table-provided root metadata.

			// Act: Validate the replacement plan.
			err := validateReplacementPlan(test.winner, test.victims)

			// Assert: Each scenario returns the expected outcome.
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestValidateFailurePlan verifies shared failure root validation.
//
// Scenario:
// - Failure plans include valid losers plus invalid edge cases.
// Setup:
//   - Build winner and loser metadata covering live, coinbase, and terminal
//     states.
//
// Action:
// - Validate each failure plan through validateFailurePlan.
// Assertions:
// - Valid plans pass.
// - Missing or invalid loser sets fail.
func TestValidateFailurePlan(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{Txid: chainhash.Hash{1}, Status: TxStatusPublished}
	failedRoot := txChainMeta{Txid: chainhash.Hash{2}, Status: TxStatusPending}

	tests := []struct {
		name    string
		winner  txChainMeta
		roots   []txChainMeta
		wantErr error
	}{
		{
			name:   "valid plan",
			winner: winner,
			roots:  []txChainMeta{failedRoot},
		},
		{
			name:    "missing roots",
			winner:  winner,
			wantErr: errFailureRequiresRoots,
		},
		{
			name:    "self conflict",
			winner:  winner,
			roots:   []txChainMeta{winner},
			wantErr: errSelfConflict,
		},
		{
			name:   "coinbase root invalid",
			winner: winner,
			roots: []txChainMeta{{
				Txid:       chainhash.Hash{4},
				Status:     TxStatusPending,
				IsCoinbase: true,
			}},
			wantErr: errFailureRootInvalid,
		},
		{
			name:   "terminal root invalid",
			winner: winner,
			roots: []txChainMeta{{
				Txid:   chainhash.Hash{5},
				Status: TxStatusFailed,
			}},
			wantErr: errFailureRootInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Reuse the table-provided winner and loser metadata.

			// Act: Validate the failure plan.
			err := validateFailurePlan(test.winner, test.roots)

			// Assert: Each scenario returns the expected outcome.
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestValidateOrphanPlan verifies shared orphan-root validation.
//
// Scenario:
//   - Orphan plans include one valid orphaned coinbase root and one invalid
//     live non-coinbase row.
//
// Setup:
// - Build metadata for the valid and invalid root states.
// Action:
// - Validate each orphan plan through validateOrphanPlan.
// Assertions:
// - Only orphaned coinbase roots are accepted.
func TestValidateOrphanPlan(t *testing.T) {
	t.Parallel()

	orphanRoot := txChainMeta{
		Txid:       chainhash.Hash{3},
		Status:     TxStatusOrphaned,
		IsCoinbase: true,
	}
	failedRoot := txChainMeta{Txid: chainhash.Hash{2}, Status: TxStatusPending}

	// Arrange: Build one valid and one invalid orphan-root set.

	// Act: Validate the supported orphan plan.
	err := validateOrphanPlan([]txChainMeta{orphanRoot})

	// Assert: The orphaned coinbase root is accepted.
	require.NoError(t, err)

	// Act: Validate one invalid non-orphan root.
	err = validateOrphanPlan([]txChainMeta{failedRoot})

	// Assert: Non-orphan roots are rejected.
	require.ErrorIs(t, err, errOrphanRootInvalid)
}

// TestValidateCoinbaseReconfirmation verifies shared orphaned-coinbase
// reconfirmation validation.
//
// Scenario:
//   - Reconfirmation plans include one valid orphaned coinbase root and one
//     invalid live non-coinbase row.
//
// Setup:
// - Build metadata for the valid and invalid root states.
// Action:
// - Validate each reconfirmation target through validateCoinbaseReconfirmation.
// Assertions:
// - Only orphaned coinbase roots are accepted.
func TestValidateCoinbaseReconfirmation(t *testing.T) {
	t.Parallel()

	orphanRoot := txChainMeta{
		Txid:       chainhash.Hash{3},
		Status:     TxStatusOrphaned,
		IsCoinbase: true,
	}
	failedRoot := txChainMeta{Txid: chainhash.Hash{2}, Status: TxStatusPending}

	// Arrange: Build one valid orphaned coinbase and one invalid row.

	// Act: Validate the supported orphaned-coinbase target.
	err := validateCoinbaseReconfirmation(orphanRoot)

	// Assert: The orphaned coinbase root is accepted.
	require.NoError(t, err)

	// Act: Validate an invalid non-orphaned row.
	err = validateCoinbaseReconfirmation(failedRoot)

	// Assert: Non-orphaned roots are rejected.
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
		Status: TxStatusPublished,
	}
	descendant := txChainMeta{
		ID:     3,
		Txid:   chainhash.Hash{3},
		Status: TxStatusPublished,
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
		Status: TxStatusPublished,
	}
	victimTwo := txChainMeta{
		ID:     3,
		Txid:   chainhash.Hash{3},
		Status: TxStatusPublished,
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

// TestCollectTxChainDescendantIDsContext verifies traversal cancellation
// handling.
//
// Scenario:
// - The caller context is already canceled before traversal begins.
// Setup:
// - Create one canceled context and one child callback that must not run.
// Action:
// - Start collectTxChainDescendantIDs with the canceled context.
// Assertions:
// - The walk returns context.Canceled without visiting any nodes.
func TestCollectTxChainDescendantIDsContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := collectTxChainDescendantIDs(
		ctx, []int64{1},
		func(_ context.Context, _ int64) ([]int64, error) {
			return nil, errUnexpectedTraversalCall
		},
	)
	require.ErrorIs(t, err, context.Canceled)
}
