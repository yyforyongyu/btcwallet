package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

var (
	errTestLoadWinner       = errors.New("load winner failed")
	errTestLoadVictims      = errors.New("load victims failed")
	errTestRecordEdge       = errors.New("record failed")
	errTestReclaimInputs    = errors.New("reclaim failed")
	errTestLoadRoots        = errors.New("load roots failed")
	errTestListDirectRoots  = errors.New("list direct roots failed")
	errTestListChildren     = errors.New("list children failed")
	errTestCollect          = errors.New("collect failed")
	errTestClearRoot        = errors.New("clear root failed")
	errTestClearDescendant  = errors.New("clear descendant failed")
	errTestUpdateRoot       = errors.New("update root failed")
	errTestUpdateDescendant = errors.New("update descendant failed")
	errTestUpdate           = errors.New("update failed")
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

func TestApplyTxReplacementCommonSuccess(t *testing.T) {
	t.Parallel()

	type statusUpdateCall struct {
		status TxStatus
		txIDs  []int64
	}

	winner := txChainMeta{
		ID: 1, Txid: chainhash.Hash{1}, Status: TxStatusPublished,
	}
	victimOne := txChainMeta{
		ID: 2, Txid: chainhash.Hash{2}, Status: TxStatusPublished,
	}
	victimTwo := txChainMeta{
		ID: 3, Txid: chainhash.Hash{3}, Status: TxStatusPublished,
	}

	var (
		cleared          []int64
		replacementEdges [][2]int64
		statusUpdates    []statusUpdateCall
	)

	reclaimCalls := 0

	err := applyTxReplacementCommon(
		t.Context(),
		ApplyTxReplacementParams{
			ReplacementTxid: winner.Txid,
			ReplacedTxids:   []chainhash.Hash{victimTwo.Txid, victimOne.Txid},
		},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{victimOne, victimTwo}, nil
		},
		txChainHooks{
			ListChildren: func(_ context.Context, txID int64) ([]int64, error) {
				switch txID {
				case victimOne.ID:
					return []int64{4}, nil
				case victimTwo.ID:
					return []int64{5}, nil
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

				statusUpdates = append(statusUpdates, statusUpdateCall{
					status: status,
					txIDs:  append([]int64(nil), txIDs...),
				})

				return nil
			},
			ReclaimInputsByTxid: func(_ context.Context,
				txid chainhash.Hash, txID int64) error {

				reclaimCalls++
				require.Equal(t, winner.Txid, txid)
				require.Equal(t, winner.ID, txID)

				return nil
			},
			RecordReplacementEdge: func(_ context.Context,
				replacedTxID, replacementTxID int64) error {

				replacementEdges = append(
					replacementEdges, [2]int64{replacedTxID, replacementTxID},
				)

				return nil
			},
			ListDirectConflictRootsByTxid: func(_ context.Context,
				txid chainhash.Hash) ([]txChainMeta, error) {

				require.Equal(t, winner.Txid, txid)
				return []txChainMeta{victimOne, victimTwo}, nil
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, []int64{2, 3, 4, 5}, cleared)
	require.ElementsMatch(t, [][2]int64{{2, 1}, {3, 1}}, replacementEdges)
	require.Len(t, statusUpdates, 2)
	require.Equal(t, TxStatusReplaced, statusUpdates[0].status)
	require.Equal(t, []int64{2, 3}, statusUpdates[0].txIDs)
	require.Equal(t, TxStatusFailed, statusUpdates[1].status)
	require.Equal(t, []int64{4, 5}, statusUpdates[1].txIDs)
	require.Equal(t, 1, reclaimCalls)
}

func TestApplyTxFailureCommonSuccess(t *testing.T) {
	t.Parallel()

	type statusUpdateCall struct {
		status TxStatus
		txIDs  []int64
	}

	winner := txChainMeta{
		ID: 1, Txid: chainhash.Hash{1}, Status: TxStatusPublished,
	}
	rootOne := txChainMeta{
		ID: 2, Txid: chainhash.Hash{2}, Status: TxStatusPending,
	}
	rootTwo := txChainMeta{
		ID: 3, Txid: chainhash.Hash{3}, Status: TxStatusPublished,
	}

	var (
		cleared       []int64
		statusUpdates []statusUpdateCall
	)

	reclaimCalls := 0

	err := applyTxFailureCommon(
		t.Context(),
		ApplyTxFailureParams{
			ConflictingTxid: winner.Txid,
			FailedTxids:     []chainhash.Hash{rootOne.Txid, rootTwo.Txid},
		},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{rootOne, rootTwo}, nil
		},
		txChainHooks{
			ListChildren: func(_ context.Context, txID int64) ([]int64, error) {
				switch txID {
				case rootOne.ID:
					return []int64{4}, nil
				case 4:
					return []int64{5}, nil
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

				statusUpdates = append(statusUpdates, statusUpdateCall{
					status: status,
					txIDs:  append([]int64(nil), txIDs...),
				})

				return nil
			},
			ReclaimInputsByTxid: func(_ context.Context,
				txid chainhash.Hash, txID int64) error {

				reclaimCalls++
				require.Equal(t, winner.Txid, txid)
				require.Equal(t, winner.ID, txID)

				return nil
			},
			ListDirectConflictRootsByTxid: func(_ context.Context,
				txid chainhash.Hash) ([]txChainMeta, error) {

				require.Equal(t, winner.Txid, txid)
				return []txChainMeta{rootOne, rootTwo}, nil
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, []int64{2, 3, 4, 5}, cleared)
	require.Len(t, statusUpdates, 2)
	require.Equal(t, TxStatusFailed, statusUpdates[0].status)
	require.Equal(t, []int64{2, 3}, statusUpdates[0].txIDs)
	require.Equal(t, TxStatusFailed, statusUpdates[1].status)
	require.Equal(t, []int64{4, 5}, statusUpdates[1].txIDs)
	require.Equal(t, 1, reclaimCalls)
}

func TestApplyTxReplacementCommonErrorPaths(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID: 1, Txid: chainhash.Hash{1}, Status: TxStatusPublished,
	}
	victim := txChainMeta{
		ID: 2, Txid: chainhash.Hash{2}, Status: TxStatusPublished,
	}

	tests := []struct {
		name       string
		loadWinner func(context.Context, chainhash.Hash) (txChainMeta, error)
		loadVictim func(
			context.Context, []chainhash.Hash,
		) ([]txChainMeta, error)
		hooks   txChainHooks
		wantErr error
	}{
		{
			name: "winner load error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return txChainMeta{}, errTestLoadWinner
			},
			loadVictim: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return nil, errUnexpectedTraversalCall
			},
			wantErr: errTestLoadWinner,
		},
		{
			name: "victim load error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return winner, nil
			},
			loadVictim: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return nil, errTestLoadVictims
			},
			wantErr: errTestLoadVictims,
		},
		{
			name: "record edge error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return winner, nil
			},
			loadVictim: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{victim}, nil
			},
			hooks: txChainHooks{
				ListDirectConflictRootsByTxid: func(context.Context,
					chainhash.Hash) ([]txChainMeta, error) {

					return []txChainMeta{victim}, nil
				},
				RecordReplacementEdge: func(
					context.Context, int64, int64,
				) error {

					return errTestRecordEdge
				},
			},
			wantErr: errTestRecordEdge,
		},
		{
			name: "reclaim error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return winner, nil
			},
			loadVictim: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{victim}, nil
			},
			hooks: txChainHooks{
				ListDirectConflictRootsByTxid: func(context.Context,
					chainhash.Hash) ([]txChainMeta, error) {

					return []txChainMeta{victim}, nil
				},
				ListChildren: func(context.Context, int64) ([]int64, error) {
					return nil, nil
				},
				ClearSpentByTx: func(context.Context, int64) error {
					return nil
				},
				UpdateStatus: func(context.Context, TxStatus, []int64) error {
					return nil
				},
				RecordReplacementEdge: func(
					context.Context, int64, int64,
				) error {

					return nil
				},
				ReclaimInputsByTxid: func(context.Context,
					chainhash.Hash, int64) error {

					return errTestReclaimInputs
				},
			},
			wantErr: errTestReclaimInputs,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := applyTxReplacementCommon(
				t.Context(),
				ApplyTxReplacementParams{ReplacementTxid: winner.Txid},
				test.loadWinner, test.loadVictim, test.hooks,
			)
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestApplyTxFailureCommonErrorPaths(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID: 1, Txid: chainhash.Hash{1}, Status: TxStatusPublished,
	}
	root := txChainMeta{ID: 2, Txid: chainhash.Hash{2}, Status: TxStatusPending}

	tests := []struct {
		name       string
		loadWinner func(context.Context, chainhash.Hash) (txChainMeta, error)
		loadRoots  func(
			context.Context, []chainhash.Hash,
		) ([]txChainMeta, error)
		hooks   txChainHooks
		wantErr error
	}{
		{
			name: "winner load error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return txChainMeta{}, errTestLoadWinner
			},
			loadRoots: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return nil, errUnexpectedTraversalCall
			},
			wantErr: errTestLoadWinner,
		},
		{
			name: "roots load error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return winner, nil
			},
			loadRoots: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return nil, errTestLoadRoots
			},
			wantErr: errTestLoadRoots,
		},
		{
			name: "validation error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return txChainMeta{
					Txid: winner.Txid, Status: TxStatusFailed,
				}, nil
			},
			loadRoots: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{root}, nil
			},
			wantErr: errFailureWinnerInvalid,
		},
		{
			name: "reclaim error",
			loadWinner: func(context.Context,
				chainhash.Hash) (txChainMeta, error) {

				return winner, nil
			},
			loadRoots: func(context.Context,
				[]chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{root}, nil
			},
			hooks: txChainHooks{
				ListDirectConflictRootsByTxid: func(context.Context,
					chainhash.Hash) ([]txChainMeta, error) {

					return []txChainMeta{root}, nil
				},
				ListChildren: func(context.Context, int64) ([]int64, error) {
					return nil, nil
				},
				ClearSpentByTx: func(context.Context, int64) error {
					return nil
				},
				UpdateStatus: func(context.Context, TxStatus, []int64) error {
					return nil
				},
				ReclaimInputsByTxid: func(context.Context,
					chainhash.Hash, int64) error {

					return errTestReclaimInputs
				},
			},
			wantErr: errTestReclaimInputs,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := applyTxFailureCommon(
				t.Context(),
				ApplyTxFailureParams{ConflictingTxid: winner.Txid},
				test.loadWinner, test.loadRoots, test.hooks,
			)
			require.ErrorIs(t, err, test.wantErr)
		})
	}
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

func TestValidateDirectConflictRoots(t *testing.T) {
	t.Parallel()

	winnerTxid := chainhash.Hash{1}
	rootOne := txChainMeta{ID: 2, Txid: chainhash.Hash{2}}
	rootTwo := txChainMeta{ID: 3, Txid: chainhash.Hash{3}}

	tests := []struct {
		name    string
		roots   []txChainMeta
		list    func(context.Context, chainhash.Hash) ([]txChainMeta, error)
		wantErr error
	}{
		{
			name:  "success",
			roots: []txChainMeta{rootTwo, rootOne},
			list: func(_ context.Context,
				txid chainhash.Hash) ([]txChainMeta, error) {

				require.Equal(t, winnerTxid, txid)
				return []txChainMeta{rootOne, rootTwo}, nil
			},
		},
		{
			name:  "list error",
			roots: []txChainMeta{rootOne},
			list: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return nil, errTestListDirectRoots
			},
			wantErr: errTestListDirectRoots,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateDirectConflictRoots(
				t.Context(), winnerTxid, test.roots, test.list,
				errReplacementVictimNotDirect,
				errReplacementVictimSetIncomplete,
			)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestValidateOrphanPlanEmptyRoots(t *testing.T) {
	t.Parallel()

	err := validateOrphanPlan(nil)
	require.ErrorIs(t, err, errOrphanRootInvalid)
}

func TestBuildDirectConflictMeta(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{9}
	tests := []struct {
		name       string
		statusCode int64
		txHash     []byte
		hasBlock   bool
		isCoinbase bool
		want       txChainMeta
		wantOK     bool
		wantErr    error
	}{
		{
			name:       "live pending regular",
			statusCode: int64(TxStatusPending),
			txHash:     hash[:],
			want: txChainMeta{
				ID:     11,
				Txid:   hash,
				Status: TxStatusPending,
			},
			wantOK: true,
		},
		{
			name:       "confirmed filtered",
			statusCode: int64(TxStatusPublished),
			txHash:     hash[:],
			hasBlock:   true,
		},
		{
			name:       "coinbase filtered",
			statusCode: int64(TxStatusPublished),
			txHash:     hash[:],
			isCoinbase: true,
		},
		{
			name:       "terminal filtered",
			statusCode: int64(TxStatusFailed),
			txHash:     hash[:],
		},
		{
			name:       "invalid status",
			statusCode: 9,
			txHash:     hash[:],
			wantErr:    errInvalidTxStatus,
		},
		{
			name:       "invalid hash",
			statusCode: int64(TxStatusPending),
			txHash:     []byte{1, 2, 3},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			meta, ok, err := buildDirectConflictMeta(
				11, test.txHash, test.statusCode, test.hasBlock,
				test.isCoinbase,
			)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}

			if test.name == "invalid hash" {
				require.ErrorContains(t, err, "transaction hash")
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.wantOK, ok)
			require.Equal(t, test.want, meta)
		})
	}
}

func TestTxIDsFromMetas(t *testing.T) {
	t.Parallel()

	ids := txIDsFromMetas([]txChainMeta{{ID: 4}, {ID: 5}, {ID: 4}, {ID: 6}})
	require.Equal(t, []int64{4, 5, 6}, ids)
}

func TestCollectTxChainDescendantIDsDeduplicatesRoots(t *testing.T) {
	t.Parallel()

	descendants, err := collectTxChainDescendantIDs(
		t.Context(), []int64{1, 1},
		func(_ context.Context, parentID int64) ([]int64, error) {
			if parentID == 1 {
				return []int64{2}, nil
			}

			return nil, nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, []int64{2}, descendants)
}

func TestIsLiveTxStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status TxStatus
		want   bool
	}{
		{status: TxStatusPending, want: true},
		{status: TxStatusPublished, want: true},
		{status: TxStatusReplaced, want: false},
		{status: TxStatusFailed, want: false},
		{status: TxStatusOrphaned, want: false},
		{status: TxStatus(99), want: false},
	}

	for _, test := range tests {
		require.Equal(t, test.want, isLiveTxStatus(test.status))
	}
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

func TestCollectTxChainDescendantIDsChildError(t *testing.T) {
	t.Parallel()

	_, err := collectTxChainDescendantIDs(
		t.Context(), []int64{1},
		func(_ context.Context, _ int64) ([]int64, error) {
			return nil, errTestListChildren
		},
	)
	require.ErrorIs(t, err, errTestListChildren)
}

func TestApplyTxChainInvalidationErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hooks   txChainHooks
		wantErr error
	}{
		{
			name: "collect error",
			hooks: txChainHooks{
				ListChildren: func(context.Context, int64) ([]int64, error) {
					return nil, errTestCollect
				},
			},
			wantErr: errTestCollect,
		},
		{
			name: "clear root error",
			hooks: txChainHooks{
				ListChildren: func(context.Context, int64) ([]int64, error) {
					return nil, nil
				},
				ClearSpentByTx: func(context.Context, int64) error {
					return errTestClearRoot
				},
			},
			wantErr: errTestClearRoot,
		},
		{
			name: "clear descendant error",
			hooks: txChainHooks{
				ListChildren: func(
					_ context.Context, txID int64,
				) ([]int64, error) {

					if txID == 1 {
						return []int64{2}, nil
					}

					return nil, nil
				},
				ClearSpentByTx: func(_ context.Context, txID int64) error {
					if txID == 2 {
						return errTestClearDescendant
					}

					return nil
				},
			},
			wantErr: errTestClearDescendant,
		},
		{
			name: "update root status error",
			hooks: txChainHooks{
				ListChildren: func(context.Context, int64) ([]int64, error) {
					return nil, nil
				},
				ClearSpentByTx: func(context.Context, int64) error {
					return nil
				},
				UpdateStatus: func(_ context.Context, status TxStatus,
					_ []int64) error {

					if status == TxStatusReplaced {
						return errTestUpdateRoot
					}

					return nil
				},
			},
			wantErr: errTestUpdateRoot,
		},
		{
			name: "update descendant status error",
			hooks: txChainHooks{
				ListChildren: func(
					_ context.Context, txID int64,
				) ([]int64, error) {

					if txID == 1 {
						return []int64{2}, nil
					}

					return nil, nil
				},
				ClearSpentByTx: func(context.Context, int64) error {
					return nil
				},
				UpdateStatus: func(_ context.Context, status TxStatus,
					ids []int64) error {

					if status == TxStatusFailed &&
						len(ids) == 1 && ids[0] == 2 {

						return errTestUpdateDescendant
					}

					return nil
				},
			},
			wantErr: errTestUpdateDescendant,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := applyTxChainInvalidation(
				t.Context(), []int64{1}, TxStatusReplaced, test.hooks,
			)
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestApplyTxReplacementCommonInvalidationError(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID: 1, Txid: chainhash.Hash{1}, Status: TxStatusPublished,
	}
	victim := txChainMeta{
		ID: 2, Txid: chainhash.Hash{2}, Status: TxStatusPublished,
	}

	err := applyTxReplacementCommon(
		t.Context(),
		ApplyTxReplacementParams{ReplacementTxid: winner.Txid},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{victim}, nil
		},
		txChainHooks{
			ListDirectConflictRootsByTxid: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{victim}, nil
			},
			RecordReplacementEdge: func(context.Context, int64, int64) error {
				return nil
			},
			ListChildren: func(context.Context, int64) ([]int64, error) {
				return nil, nil
			},
			ClearSpentByTx: func(context.Context, int64) error {
				return nil
			},
			UpdateStatus: func(context.Context, TxStatus, []int64) error {
				return errTestUpdate
			},
		},
	)
	require.ErrorIs(t, err, errTestUpdate)
}

func TestApplyTxFailureCommonInvalidationError(t *testing.T) {
	t.Parallel()

	winner := txChainMeta{
		ID: 1, Txid: chainhash.Hash{1}, Status: TxStatusPublished,
	}
	root := txChainMeta{ID: 2, Txid: chainhash.Hash{2}, Status: TxStatusPending}

	err := applyTxFailureCommon(
		t.Context(),
		ApplyTxFailureParams{ConflictingTxid: winner.Txid},
		func(context.Context, chainhash.Hash) (txChainMeta, error) {
			return winner, nil
		},
		func(context.Context, []chainhash.Hash) ([]txChainMeta, error) {
			return []txChainMeta{root}, nil
		},
		txChainHooks{
			ListDirectConflictRootsByTxid: func(context.Context,
				chainhash.Hash) ([]txChainMeta, error) {

				return []txChainMeta{root}, nil
			},
			ListChildren: func(context.Context, int64) ([]int64, error) {
				return nil, nil
			},
			ClearSpentByTx: func(context.Context, int64) error {
				return nil
			},
			UpdateStatus: func(context.Context, TxStatus, []int64) error {
				return errTestUpdate
			},
		},
	)
	require.ErrorIs(t, err, errTestUpdate)
}
