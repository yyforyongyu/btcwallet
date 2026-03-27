package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var errUnexpectedInvalidateCall = errors.New("unexpected invalidate call")

// invalidateUnminedTxOpsFuncs is a test double for invalidateUnminedTxOps.
type invalidateUnminedTxOpsFuncs struct {
	loadTargetFn             func(context.Context, uint32, chainhash.Hash) (invalidateUnminedTxTarget, error)
	listUnminedTxRecordsFn   func(context.Context, int64) ([]unminedTxRecord, error)
	clearSpentUtxosFn        func(context.Context, int64, int64) error
	markTransactionsFailedFn func(context.Context, int64, []int64) error
}

// loadTarget implements invalidateUnminedTxOps.
func (f invalidateUnminedTxOpsFuncs) loadTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (invalidateUnminedTxTarget, error) {

	if f.loadTargetFn == nil {
		return invalidateUnminedTxTarget{}, errUnexpectedInvalidateCall
	}

	return f.loadTargetFn(ctx, walletID, txHash)
}

// listUnminedTxRecords implements invalidateUnminedTxOps.
func (f invalidateUnminedTxOpsFuncs) listUnminedTxRecords(ctx context.Context,
	walletID int64) ([]unminedTxRecord, error) {

	if f.listUnminedTxRecordsFn == nil {
		return nil, errUnexpectedInvalidateCall
	}

	return f.listUnminedTxRecordsFn(ctx, walletID)
}

// clearSpentUtxos implements invalidateUnminedTxOps.
func (f invalidateUnminedTxOpsFuncs) clearSpentUtxos(ctx context.Context,
	walletID int64, txID int64) error {

	if f.clearSpentUtxosFn == nil {
		return errUnexpectedInvalidateCall
	}

	return f.clearSpentUtxosFn(ctx, walletID, txID)
}

// markTransactionsFailed implements invalidateUnminedTxOps.
func (f invalidateUnminedTxOpsFuncs) markTransactionsFailed(
	ctx context.Context, walletID int64, txIDs []int64) error {

	if f.markTransactionsFailedFn == nil {
		return errUnexpectedInvalidateCall
	}

	return f.markTransactionsFailedFn(ctx, walletID, txIDs)
}

// TestValidateInvalidateUnminedTxTarget verifies the root-state validation for
// InvalidateUnminedTx.
func TestValidateInvalidateUnminedTxTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  invalidateUnminedTxTarget
		wantErr error
	}{
		{
			name: "pending root",
			target: invalidateUnminedTxTarget{
				txHash:   chainhash.Hash{1},
				status:   TxStatusPending,
				hasBlock: false,
			},
		},
		{
			name: "published root",
			target: invalidateUnminedTxTarget{
				txHash:   chainhash.Hash{2},
				status:   TxStatusPublished,
				hasBlock: false,
			},
		},
		{
			name: "confirmed root rejected",
			target: invalidateUnminedTxTarget{
				txHash:   chainhash.Hash{3},
				status:   TxStatusPublished,
				hasBlock: true,
			},
			wantErr: ErrInvalidateRequiresUnmined,
		},
		{
			name: "failed root rejected",
			target: invalidateUnminedTxTarget{
				txHash: chainhash.Hash{4},
				status: TxStatusFailed,
			},
			wantErr: ErrInvalidateRequiresUnmined,
		},
		{
			name: "coinbase root rejected",
			target: invalidateUnminedTxTarget{
				txHash:     chainhash.Hash{5},
				status:     TxStatusPublished,
				isCoinbase: true,
			},
			wantErr: ErrInvalidateRequiresUnmined,
		},
		{
			name: "orphaned root rejected",
			target: invalidateUnminedTxTarget{
				txHash: chainhash.Hash{6},
				status: TxStatusOrphaned,
			},
			wantErr: ErrInvalidateRequiresUnmined,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateInvalidateUnminedTxTarget(test.target)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestInvalidateUnminedTxWithOps verifies the shared invalidation workflow for
// one unmined root and its descendants.
func TestInvalidateUnminedTxWithOps(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}
	grandchildHash := chainhash.Hash{3}

	candidates := []unminedTxRecord{
		{
			id:   2,
			hash: childHash,
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootHash, Index: 0},
			}}},
		},
		{
			id:   3,
			hash: grandchildHash,
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: childHash, Index: 0},
			}}},
		},
	}

	var cleared []int64
	var failedIDs []int64

	err := invalidateUnminedTxWithOps(
		t.Context(),
		InvalidateUnminedTxParams{WalletID: 7, Txid: rootHash},
		invalidateUnminedTxOpsFuncs{
			loadTargetFn: func(context.Context, uint32,
				chainhash.Hash) (invalidateUnminedTxTarget, error) {

				return invalidateUnminedTxTarget{
					id:     1,
					txHash: rootHash,
					status: TxStatusPublished,
				}, nil
			},
			listUnminedTxRecordsFn: func(context.Context,
				int64) ([]unminedTxRecord, error) {

				return candidates, nil
			},
			clearSpentUtxosFn: func(_ context.Context, _ int64, txID int64) error {
				cleared = append(cleared, txID)
				return nil
			},
			markTransactionsFailedFn: func(_ context.Context, _ int64,
				txIDs []int64) error {

				failedIDs = append([]int64(nil), txIDs...)
				return nil
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, []int64{1, 2, 3}, cleared)
	require.Equal(t, []int64{1, 2, 3}, failedIDs)
}
