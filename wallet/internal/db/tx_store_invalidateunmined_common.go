package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	// ErrInvalidateRequiresUnmined indicates that InvalidateUnminedTx only
	// accepts current unmined pending or published transactions.
	ErrInvalidateRequiresUnmined = errors.New(
		"invalidate requires an unmined pending or published transaction",
	)
)

// invalidateUnminedTxTarget is the normalized metadata the shared invalidation
// workflow needs for the root transaction.
type invalidateUnminedTxTarget struct {
	id         int64
	txHash     chainhash.Hash
	status     TxStatus
	hasBlock   bool
	isCoinbase bool
}

// invalidateUnminedTxOps is the small backend adapter the shared
// InvalidateUnminedTx workflow needs.
type invalidateUnminedTxOps interface {
	// loadTarget loads the wallet-scoped root transaction metadata.
	loadTarget(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (invalidateUnminedTxTarget, error)

	// listUnminedTxRecords loads the wallet's active unmined transaction rows
	// in the normalized shape the descendant walk expects.
	listUnminedTxRecords(ctx context.Context,
		walletID int64) ([]unminedTxRecord, error)

	// clearSpentUtxos restores any wallet-owned parent outputs spent by the
	// given transaction row.
	clearSpentUtxos(ctx context.Context, walletID int64, txID int64) error

	// markTransactionsFailed batch-marks the provided transaction rows as
	// failed.
	markTransactionsFailed(ctx context.Context, walletID int64,
		txIDs []int64) error
}

// validateInvalidateUnminedTxTarget checks that the requested root is a current
// unmined non-coinbase transaction.
func validateInvalidateUnminedTxTarget(
	target invalidateUnminedTxTarget) error {

	if target.hasBlock || target.isCoinbase || !isUnminedStatus(target.status) {
		return fmt.Errorf("transaction %s: %w", target.txHash,
			ErrInvalidateRequiresUnmined)
	}

	return nil
}

// invalidateUnminedTxRootsWithOps invalidates the provided unmined roots
// together with any descendant branch that depends on them.
func invalidateUnminedTxRootsWithOps(ctx context.Context, walletID uint32,
	rootTargets []invalidateUnminedTxTarget,
	ops invalidateUnminedTxOps) error {

	rootHashes := make(map[chainhash.Hash]struct{}, len(rootTargets))

	rootIDs := make([]int64, 0, len(rootTargets))
	for _, target := range rootTargets {
		err := validateInvalidateUnminedTxTarget(target)
		if err != nil {
			return err
		}

		rootHashes[target.txHash] = struct{}{}
		rootIDs = append(rootIDs, target.id)
	}

	candidates, err := ops.listUnminedTxRecords(ctx, int64(walletID))
	if err != nil {
		return fmt.Errorf("list unmined invalidation candidates: %w", err)
	}

	descendantIDs := collectDescendantTxIDs(rootHashes, candidates)

	for _, rootID := range rootIDs {
		err = ops.clearSpentUtxos(ctx, int64(walletID), rootID)
		if err != nil {
			return fmt.Errorf("clear root spent utxos: %w", err)
		}
	}

	for _, descendantID := range descendantIDs {
		err = ops.clearSpentUtxos(ctx, int64(walletID), descendantID)
		if err != nil {
			return fmt.Errorf("clear descendant spent utxos: %w", err)
		}
	}

	failedIDs := make([]int64, 0, len(descendantIDs)+len(rootIDs))
	failedIDs = append(failedIDs, rootIDs...)
	failedIDs = append(failedIDs, descendantIDs...)

	err = ops.markTransactionsFailed(ctx, int64(walletID), failedIDs)
	if err != nil {
		return fmt.Errorf("mark invalidated transactions failed: %w", err)
	}

	return nil
}

// invalidateUnminedTxWithOps invalidates one wallet-owned unmined transaction
// root together with any descendant branch that depends on it.
func invalidateUnminedTxWithOps(ctx context.Context,
	params InvalidateUnminedTxParams, ops invalidateUnminedTxOps) error {

	target, err := ops.loadTarget(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load invalidate transaction target: %w", err)
	}

	return invalidateUnminedTxRootsWithOps(
		ctx, params.WalletID, []invalidateUnminedTxTarget{target}, ops,
	)
}
