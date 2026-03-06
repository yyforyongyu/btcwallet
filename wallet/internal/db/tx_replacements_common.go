package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	// errReplacementRequiresVictims indicates that a replacement flow
	// was called without any direct victim transactions.
	errReplacementRequiresVictims = errors.New(
		"replacement requires at least one victim transaction",
	)

	// errSelfReplacement indicates that a replacement flow tried to replace a
	// transaction with itself.
	errSelfReplacement = errors.New(
		"replacement transaction cannot replace itself",
	)

	// errReplacementWinnerInvalid indicates that the winning replacement
	// transaction was not a live regular transaction.
	errReplacementWinnerInvalid = errors.New(
		"replacement transaction must be live and non-coinbase",
	)

	// errReplacementVictimInvalid indicates that a direct
	// replacement victim was not an unconfirmed regular
	// transaction.
	errReplacementVictimInvalid = errors.New(
		"replacement victim must be unconfirmed and non-coinbase",
	)

	// errFailureWinnerInvalid indicates that the transaction winning a direct
	// conflict could not safely own the spent-input edges.
	errFailureWinnerInvalid = errors.New(
		"conflicting transaction must be live and non-coinbase",
	)

	// errFailureRequiresRoots indicates that a failure flow was called without
	// any direct loser transactions.
	errFailureRequiresRoots = errors.New(
		"failure requires at least one loser transaction",
	)

	// errFailureRootInvalid indicates that a failure flow tried to invalidate a
	// transaction that is not eligible for direct conflict failure.
	errFailureRootInvalid = errors.New(
		"failed transaction must be unconfirmed and non-coinbase",
	)

	// errOrphanRootInvalid indicates that an orphan propagation flow was called
	// with a root transaction that is not already an orphaned coinbase.
	errOrphanRootInvalid = errors.New(
		"orphan root must be an orphaned coinbase transaction",
	)

	// errCoinbaseReconfirmationInvalid indicates that a reconfirmation flow was
	// called for a row that is not currently an orphaned coinbase.
	errCoinbaseReconfirmationInvalid = errors.New(
		"coinbase reconfirmation requires an orphaned coinbase transaction",
	)

	// errCoinbaseReconfirmationStateChanged indicates that the row
	// stopped being an orphaned coinbase before the
	// reconfirmation update was applied.
	errCoinbaseReconfirmationStateChanged = errors.New(
		"orphaned coinbase state changed before reconfirmation",
	)

	// errWinnerInputNotReclaimed indicates that a winner transaction still does
	// not own one of its wallet-owned inputs after invalidation completed.
	errWinnerInputNotReclaimed = errors.New("winner input was not reclaimed")
)

// ApplyTxReplacementParams describes one replacement winner and the direct
// victim transactions that it invalidates.
type ApplyTxReplacementParams struct {
	// WalletID scopes the replacement flow to one wallet.
	WalletID uint32

	// ReplacementTxid identifies the transaction that wins the
	// conflict and must own the spent-input edges after the flow
	// completes.
	ReplacementTxid chainhash.Hash

	// ReplacedTxids lists the direct victim transactions that lose
	// the conflict. Descendants are discovered automatically from
	// the stored spend graph.
	ReplacedTxids []chainhash.Hash
}

// ApplyTxFailureParams describes a conflict winner and one or more direct loser
// transactions that should become failed.
type ApplyTxFailureParams struct {
	// WalletID scopes the failure flow to one wallet.
	WalletID uint32

	// ConflictingTxid identifies the transaction that wins the
	// conflict and must own the affected spent-input edges after
	// the flow completes.
	ConflictingTxid chainhash.Hash

	// FailedTxids lists the direct loser transactions.
	// Descendants are discovered automatically from the stored
	// spend graph.
	FailedTxids []chainhash.Hash
}

// OrphanTxChainParams identifies orphaned coinbase roots whose descendants must
// be marked failed.
type OrphanTxChainParams struct {
	// WalletID scopes the orphan propagation to one wallet.
	WalletID uint32

	// Txids lists the already-orphaned coinbase transactions that
	// form the roots of the invalidation walk.
	Txids []chainhash.Hash
}

// ReconfirmOrphanedCoinbaseParams identifies one orphaned coinbase transaction
// that should be restored to the best chain.
type ReconfirmOrphanedCoinbaseParams struct {
	// WalletID scopes the reconfirmation to one wallet.
	WalletID uint32

	// Txid identifies the orphaned coinbase transaction to restore.
	Txid chainhash.Hash

	// Block identifies the block that now confirms the coinbase transaction.
	Block Block
}

// txChainMeta stores the transaction facts needed by the replacement and
// invalidation flows without exposing backend-specific sqlc row types.
type txChainMeta struct {
	// ID is the wallet-scoped transaction row ID.
	ID int64

	// Txid is the transaction hash.
	Txid chainhash.Hash

	// Status is the current wallet-relative validity state.
	Status TxStatus

	// HasBlock reports whether the transaction is currently confirmed.
	HasBlock bool

	// IsCoinbase reports whether the transaction is a coinbase row.
	IsCoinbase bool
}

// txChainHooks provides the backend-specific operations needed by the common
// graph-walk and status-update logic.
type txChainHooks struct {
	// ListChildren returns the direct child transaction IDs of one parent.
	ListChildren func(context.Context, int64) ([]int64, error)

	// ClearSpentByTx removes every spent-input edge owned by the provided
	// transaction ID so invalidated rows release their inputs.
	ClearSpentByTx func(context.Context, int64) error

	// UpdateStatus rewrites one batch of wallet-scoped
	// transaction row IDs to the provided status.
	UpdateStatus func(context.Context, TxStatus, []int64) error

	// ReclaimInputsByTxid replays the winner transaction's
	// spent-input edges after invalid roots release their prior
	// claims.
	ReclaimInputsByTxid func(context.Context, chainhash.Hash, int64) error

	// RecordReplacementEdge records one directed victim -> winner edge.
	RecordReplacementEdge func(context.Context, int64, int64) error
}

// buildTxChainHooks wires backend-specific replacement callbacks
// into the shared txChainHooks container.
func buildTxChainHooks(
	listChildren func(context.Context, int64) ([]int64, error),
	clearSpentByTx func(context.Context, int64) error,
	updateStatus func(context.Context, TxStatus, []int64) error,
	reclaimInputsByTxid func(context.Context, chainhash.Hash, int64) error,
	recordReplacementEdge func(context.Context, int64, int64) error,
) txChainHooks {

	return txChainHooks{
		ListChildren:          listChildren,
		ClearSpentByTx:        clearSpentByTx,
		UpdateStatus:          updateStatus,
		ReclaimInputsByTxid:   reclaimInputsByTxid,
		RecordReplacementEdge: recordReplacementEdge,
	}
}

// applyTxReplacementCommon executes the shared replacement flow once the caller
// has bound backend-specific metadata and query hooks.
func applyTxReplacementCommon(ctx context.Context,
	params ApplyTxReplacementParams,
	loadWinner func(context.Context, chainhash.Hash) (txChainMeta, error),
	loadVictims func(context.Context, []chainhash.Hash) ([]txChainMeta, error),
	hooks txChainHooks) error {

	winner, err := loadWinner(ctx, params.ReplacementTxid)
	if err != nil {
		return err
	}

	victims, err := loadVictims(ctx, params.ReplacedTxids)
	if err != nil {
		return err
	}

	err = validateReplacementPlan(winner, victims)
	if err != nil {
		return err
	}

	for _, victim := range victims {
		err = hooks.RecordReplacementEdge(ctx, victim.ID, winner.ID)
		if err != nil {
			return err
		}
	}

	err = applyTxChainInvalidation(
		ctx, txIDsFromMetas(victims), TxStatusReplaced, hooks,
	)
	if err != nil {
		return err
	}

	return hooks.ReclaimInputsByTxid(
		ctx, params.ReplacementTxid, winner.ID,
	)
}

// applyTxFailureCommon executes the shared direct-conflict failure flow once
// the caller has bound backend-specific metadata and query hooks.
func applyTxFailureCommon(ctx context.Context, params ApplyTxFailureParams,
	loadWinner func(context.Context, chainhash.Hash) (txChainMeta, error),
	loadRoots func(context.Context, []chainhash.Hash) ([]txChainMeta, error),
	hooks txChainHooks) error {

	winner, err := loadWinner(ctx, params.ConflictingTxid)
	if err != nil {
		return err
	}

	roots, err := loadRoots(ctx, params.FailedTxids)
	if err != nil {
		return err
	}

	err = validateFailurePlan(winner, roots)
	if err != nil {
		return err
	}

	err = applyTxChainInvalidation(
		ctx, txIDsFromMetas(roots), TxStatusFailed, hooks,
	)
	if err != nil {
		return err
	}

	return hooks.ReclaimInputsByTxid(
		ctx, params.ConflictingTxid, winner.ID,
	)
}

// validateReplacementPlan checks the root invariants for a replacement flow.
func validateReplacementPlan(winner txChainMeta, victims []txChainMeta) error {
	if len(victims) == 0 {
		return errReplacementRequiresVictims
	}

	err := validateReplacementWinner(winner)
	if err != nil {
		return err
	}

	for _, victim := range victims {
		if victim.Txid == winner.Txid {
			return fmt.Errorf("transaction %s: %w", victim.Txid,
				errSelfReplacement)
		}

		err := validateReplacementVictim(victim)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateFailurePlan checks the root invariants for a direct conflict failure.
func validateFailurePlan(winner txChainMeta, failed []txChainMeta) error {
	if len(failed) == 0 {
		return errFailureRequiresRoots
	}

	err := validateFailureWinner(winner)
	if err != nil {
		return err
	}

	for _, root := range failed {
		if root.Txid == winner.Txid {
			return fmt.Errorf("transaction %s: %w", root.Txid,
				errSelfReplacement)
		}

		err := validateFailureRoot(root)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateOrphanPlan checks the root invariants for orphan descendant failure.
func validateOrphanPlan(roots []txChainMeta) error {
	for _, root := range roots {
		err := validateOrphanRoot(root)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateCoinbaseReconfirmation checks that the row can be restored from the
// orphaned coinbase state.
func validateCoinbaseReconfirmation(meta txChainMeta) error {
	if !meta.IsCoinbase || meta.HasBlock || meta.Status != TxStatusOrphaned {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errCoinbaseReconfirmationInvalid)
	}

	return nil
}

func validateReplacementWinner(meta txChainMeta) error {
	if meta.IsCoinbase || !isLiveTxStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errReplacementWinnerInvalid)
	}

	return nil
}

func validateReplacementVictim(meta txChainMeta) error {
	if meta.IsCoinbase || meta.HasBlock || !isReplaceableStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errReplacementVictimInvalid)
	}

	return nil
}

func validateFailureWinner(meta txChainMeta) error {
	if meta.IsCoinbase || !isLiveTxStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errFailureWinnerInvalid)
	}

	return nil
}

func validateFailureRoot(meta txChainMeta) error {
	if meta.IsCoinbase || meta.HasBlock || !isFailureRootStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errFailureRootInvalid)
	}

	return nil
}

func validateOrphanRoot(meta txChainMeta) error {
	if !meta.IsCoinbase || meta.HasBlock || meta.Status != TxStatusOrphaned {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errOrphanRootInvalid)
	}

	return nil
}

// collectDescendantTxIDs performs an application-side breadth-first walk over
// the spend graph and returns each discovered descendant exactly once.
func collectDescendantTxIDs(ctx context.Context, rootIDs []int64,
	listChildren func(context.Context, int64) ([]int64, error),
) ([]int64, error) {

	visited := make(map[int64]struct{}, len(rootIDs))

	queue := make([]int64, 0, len(rootIDs))
	for _, rootID := range rootIDs {
		if _, ok := visited[rootID]; ok {
			continue
		}

		visited[rootID] = struct{}{}
		queue = append(queue, rootID)
	}

	descendants := make([]int64, 0)
	for len(queue) > 0 {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}

		parentID := queue[0]
		queue = queue[1:]

		children, err := listChildren(ctx, parentID)
		if err != nil {
			return nil, err
		}

		for _, childID := range children {
			if _, ok := visited[childID]; ok {
				continue
			}

			visited[childID] = struct{}{}
			queue = append(queue, childID)
			descendants = append(descendants, childID)
		}
	}

	return descendants, nil
}

// applyTxChainInvalidation clears spent-input edges for the provided roots and
// their descendants, then applies the requested terminal statuses.
func applyTxChainInvalidation(ctx context.Context, rootIDs []int64,
	rootStatus TxStatus, hooks txChainHooks) error {

	descendants, err := collectDescendantTxIDs(
		ctx, rootIDs, hooks.ListChildren,
	)
	if err != nil {
		return fmt.Errorf("collect descendant transactions: %w", err)
	}

	for _, txID := range rootIDs {
		err := hooks.ClearSpentByTx(ctx, txID)
		if err != nil {
			return err
		}
	}

	for _, txID := range descendants {
		err := hooks.ClearSpentByTx(ctx, txID)
		if err != nil {
			return err
		}
	}

	err = hooks.UpdateStatus(ctx, rootStatus, rootIDs)
	if err != nil {
		return err
	}

	err = hooks.UpdateStatus(ctx, TxStatusFailed, descendants)
	if err != nil {
		return err
	}

	return nil
}

func txIDsFromMetas(metas []txChainMeta) []int64 {
	ids := make([]int64, 0, len(metas))
	seen := make(map[int64]struct{}, len(metas))

	for _, meta := range metas {
		if _, ok := seen[meta.ID]; ok {
			continue
		}

		seen[meta.ID] = struct{}{}
		ids = append(ids, meta.ID)
	}

	return ids
}

func isLiveTxStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished:
		return true

	case TxStatusReplaced, TxStatusFailed, TxStatusOrphaned:
		return false
	}

	return false
}

func isReplaceableStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished, TxStatusReplaced:
		return true

	case TxStatusFailed, TxStatusOrphaned:
		return false
	}

	return false
}

func isFailureRootStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished, TxStatusFailed:
		return true

	case TxStatusReplaced, TxStatusOrphaned:
		return false
	}

	return false
}
