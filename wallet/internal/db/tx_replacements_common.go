package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

var (
	// errReplacementRequiresVictims indicates that a replacement flow
	// was called without any direct victim transactions.
	errReplacementRequiresVictims = errors.New(
		"replacement requires at least one victim transaction",
	)

	// errSelfConflict indicates that a replacement or failure flow tried to use
	// the same transaction as both winner and loser.
	errSelfConflict = errors.New(
		"transaction cannot conflict with itself",
	)

	// errReplacementWinnerInvalid indicates that the winning replacement
	// transaction was not a live unconfirmed regular transaction.
	errReplacementWinnerInvalid = errors.New(
		"replacement transaction must be live, unconfirmed, and non-coinbase",
	)

	// errReplacementVictimInvalid indicates that a direct
	// replacement victim was not a published unconfirmed regular
	// transaction.
	errReplacementVictimInvalid = errors.New(
		"replacement victim must be published, unconfirmed, and non-coinbase",
	)

	// errReplacementVictimNotDirect indicates that a supplied replacement root
	// did not directly conflict with the winner on a wallet-owned input.
	errReplacementVictimNotDirect = errors.New(
		"replacement victim must directly conflict with winner " +
			"on a wallet-owned input",
	)

	// errReplacementVictimSetIncomplete indicates that a replacement flow did
	// not include every direct conflict loser on the winner's wallet-owned
	// inputs.
	errReplacementVictimSetIncomplete = errors.New(
		"replacement must include every direct victim on " +
			"wallet-owned inputs",
	)

	// errFailureWinnerInvalid indicates that the transaction winning a direct
	// conflict could not safely own the spent-input edges.
	errFailureWinnerInvalid = errors.New(
		"conflicting transaction must be live, non-terminal, and non-coinbase",
	)

	// errFailureRequiresRoots indicates that a failure flow was called without
	// any direct loser transactions.
	errFailureRequiresRoots = errors.New(
		"failure requires at least one loser transaction",
	)

	// errFailureRootInvalid indicates that a failure flow tried to invalidate a
	// transaction that is not eligible for direct conflict failure.
	errFailureRootInvalid = errors.New(
		"failure root must be live, unconfirmed, and non-coinbase",
	)

	// errFailureRootNotDirect indicates that a supplied failure root did not
	// directly conflict with the winner on a wallet-owned input.
	errFailureRootNotDirect = errors.New(
		"failure root must directly conflict with winner on " +
			"a wallet-owned input",
	)

	// errFailureRootSetIncomplete indicates that a failure flow did not include
	// every direct conflict loser on the winner's wallet-owned inputs.
	errFailureRootSetIncomplete = errors.New(
		"failure must include every direct loser on " +
			"wallet-owned inputs",
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

	// errCoinbaseReconfirmationHasDescendants indicates that root-only coinbase
	// reconfirmation was attempted while a dependent descendant branch is still
	// stored.
	errCoinbaseReconfirmationHasDescendants = errors.New(
		"coinbase reconfirmation requires no stored descendants",
	)

	// errWinnerInputNotReclaimed indicates that a winner transaction still does
	// not own one of its wallet-owned inputs after invalidation completed.
	errWinnerInputNotReclaimed = errors.New("winner input was not reclaimed")
)

// txGraphMeta stores the transaction facts needed by the replacement and
// invalidation flows without exposing backend-specific sqlc row types.
type txGraphMeta struct {
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

// txGraphHooks provides the backend-specific operations needed by the common
// graph-walk and status-update logic.
type txGraphHooks struct {
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

	// ListDirectConflictRootsByTxid reports the live unconfirmed
	// direct loser set for a winner transaction by examining the
	// wallet-owned inputs in conflict with it.
	ListDirectConflictRootsByTxid func(context.Context,
		chainhash.Hash) ([]txGraphMeta, error)
}

// buildTxGraphHooks wires backend-specific replacement callbacks
// into the shared txGraphHooks container.
func buildTxGraphHooks(
	listChildren func(context.Context, int64) ([]int64, error),
	clearSpentByTx func(context.Context, int64) error,
	updateStatus func(context.Context, TxStatus, []int64) error,
	reclaimInputsByTxid func(context.Context, chainhash.Hash, int64) error,
	recordReplacementEdge func(context.Context, int64, int64) error,
	listDirectConflictRootsByTxid func(context.Context,
		chainhash.Hash) ([]txGraphMeta, error),
) txGraphHooks {

	return txGraphHooks{
		ListChildren:                  listChildren,
		ClearSpentByTx:                clearSpentByTx,
		UpdateStatus:                  updateStatus,
		ReclaimInputsByTxid:           reclaimInputsByTxid,
		RecordReplacementEdge:         recordReplacementEdge,
		ListDirectConflictRootsByTxid: listDirectConflictRootsByTxid,
	}
}

// buildTxGraphHooksFor binds one backend query handle and wallet scope to the
// shared graph-hook container.
func buildTxGraphHooksFor[Q any](qtx Q, walletID uint32,
	listChildren func(context.Context, Q, uint32, int64) ([]int64, error),
	clearSpentByTx func(context.Context, Q, uint32, int64) error,
	updateStatus func(context.Context, Q, uint32, TxStatus, []int64) error,
	reclaimInputsByTxid func(
		context.Context, Q, uint32, chainhash.Hash, int64,
	) error,
	recordReplacementEdge func(context.Context, Q, uint32, int64, int64) error,
	listDirectConflictRootsByTxid func(
		context.Context, Q, uint32, chainhash.Hash,
	) ([]txGraphMeta, error)) txGraphHooks {

	return buildTxGraphHooks(
		func(ctx context.Context, parentID int64) ([]int64, error) {
			return listChildren(ctx, qtx, walletID, parentID)
		},
		func(ctx context.Context, txID int64) error {
			return clearSpentByTx(ctx, qtx, walletID, txID)
		},
		func(ctx context.Context, status TxStatus, txIDs []int64) error {
			return updateStatus(ctx, qtx, walletID, status, txIDs)
		},
		func(ctx context.Context, txid chainhash.Hash, txID int64) error {
			return reclaimInputsByTxid(ctx, qtx, walletID, txid, txID)
		},
		func(ctx context.Context, replacedTxID int64,
			replacementTxID int64) error {

			return recordReplacementEdge(
				ctx, qtx, walletID, replacedTxID, replacementTxID,
			)
		},
		func(ctx context.Context, txid chainhash.Hash) ([]txGraphMeta, error) {
			return listDirectConflictRootsByTxid(ctx, qtx, walletID, txid)
		},
	)
}

// applyTxReplacementCommon executes the shared replacement flow once the caller
// has bound backend-specific metadata and query hooks.
func applyTxReplacementCommon(ctx context.Context,
	params ApplyTxReplacementParams,
	loadWinner func(context.Context, chainhash.Hash) (txGraphMeta, error),
	loadVictims func(context.Context, []chainhash.Hash) ([]txGraphMeta, error),
	hooks txGraphHooks) error {

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

	err = validateDirectConflictRoots(
		ctx, params.ReplacementTxid, victims,
		hooks.ListDirectConflictRootsByTxid,
		errReplacementVictimNotDirect,
		errReplacementVictimSetIncomplete,
	)
	if err != nil {
		return err
	}

	for _, victim := range victims {
		err = hooks.RecordReplacementEdge(ctx, victim.ID, winner.ID)
		if err != nil {
			return err
		}
	}

	err = applyTxGraphInvalidation(
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
	loadWinner func(context.Context, chainhash.Hash) (txGraphMeta, error),
	loadRoots func(context.Context, []chainhash.Hash) ([]txGraphMeta, error),
	hooks txGraphHooks) error {

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

	err = validateDirectConflictRoots(
		ctx, params.ConflictingTxid, roots,
		hooks.ListDirectConflictRootsByTxid,
		errFailureRootNotDirect,
		errFailureRootSetIncomplete,
	)
	if err != nil {
		return err
	}

	err = applyTxGraphInvalidation(
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
func validateReplacementPlan(winner txGraphMeta, victims []txGraphMeta) error {
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
				errSelfConflict)
		}

		err := validateReplacementVictim(victim)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateFailurePlan checks the root invariants for a direct conflict failure.
func validateFailurePlan(winner txGraphMeta, failed []txGraphMeta) error {
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
				errSelfConflict)
		}

		err := validateFailureRoot(root)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateDirectConflictRoots ensures that the caller supplied exactly the live
// direct loser set for the winner's wallet-owned inputs.
func validateDirectConflictRoots(ctx context.Context, winnerTxid chainhash.Hash,
	roots []txGraphMeta,
	listDirectConflictRootsByTxid func(context.Context,
		chainhash.Hash) ([]txGraphMeta, error),
	rootErr error, missingRootErr error) error {

	directRoots, err := listDirectConflictRootsByTxid(ctx, winnerTxid)
	if err != nil {
		return fmt.Errorf("list direct conflict roots for %s: %w",
			winnerTxid, err)
	}

	directRootSet := make(map[int64]txGraphMeta, len(directRoots))
	for _, directRoot := range directRoots {
		directRootSet[directRoot.ID] = directRoot
	}

	requestedRootSet := make(map[int64]struct{}, len(roots))
	for _, root := range roots {
		requestedRootSet[root.ID] = struct{}{}

		if _, ok := directRootSet[root.ID]; ok {
			continue
		}

		return fmt.Errorf("transaction %s: %w", root.Txid, rootErr)
	}

	for _, directRoot := range directRoots {
		if _, ok := requestedRootSet[directRoot.ID]; ok {
			continue
		}

		return fmt.Errorf("transaction %s: %w", directRoot.Txid,
			missingRootErr)
	}

	return nil
}

// buildDirectConflictMeta converts one backend row into the shared
// txGraphMeta shape and filters out rows that cannot be direct live conflict
// roots.
func buildDirectConflictMeta(id int64, txHashBytes []byte, statusCode int64,
	hasBlock bool, isCoinbase bool) (txGraphMeta, bool, error) {

	status, err := parseTxStatus(statusCode)
	if err != nil {
		return txGraphMeta{}, false, err
	}

	if hasBlock || isCoinbase || !isLiveTxStatus(status) {
		return txGraphMeta{}, false, nil
	}

	txHash, err := chainhash.NewHash(txHashBytes)
	if err != nil {
		return txGraphMeta{}, false, fmt.Errorf("transaction hash: %w", err)
	}

	return txGraphMeta{
		ID:         id,
		Txid:       *txHash,
		Status:     status,
		HasBlock:   hasBlock,
		IsCoinbase: isCoinbase,
	}, true, nil
}

// txSpendsAnyOutpoint reports whether the candidate transaction spends any
// wallet-owned outpoint from the winner's input set.
func txSpendsAnyOutpoint(tx *wire.MsgTx,
	outpoints map[wire.OutPoint]struct{}) bool {

	for _, txIn := range tx.TxIn {
		if _, ok := outpoints[txIn.PreviousOutPoint]; ok {
			return true
		}
	}

	return false
}

// validateOrphanPlan checks the root invariants for orphan descendant failure.
func validateOrphanPlan(roots []txGraphMeta) error {
	if len(roots) == 0 {
		return errOrphanRootInvalid
	}

	for _, root := range roots {
		err := validateOrphanRoot(root)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateCoinbaseReconfirmation checks that the row can be restored from the
// orphaned coinbase state without exposing an already-stored descendant branch
// as live again.
func validateCoinbaseReconfirmation(ctx context.Context, meta txGraphMeta,
	listDescendantTxIDs func(context.Context,
		chainhash.Hash) ([]int64, error)) error {

	if !meta.IsCoinbase || meta.HasBlock || meta.Status != TxStatusOrphaned {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errCoinbaseReconfirmationInvalid)
	}

	descendantIDs, err := listDescendantTxIDs(ctx, meta.Txid)
	if err != nil {
		return fmt.Errorf("list descendants for transaction %s: %w",
			meta.Txid, err)
	}

	if len(descendantIDs) > 0 {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errCoinbaseReconfirmationHasDescendants)
	}

	return nil
}

// validateReplacementWinner checks that the replacement winner remains a live
// unconfirmed regular transaction that can safely reclaim wallet-owned inputs.
func validateReplacementWinner(meta txGraphMeta) error {
	if meta.IsCoinbase || meta.HasBlock || !isLiveTxStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errReplacementWinnerInvalid)
	}

	return nil
}

// validateReplacementVictim checks that a replacement victim is still a
// published unconfirmed regular transaction.
func validateReplacementVictim(meta txGraphMeta) error {
	if meta.IsCoinbase || meta.HasBlock || meta.Status != TxStatusPublished {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errReplacementVictimInvalid)
	}

	return nil
}

// validateFailureWinner checks that the conflict winner remains eligible to
// reclaim wallet-owned inputs after losers are failed.
func validateFailureWinner(meta txGraphMeta) error {
	if meta.IsCoinbase || !isLiveTxStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errFailureWinnerInvalid)
	}

	return nil
}

// validateFailureRoot checks that a direct conflict loser is still an
// unconfirmed live regular transaction.
func validateFailureRoot(meta txGraphMeta) error {
	if meta.IsCoinbase || meta.HasBlock || !isLiveTxStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errFailureRootInvalid)
	}

	return nil
}

// validateOrphanRoot checks that orphan propagation starts from an already
// orphaned coinbase root.
func validateOrphanRoot(meta txGraphMeta) error {
	if !meta.IsCoinbase || meta.HasBlock || meta.Status != TxStatusOrphaned {
		return fmt.Errorf("transaction %s: %w", meta.Txid,
			errOrphanRootInvalid)
	}

	return nil
}

// collectTxGraphDescendantIDs performs an iterative breadth-first walk over the
// spend graph and returns each discovered descendant exactly once.
//
// The queue-based traversal never recurses, so even very deep invalidation
// chains do not risk call-stack growth.
func collectTxGraphDescendantIDs(ctx context.Context, rootIDs []int64,
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

// applyTxGraphInvalidation clears spent-input edges for the provided roots and
// their descendants, then applies the requested terminal statuses.
func applyTxGraphInvalidation(ctx context.Context, rootIDs []int64,
	rootStatus TxStatus, hooks txGraphHooks) error {

	descendants, err := collectTxGraphDescendantIDs(
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

	// Descendants inherit `failed` when their parent branch is invalidated,
	// even if the root cause was not a direct double-spend against the
	// descendant itself (for example, coinbase orphan propagation).
	err = hooks.UpdateStatus(ctx, TxStatusFailed, descendants)
	if err != nil {
		return err
	}

	return nil
}

// txIDsFromMetas extracts the wallet-scoped row IDs needed by batch update
// helpers from the shared metadata slice.
func txIDsFromMetas(metas []txGraphMeta) []int64 {
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

// isLiveTxStatus reports whether a transaction status still participates in the
// live wallet graph and may own spent-input edges.
func isLiveTxStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished:
		return true

	case TxStatusReplaced, TxStatusFailed, TxStatusOrphaned:
		return false
	}

	return false
}
