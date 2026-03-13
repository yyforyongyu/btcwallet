package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

var (
	// errNilTransaction indicates that CreateTxParams did not include a
	// transaction to persist.
	errNilTransaction = errors.New("transaction is required")

	// errCoinbaseRequiresBlock indicates that a coinbase transaction was
	// provided without a confirming block reference.
	errCoinbaseRequiresBlock = errors.New(
		"coinbase transaction requires a block",
	)

	// errConfirmedRequiresPublished indicates that a mined transaction was
	// provided with a non-published status.
	errConfirmedRequiresPublished = errors.New(
		"confirmed transaction must be published",
	)

	// errCreateTxOrphanedStatus indicates that CreateTx attempted to insert a
	// transaction directly in the orphaned state.
	errCreateTxOrphanedStatus = errors.New(
		"create tx cannot use orphaned status",
	)

	// errCreateTxTerminalStatus indicates that CreateTx attempted to insert a
	// blockless transaction directly in a terminal invalid state.
	errCreateTxTerminalStatus = errors.New(
		"create tx cannot use terminal blockless status",
	)

	// errInvalidTxStatus indicates that a status string does not map to a
	// supported TxStatus value.
	errInvalidTxStatus = errors.New("invalid transaction status")

	// errCreditIndexOutOfRange indicates that a credited output index does not
	// exist in the serialized transaction.
	errCreditIndexOutOfRange = errors.New("credit index out of range")

	// errDuplicateInputOutPoint indicates that CreateTx received the same
	// previous outpoint more than once.
	errDuplicateInputOutPoint = errors.New("duplicate input outpoint")

	// errDeleteRequiresLiveUnconfirmed indicates that DeleteTx only accepts
	// live blockless transactions.
	errDeleteRequiresLiveUnconfirmed = errors.New(
		"live unconfirmed transaction required",
	)

	// errDeleteRequiresLeaf indicates that DeleteTx only accepts live
	// transactions with no child spenders.
	errDeleteRequiresLeaf = errors.New("delete requires a leaf transaction")

	// ErrDeleteRequiresLeaf reports that DeleteTx was called for a transaction
	// that still has direct child spenders.
	ErrDeleteRequiresLeaf = errDeleteRequiresLeaf
)

// serializeMsgTx serializes a wire.MsgTx so it can be stored in the
// transactions table.
func serializeMsgTx(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer

	err := tx.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("serialize transaction: %w", err)
	}

	return buf.Bytes(), nil
}

// deserializeMsgTx deserializes a stored transaction payload back into a
// wire.MsgTx.
func deserializeMsgTx(rawTx []byte) (*wire.MsgTx, error) {
	var tx wire.MsgTx

	err := tx.Deserialize(bytes.NewReader(rawTx))
	if err != nil {
		return nil, fmt.Errorf("deserialize transaction: %w", err)
	}

	return &tx, nil
}

// parseTxStatus converts a stored numeric status code into the strongly typed
// TxStatus enum used by the public db API.
func parseTxStatus(status int64) (TxStatus, error) {
	txStatus, err := int64ToUint8(status)
	if err != nil {
		return TxStatus(0), fmt.Errorf("status %d: %w", status,
			errInvalidTxStatus)
	}

	switch TxStatus(txStatus) {
	case TxStatusPending,
		TxStatusPublished,
		TxStatusReplaced,
		TxStatusFailed,
		TxStatusOrphaned:

		return TxStatus(txStatus), nil

	default:
		return TxStatus(0), fmt.Errorf("status %d: %w", status,
			errInvalidTxStatus)
	}
}

// validateCreateTxParams enforces the API invariants shared by both SQL
// backends before a transaction write begins.
func validateCreateTxParams(params CreateTxParams) error {
	if params.Tx == nil {
		return errNilTransaction
	}

	isCoinbase := blockchain.IsCoinBaseTx(params.Tx)

	err := validateCreateTxStatus(params.Status, params.Block, isCoinbase)
	if err != nil {
		return err
	}

	maxIndex := int64(len(params.Tx.TxOut))

	// Every requested credit must map to one real output exactly once because
	// the write path persists one UTXO row per credited output index and later
	// dereferences params.Tx.TxOut[credit.Index].
	for index := range params.Credits {
		if int64(index) >= maxIndex {
			return fmt.Errorf(
				"credit index %d: %w", index,
				errCreditIndexOutOfRange,
			)
		}
	}

	// Coinbase transactions do not participate in the wallet-owned spend graph,
	// so duplicate-prevout validation only matters for ordinary transactions.
	if isCoinbase {
		return nil
	}

	seenInputs := make(map[wire.OutPoint]struct{}, len(params.Tx.TxIn))

	for inputIndex, txIn := range params.Tx.TxIn {
		if _, ok := seenInputs[txIn.PreviousOutPoint]; ok {
			return fmt.Errorf("input %d: %w", inputIndex,
				errDuplicateInputOutPoint)
		}

		seenInputs[txIn.PreviousOutPoint] = struct{}{}
	}

	return nil
}

// validateCreateTxStatus enforces the combinations of block assignment,
// wallet-visible status, and coinbase semantics that CreateTx accepts.
//
// The accepted state space is intentionally narrow:
//   - callers must not insert orphaned history directly because orphaning is
//     a derived state created by rollback or invalidation flows;
//   - coinbase rows must carry a confirming block because a blockless
//     coinbase is not spendable wallet history; and
//   - any row tied to a block must be published because confirmation and
//     pending status are mutually exclusive.
func validateCreateTxStatus(status TxStatus, block *Block,
	isCoinbase bool) error {

	_, err := parseTxStatus(int64(status))
	if err != nil {
		return err
	}

	// Orphaned rows only arise from disconnect handling after the transaction
	// has already been stored as mined history.
	if status == TxStatusOrphaned {
		return errCreateTxOrphanedStatus
	}

	// Blockless inserts may only represent the live unconfirmed set. Terminal
	// invalid-history states are derived later by invalidation flows.
	if block == nil &&
		status != TxStatusPending && status != TxStatusPublished {

		return errCreateTxTerminalStatus
	}

	// A coinbase without a confirming block cannot represent valid wallet
	// state, so validation fails immediately with errCoinbaseRequiresBlock.
	if isCoinbase && block == nil {
		return errCoinbaseRequiresBlock
	}

	// Once a row is tied to a block it is confirmed history, so it cannot
	// retain an unconfirmed status such as pending.
	if block != nil && status != TxStatusPublished {
		return errConfirmedRequiresPublished
	}

	return nil
}

// liveTxRecord is the decoded view of one live unmined transaction row used by
// shared spend-dependency checks.
type liveTxRecord struct {
	ID   int64
	Hash chainhash.Hash
	Tx   *wire.MsgTx
}

// listLiveTransactionsFn loads the live blockless transaction rows for one
// wallet during rollback descendant invalidation.
type listLiveTransactionsFn[Row any] func(context.Context, int64) ([]Row, error)

// extractLiveTxFn projects one backend-specific live transaction row into the
// shared `(id, tx_hash, raw_tx)` shape used by the invalidation walk.
type extractLiveTxFn[Row any] func(Row) (int64, []byte, []byte)

// clearDescendantSpendsFn clears any wallet-owned spend edges claimed by one
// descendant transaction before its status is rewritten.
type clearDescendantSpendsFn[ClearParams any] func(context.Context,
	ClearParams) (int64, error)

// buildClearParamsFn constructs the backend-specific parameter payload used to
// clear one descendant transaction's spend edges.
type buildClearParamsFn[ClearParams any] func(int64, int64) ClearParams

// updateDescendantStatusesFn applies the terminal invalid status to a batch of
// collected descendant transaction IDs.
type updateDescendantStatusesFn[UpdateParams any] func(context.Context,
	UpdateParams) (int64, error)

// buildUpdateParamsFn constructs the backend-specific parameter payload for the
// descendant status batch update.
type buildUpdateParamsFn[UpdateParams any] func(int64, []int64) UpdateParams

// newLiveTxRecord decodes one normalized live transaction row into the shared
// dependency-walk shape.
func newLiveTxRecord(id int64, hash []byte,
	rawTx []byte) (liveTxRecord, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return liveTxRecord{}, fmt.Errorf("transaction hash: %w", err)
	}

	tx, err := deserializeMsgTx(rawTx)
	if err != nil {
		return liveTxRecord{}, err
	}

	return liveTxRecord{ID: id, Hash: *txHash, Tx: tx}, nil
}

// buildLiveTxRecords decodes backend-specific live transaction rows into the
// shared dependency-walk shape.
func buildLiveTxRecords[T any](rows []T,
	extract func(T) (int64, []byte, []byte)) ([]liveTxRecord, error) {

	records := make([]liveTxRecord, 0, len(rows))
	for _, row := range rows {
		id, hash, rawTx := extract(row)

		record, err := newLiveTxRecord(id, hash, rawTx)
		if err != nil {
			return nil, fmt.Errorf("decode live transaction %d: %w", id, err)
		}

		records = append(records, record)
	}

	return records, nil
}

// collectDirectChildTxIDs returns the IDs of live transactions that directly
// spend any output created by the provided parent hash.
func collectDirectChildTxIDs(parentHash chainhash.Hash,
	candidates []liveTxRecord) []int64 {

	parentHashes := map[chainhash.Hash]struct{}{
		parentHash: {},
	}

	childIDs := make([]int64, 0, len(candidates))
	for _, candidate := range candidates {
		if txSpendsAnyParent(candidate.Tx, parentHashes) {
			childIDs = append(childIDs, candidate.ID)
		}
	}

	return childIDs
}

// collectDescendantTxIDs returns every live transaction that depends on any of
// the provided root hashes, including indirect descendants discovered through
// newly invalidated child hashes.
func collectDescendantTxIDs(rootHashes map[chainhash.Hash]struct{},
	candidates []liveTxRecord) []int64 {

	invalidHashes := make(map[chainhash.Hash]struct{}, len(rootHashes))
	for hash := range rootHashes {
		invalidHashes[hash] = struct{}{}
	}

	invalidIDs := make(map[int64]struct{}, len(candidates))

	// Keep walking until one full pass finds no new descendants. The candidate
	// set is finite and invalidIDs only ever grows, so the loop can add at most
	// len(candidates) rows before it terminates.
	for changed := true; changed; {
		changed = false

		for _, candidate := range candidates {
			if _, ok := invalidIDs[candidate.ID]; ok {
				continue
			}

			if !txSpendsAnyParent(candidate.Tx, invalidHashes) {
				continue
			}

			invalidIDs[candidate.ID] = struct{}{}
			invalidHashes[candidate.Hash] = struct{}{}
			changed = true
		}
	}

	descendantIDs := make([]int64, 0, len(invalidIDs))
	for _, candidate := range candidates {
		if _, ok := invalidIDs[candidate.ID]; ok {
			descendantIDs = append(descendantIDs, candidate.ID)
		}
	}

	return descendantIDs
}

// applyRollbackDescendantInvalidation clears spend edges and marks failed every
// live descendant discovered from the provided wallet-scoped rollback roots.
//
// The backend supplies three things: how to list the live blockless rows for a
// wallet, how to clear a descendant's claimed spend edges, and how to batch the
// final status update once every descendant ID has been collected.
func applyRollbackDescendantInvalidation[
	Row any, ClearParams any, UpdateParams any,
](ctx context.Context,
	rootHashesByWallet map[uint32]map[chainhash.Hash]struct{},
	listUnminedTransactions listLiveTransactionsFn[Row],
	extractLiveTx extractLiveTxFn[Row],
	clearUtxosSpentByTxID clearDescendantSpendsFn[ClearParams],
	buildClearParams buildClearParamsFn[ClearParams],
	updateTransactionStatusByIDs updateDescendantStatusesFn[UpdateParams],
	buildUpdateParams buildUpdateParamsFn[UpdateParams],
) error {

	for walletID, rootHashes := range rootHashesByWallet {
		walletID64 := int64(walletID)

		rows, err := listUnminedTransactions(ctx, walletID64)
		if err != nil {
			return fmt.Errorf(
				"list live rollback descendants for wallet %d: %w",
				walletID, err,
			)
		}

		candidates, err := buildLiveTxRecords(rows, extractLiveTx)
		if err != nil {
			return err
		}

		descendantIDs := collectDescendantTxIDs(rootHashes, candidates)
		if len(descendantIDs) == 0 {
			continue
		}

		for _, descendantID := range descendantIDs {
			_, err = clearUtxosSpentByTxID(
				ctx, buildClearParams(walletID64, descendantID),
			)
			if err != nil {
				return fmt.Errorf(
					"clear rollback descendant spends for wallet %d: %w",
					walletID, err,
				)
			}
		}

		_, err = updateTransactionStatusByIDs(
			ctx, buildUpdateParams(walletID64, descendantIDs),
		)
		if err != nil {
			return fmt.Errorf(
				"mark rollback descendants failed for wallet %d: %w",
				walletID, err,
			)
		}
	}

	return nil
}

// txSpendsAnyParent reports whether a transaction spends an outpoint created by
// any of the provided parent hashes.
func txSpendsAnyParent(tx *wire.MsgTx,
	parentHashes map[chainhash.Hash]struct{}) bool {

	for _, txIn := range tx.TxIn {
		if _, ok := parentHashes[txIn.PreviousOutPoint.Hash]; ok {
			return true
		}
	}

	return false
}

// buildTxInfo converts normalized transaction fields into the public TxInfo
// shape returned by the db interfaces.
func buildTxInfo(hash []byte, rawTx []byte, received time.Time, block *Block,
	status int64, label string) (*TxInfo, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("transaction hash: %w", err)
	}

	txStatus, err := parseTxStatus(status)
	if err != nil {
		return nil, err
	}

	return &TxInfo{
		Hash:         *txHash,
		SerializedTx: rawTx,
		Received:     received.UTC(),
		Block:        block,
		Status:       txStatus,
		Label:        label,
	}, nil
}

// isLiveUnconfirmedStatus reports whether a status still belongs to the live
// blockless transaction set that DeleteTx may erase.
func isLiveUnconfirmedStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished:
		return true

	case TxStatusReplaced, TxStatusFailed, TxStatusOrphaned:
		return false

	default:
		return false
	}
}
