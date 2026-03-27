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
	// ErrInvalidParam is returned when a TxStore method receives invalid input.
	ErrInvalidParam = errors.New("invalid param")

	// ErrInvalidStatus is returned when a transaction status is unknown or not
	// allowed for the requested operation.
	ErrInvalidStatus = errors.New("invalid transaction status")

	// ErrIndexOutOfRange is returned when a referenced transaction input or
	// output index does not exist.
	ErrIndexOutOfRange = errors.New("index out of range")

	// ErrDuplicateInputOutPoint is returned when CreateTx receives the same
	// previous outpoint more than once.
	ErrDuplicateInputOutPoint = errors.New("duplicate input outpoint")

	// ErrDeleteRequiresUnmined indicates that DeleteTx only accepts unmined
	// transactions.
	ErrDeleteRequiresUnmined = errors.New(
		"delete requires an unmined transaction",
	)

	// ErrDeleteRequiresLeaf indicates that DeleteTx only accepts unmined
	// transactions with no child spenders.
	ErrDeleteRequiresLeaf = errors.New("delete requires a leaf transaction")
)

// serializeMsgTx serializes a wire.MsgTx so it can be stored in the
// transactions table.
func serializeMsgTx(tx *wire.MsgTx) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: transaction is required", ErrInvalidParam)
	}

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
			ErrInvalidStatus)
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
			ErrInvalidStatus)
	}
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

// validateCreateTxParams enforces the CreateTx invariants shared by both SQL
// backends after serializeMsgTx has already verified that params.Tx is non-nil.
func validateCreateTxParams(params CreateTxParams) error {
	isCoinbase := blockchain.IsCoinBaseTx(params.Tx)

	err := validateCreateTxStatus(
		params.Status, params.Block != nil, isCoinbase,
	)
	if err != nil {
		return err
	}

	maxIndex := uint64(len(params.Tx.TxOut))

	for index := range params.Credits {
		if uint64(index) >= maxIndex {
			return fmt.Errorf("%w: credit index %d is out of range: %w",
				ErrInvalidParam, index, ErrIndexOutOfRange)
		}
	}

	// Coinbase transactions only enter wallet history once a block already
	// anchors them, so CreateTx requires the caller to provide that block up
	// front instead of storing a fake unmined intermediate row first.
	if isCoinbase {
		return nil
	}

	seenInputs := make(map[wire.OutPoint]struct{}, len(params.Tx.TxIn))
	for inputIndex, txIn := range params.Tx.TxIn {
		// One transaction cannot spend the same previous outpoint twice.
		// Rejecting duplicate inputs here keeps the later wallet-spend walk
		// simple and avoids writing contradictory spend metadata.
		if _, ok := seenInputs[txIn.PreviousOutPoint]; ok {
			return fmt.Errorf("%w: input %d duplicates a previous outpoint: %w",
				ErrInvalidParam, inputIndex, ErrDuplicateInputOutPoint)
		}

		seenInputs[txIn.PreviousOutPoint] = struct{}{}
	}

	return nil
}

// validateCreateTxStatus checks the status/block combinations that CreateTx may
// store directly.
func validateCreateTxStatus(status TxStatus, hasBlock bool,
	isCoinbase bool) error {

	_, err := parseTxStatus(int64(status))
	if err != nil {
		return fmt.Errorf("%w: status %d is not supported: %w",
			ErrInvalidParam, status, ErrInvalidStatus)
	}

	// Orphaned rows only arise later when rollback disconnects a confirmed
	// coinbase transaction. CreateTx records the initial observed facts, so it
	// never inserts orphaned history directly.
	if status == TxStatusOrphaned {
		return fmt.Errorf("%w: CreateTx cannot insert orphaned txns: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	if !hasBlock {
		// Coinbase transactions cannot exist without a confirming block from
		// the store's point of view, so callers must supply that block up
		// front.
		if isCoinbase {
			return fmt.Errorf("%w: coinbase txns require a block: %w",
				ErrInvalidParam, ErrInvalidStatus)
		}

		// Unmined non-coinbase inserts still represent current unmined wallet
		// history, so CreateTx only accepts the two active unmined statuses
		// there.
		if status != TxStatusPending && status != TxStatusPublished {
			return fmt.Errorf("%w: CreateTx requires pending or published: %w",
				ErrInvalidParam, ErrInvalidStatus)
		}

		return nil
	}

	// A non-nil block means the caller already knows the transaction is mined.
	// Mined rows must be published immediately to satisfy the transaction-state
	// invariants enforced by the schema.
	if status != TxStatusPublished {
		return fmt.Errorf("%w: confirmed txns must be published: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	return nil
}

// createTxRequest captures the backend-independent CreateTx inputs after the
// shared validation and normalization step has already succeeded.
type createTxRequest struct {
	// params keeps the original public request available for backend helpers
	// that still need the caller-supplied CreateTx metadata.
	params CreateTxParams

	// rawTx stores the serialized transaction bytes once so both backends reuse
	// the same payload throughout the write.
	rawTx []byte

	// txHash avoids recomputing the transaction hash across the shared flow and
	// backend adapters.
	txHash chainhash.Hash

	// received is normalized to UTC before any backend insert logic runs.
	received time.Time

	// isCoinbase caches the consensus coinbase check for backend insert params.
	isCoinbase bool
}

// newCreateTxRequest performs the backend-independent CreateTx preparation
// shared by both SQL stores before they open a write transaction.
func newCreateTxRequest(params CreateTxParams) (createTxRequest, error) {
	rawTx, err := serializeMsgTx(params.Tx)
	if err != nil {
		return createTxRequest{}, err
	}

	err = validateCreateTxParams(params)
	if err != nil {
		return createTxRequest{}, err
	}

	return createTxRequest{
		params:     params,
		rawTx:      rawTx,
		txHash:     params.Tx.TxHash(),
		received:   params.Received.UTC(),
		isCoinbase: blockchain.IsCoinBaseTx(params.Tx),
	}, nil
}

// createTxExistingTarget is the normalized metadata the shared CreateTx flow
// needs when the wallet already stores the requested tx hash.
type createTxExistingTarget struct {
	id         int64
	status     TxStatus
	hasBlock   bool
	isCoinbase bool
}

var errCreateTxExistingNotFound = errors.New(
	"create transaction existing target not found",
)

// createTxOps is the small semantic adapter CreateTx needs from one SQL
// backend.
//
// The shared CreateTx algorithm is intentionally linear:
//   - reject duplicate wallet-scoped tx hashes before any writes happen
//   - insert the base transaction row exactly once
//   - insert every wallet-owned credited output as a UTXO
//   - attach any wallet-owned spent inputs to that new transaction row
//
// Each backend implements those steps with its own sqlc-generated query types
// while createTxWithOps keeps the high-level sequencing in one place.
type createTxOps interface {
	// loadExisting loads any existing wallet-scoped transaction row for the
	// same hash.
	loadExisting(ctx context.Context,
		req createTxRequest) (*createTxExistingTarget, error)

	// confirmExisting reuses one existing row when CreateTx learns about the
	// same transaction with confirming block context later.
	confirmExisting(ctx context.Context, req createTxRequest,
		existing createTxExistingTarget) error

	// prepareBlock validates and caches any optional confirming block metadata
	// the later insert step needs.
	prepareBlock(ctx context.Context, req createTxRequest) error

	// listDirectConflictTargets returns the direct wallet-owned spender rows
	// that conflict with the incoming transaction on its inputs.
	listDirectConflictTargets(ctx context.Context,
		req createTxRequest) ([]invalidateUnminedTxTarget, error)

	// invalidateConflicts invalidates the provided direct conflicting root rows
	// and any dependent descendants before the incoming transaction claims
	// their wallet-owned inputs.
	invalidateConflicts(ctx context.Context, req createTxRequest,
		rootTargets []invalidateUnminedTxTarget) error

	// insert writes the base transaction row and returns its new primary key.
	insert(ctx context.Context, req createTxRequest) (int64, error)

	// insertCredits records every wallet-owned output that the caller
	// marked as a credit for this transaction.
	insertCredits(ctx context.Context, req createTxRequest, txID int64) error

	// markInputsSpent attaches wallet-owned parent outpoints to this
	// transaction row and rejects conflicts or invalid wallet parents.
	markInputsSpent(ctx context.Context, req createTxRequest, txID int64) error
}

// maybeConfirmCreateTxExisting decides whether CreateTx can reuse an existing
// wallet-scoped row instead of inserting a new one.
func maybeConfirmCreateTxExisting(ctx context.Context, req createTxRequest,
	existing createTxExistingTarget, ops createTxOps) (bool, error) {

	if req.params.Block == nil {
		return false, nil
	}

	if req.params.Status != TxStatusPublished {
		return false, nil
	}

	if existing.hasBlock {
		return false, nil
	}

	if existing.isCoinbase {
		if !req.isCoinbase || existing.status != TxStatusOrphaned {
			return false, nil
		}

		err := ops.confirmExisting(ctx, req, existing)
		if err != nil {
			return false, err
		}

		return true, nil
	}

	if !isUnminedStatus(existing.status) {
		return false, nil
	}

	err := ops.confirmExisting(ctx, req, existing)
	if err != nil {
		return false, err
	}

	return true, nil
}

// maybeInvalidateCreateTxConflicts invalidates any direct conflict roots that a
// newly confirmed transaction supersedes before the new row claims their
// wallet-owned inputs.
func maybeInvalidateCreateTxConflicts(ctx context.Context,
	req createTxRequest, ops createTxOps) error {

	if req.params.Block == nil {
		return nil
	}

	conflictTargets, err := ops.listDirectConflictTargets(ctx, req)
	if err != nil {
		return fmt.Errorf("list create transaction conflicts: %w", err)
	}

	if len(conflictTargets) == 0 {
		return nil
	}

	err = ops.invalidateConflicts(ctx, req, conflictTargets)
	if err != nil {
		return fmt.Errorf("invalidate create transaction conflicts: %w", err)
	}

	return nil
}

// loadCreateTxExisting resolves any wallet-scoped row already stored for the
// requested tx hash and reports whether one was found.
func loadCreateTxExisting(ctx context.Context, req createTxRequest,
	ops createTxOps) (*createTxExistingTarget, bool, error) {

	existing, err := ops.loadExisting(ctx, req)
	if err != nil && !errors.Is(err, errCreateTxExistingNotFound) {
		return nil, false,
			fmt.Errorf("load create transaction target: %w", err)
	}

	if errors.Is(err, errCreateTxExistingNotFound) {
		return nil, false, nil
	}

	if existing == nil {
		return nil, false, nil
	}

	return existing, true, nil
}

// createTxWithOps runs the backend-independent CreateTx orchestration once the
// caller has opened a backend-specific SQL transaction.
//
// The helper can either confirm an existing unmined row or insert a new row.
// For confirmed inserts it also invalidates any current direct conflict branch
// before the new row claims wallet-owned inputs.
func createTxWithOps(ctx context.Context, req createTxRequest,
	ops createTxOps) error {

	existing, foundExisting, err := loadCreateTxExisting(ctx, req, ops)
	if err != nil {
		return err
	}

	if foundExisting {
		handled, err := maybeConfirmCreateTxExisting(ctx, req, *existing, ops)
		if err != nil {
			return fmt.Errorf("confirm existing transaction: %w", err)
		}

		if handled {
			return nil
		}

		return fmt.Errorf("transaction %s: %w", req.txHash, ErrTxAlreadyExists)
	}

	err = ops.prepareBlock(ctx, req)
	if err != nil {
		return fmt.Errorf("prepare create block assignment: %w", err)
	}

	err = maybeInvalidateCreateTxConflicts(ctx, req, ops)
	if err != nil {
		return err
	}

	txID, err := ops.insert(ctx, req)
	if err != nil {
		return fmt.Errorf("insert transaction: %w", err)
	}

	err = ops.insertCredits(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create transaction credits: %w", err)
	}

	err = ops.markInputsSpent(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("create transaction spends: %w", err)
	}

	return nil
}

// prepareUpdateTxBlockHeight validates the optional confirming block reference
// for one UpdateTx state patch and returns the backend-specific nullable block
// height wrapper to store on the row.
func prepareUpdateTxBlockHeight[heightT, nullHeightT any](ctx context.Context,
	block *Block,
	requireBlock func(context.Context, *Block) (heightT, error),
	newNullHeight func(heightT) nullHeightT) (nullHeightT, error) {

	var zeroNullHeight nullHeightT

	if block == nil {
		return zeroNullHeight, nil
	}

	height, err := requireBlock(ctx, block)
	if err != nil {
		return zeroNullHeight,
			fmt.Errorf("require confirming block: %w", err)
	}

	return newNullHeight(height), nil
}

// validateUpdateTxParams checks that UpdateTx received at least one mutable
// field and that any requested state transition satisfies the transaction table
// invariants.
func validateUpdateTxParams(params UpdateTxParams, isCoinbase bool) error {
	if params.Label == nil && params.State == nil {
		return fmt.Errorf("%w: UpdateTx requires at least one field",
			ErrInvalidParam)
	}

	if params.State != nil {
		return validateUpdateTxState(*params.State, isCoinbase)
	}

	return nil
}

// validateUpdateTxState checks the block/status combinations UpdateTx may store
// on an existing row.
func validateUpdateTxState(state UpdateTxState, isCoinbase bool) error {
	_, err := parseTxStatus(int64(state.Status))
	if err != nil {
		return fmt.Errorf("%w: status %d is not supported: %w",
			ErrInvalidParam, state.Status, ErrInvalidStatus)
	}

	// Only disconnected coinbase rows become orphaned. Ordinary
	// transactions use the replaced/failed states instead, so UpdateTx
	// must reject orphaned transitions for non-coinbase history.
	if !isCoinbase && state.Status == TxStatusOrphaned {
		return fmt.Errorf("%w: non-coinbase txns cannot be orphaned: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	// Any row with a confirming block represents mined history, and mined
	// wallet history is always published from the wallet's point of view.
	if state.Block != nil && state.Status != TxStatusPublished {
		return fmt.Errorf("%w: confirmed txns must be published: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	// A unmined coinbase row only appears after rollback disconnects its block,
	// at which point the row must be marked orphaned rather than treated as an
	// active unmined transaction.
	if isCoinbase && state.Block == nil && state.Status != TxStatusOrphaned {
		return fmt.Errorf("%w: unmined coinbase txns must be orphaned: %w",
			ErrInvalidParam, ErrInvalidStatus)
	}

	return nil
}

// updateTxOps is the minimal backend adapter the shared UpdateTx workflow
// needs.
//
// UpdateTx first loads the existing row metadata so it can validate the patch,
// then optionally prepares any block/state params, and finally applies the
// label update and state update in one SQL transaction.
type updateTxOps interface {
	// loadIsCoinbase returns whether the existing row is coinbase history
	// so the shared validation can enforce orphaning rules correctly.
	loadIsCoinbase(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (bool, error)

	// prepareState validates and caches any backend-specific block/status
	// params needed for the later row update.
	prepareState(ctx context.Context, state UpdateTxState) error

	// updateLabel applies one user-visible label patch.
	updateLabel(ctx context.Context, walletID uint32, txHash chainhash.Hash,
		label string) error

	// updateState applies one block/status patch after prepareState succeeds.
	updateState(ctx context.Context, walletID uint32, txHash chainhash.Hash,
		state UpdateTxState) error
}

var errUpdateTxTargetNotFound = errors.New(
	"update transaction target not found",
)

// prepareUpdateTxStateParams validates the requested state patch and returns
// the backend-specific block-height/status values that the later SQL update
// needs.
func prepareUpdateTxStateParams[heightT, nullHeightT, statusT any](
	ctx context.Context, state UpdateTxState,
	newStatus func(TxStatus) statusT,
	requireBlock func(context.Context, *Block) (heightT, error),
	newNullHeight func(heightT) nullHeightT) (nullHeightT, statusT, error) {

	blockHeight, err := prepareUpdateTxBlockHeight(
		ctx, state.Block, requireBlock, newNullHeight,
	)
	if err != nil {
		var zeroStatus statusT

		return blockHeight, zeroStatus, err
	}

	return blockHeight, newStatus(state.Status), nil
}

// loadUpdateTxIsCoinbase loads the coinbase bit from one existing transaction
// row and maps backend not-found cases to ErrTxNotFound.
func loadUpdateTxIsCoinbase(ctx context.Context, txHash chainhash.Hash,
	load func(context.Context) (bool, error)) (bool, error) {

	isCoinbase, err := load(ctx)
	if err != nil {
		if errors.Is(err, errUpdateTxTargetNotFound) {
			return false, fmt.Errorf("transaction %s: %w", txHash,
				ErrTxNotFound)
		}

		return false, err
	}

	return isCoinbase, nil
}

// applyUpdateTxRows checks the affected-row count for one backend UpdateTx
// write and maps zero-row results to ErrTxNotFound.
func applyUpdateTxRows(ctx context.Context, txHash chainhash.Hash,
	action string, update func(context.Context) (int64, error)) error {

	rows, err := update(ctx)
	if err != nil {
		return fmt.Errorf("%s row: %w", action, err)
	}

	if rows == 0 {
		return fmt.Errorf("transaction %s: %w", txHash, ErrTxNotFound)
	}

	return nil
}

// updateTxWithOps runs the shared UpdateTx patch workflow inside one backend-
// specific SQL transaction.
//
// The helper validates the existing row first, prepares any requested state
// patch next, and then applies the label patch and state patch in that order.
// That keeps block validation and row mutation inside one transaction while
// still allowing callers to update either field independently.
func updateTxWithOps(ctx context.Context, params UpdateTxParams,
	ops updateTxOps) error {

	isCoinbase, err := ops.loadIsCoinbase(
		ctx, params.WalletID, params.Txid,
	)
	if err != nil {
		return fmt.Errorf("load update transaction target: %w", err)
	}

	err = validateUpdateTxParams(params, isCoinbase)
	if err != nil {
		return err
	}

	if params.State != nil {
		err = ops.prepareState(ctx, *params.State)
		if err != nil {
			return fmt.Errorf("prepare transaction state update: %w", err)
		}
	}

	if params.Label != nil {
		err = ops.updateLabel(ctx, params.WalletID, params.Txid, *params.Label)
		if err != nil {
			return fmt.Errorf("update transaction label: %w", err)
		}
	}

	if params.State != nil {
		err = ops.updateState(ctx, params.WalletID, params.Txid, *params.State)
		if err != nil {
			return fmt.Errorf("update transaction state: %w", err)
		}
	}

	return nil
}

// deleteTxOps is the minimal backend adapter the shared DeleteTx workflow
// needs.
//
// The shared delete sequence is:
//   - load and validate the target unmined row
//   - reject deletes that would orphan direct child spenders
//   - restore any wallet-owned parents the tx had marked spent
//   - delete wallet-owned outputs created by the tx itself
//   - delete the transaction row last
type deleteTxOps interface {
	// loadDeleteTarget returns the row ID of the unmined transaction
	// DeleteTx is allowed to remove.
	loadDeleteTarget(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (int64, error)

	// ensureLeaf rejects DeleteTx when the target still has direct
	// unmined child spenders.
	ensureLeaf(ctx context.Context, walletID uint32, txHash chainhash.Hash,
		txID int64) error

	// clearSpentUtxos restores any wallet-owned parent outputs the
	// transaction had marked spent.
	clearSpentUtxos(ctx context.Context, walletID uint32, txID int64) error

	// deleteCreatedUtxos removes any wallet-owned outputs created by the
	// transaction being deleted.
	deleteCreatedUtxos(ctx context.Context, walletID uint32, txID int64) error

	// deleteUnminedTransaction removes the target row after its dependent
	// wallet state has been cleaned up.
	deleteUnminedTransaction(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (int64, error)
}

// deleteTxWithOps runs the shared DeleteTx sequence inside a backend-specific
// SQL transaction.
//
// The helper restores wallet-owned parent state before deleting created wallet
// outputs and only removes the transaction row last, so a failed delete cannot
// leave partial wallet bookkeeping behind.
func deleteTxWithOps(ctx context.Context, params DeleteTxParams,
	ops deleteTxOps) error {

	txID, err := ops.loadDeleteTarget(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load delete transaction target: %w", err)
	}

	err = ops.ensureLeaf(ctx, params.WalletID, params.Txid, txID)
	if err != nil {
		return fmt.Errorf("check delete transaction leaf: %w", err)
	}

	err = ops.clearSpentUtxos(ctx, params.WalletID, txID)
	if err != nil {
		return fmt.Errorf("clear spent utxos: %w", err)
	}

	err = ops.deleteCreatedUtxos(ctx, params.WalletID, txID)
	if err != nil {
		return fmt.Errorf("delete created utxos: %w", err)
	}

	rows, err := ops.deleteUnminedTransaction(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("delete unmined transaction: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("transaction %s: %w", params.Txid, ErrTxNotFound)
	}

	return nil
}

// unminedTxRecord is the decoded view of one unmined transaction row used by
// shared descendant checks.
type unminedTxRecord struct {
	id   int64
	hash chainhash.Hash
	tx   *wire.MsgTx
}

// extractUnminedTxFn projects one backend-specific unmined transaction row into
// the shared `(id, tx_hash, raw_tx)` shape used by the invalidation walk.
type extractUnminedTxFn[Row any] func(Row) (int64, []byte, []byte)

// rollbackToBlockOps adapts one SQL backend to the full RollbackToBlock
// sequence, including sync-state rewinds, block deletion, and descendant
// invalidation.
type rollbackToBlockOps interface {
	// listRollbackRootHashes returns the coinbase roots disconnected by the
	// rollback, grouped by wallet for the later descendant walk.
	listRollbackRootHashes(ctx context.Context,
		height uint32) (map[uint32]map[chainhash.Hash]struct{}, error)

	// rewindWalletSyncStateHeights clamps wallet sync-state references
	// below the rollback boundary before block rows are removed.
	rewindWalletSyncStateHeights(ctx context.Context, height uint32) error

	// deleteBlocksAtOrAboveHeight removes the shared block rows at or above the
	// rollback boundary after sync-state references have been rewound.
	deleteBlocksAtOrAboveHeight(ctx context.Context, height uint32) error

	// markRollbackRootsOrphaned rewrites the disconnected coinbase roots to the
	// orphaned state after their confirming blocks are deleted.
	markRollbackRootsOrphaned(ctx context.Context, walletID uint32,
		rootHashes map[chainhash.Hash]struct{}) error

	// listUnminedTxRecords loads the wallet's current unmined transaction
	// rows in the normalized shape the descendant walk expects.
	listUnminedTxRecords(ctx context.Context,
		walletID int64) ([]unminedTxRecord, error)

	// clearDescendantSpends removes any wallet-owned spend edges claimed by one
	// invalid descendant before its status is rewritten.
	clearDescendantSpends(ctx context.Context, walletID int64,
		descendantID int64) error

	// markDescendantsFailed batch-marks the discovered descendants as
	// failed once every dependent spend edge has been cleared.
	markDescendantsFailed(ctx context.Context, walletID int64,
		descendantIDs []int64) error
}

// newUnminedTxRecord decodes one normalized unmined transaction row into the
// shared dependency-walk shape.
func newUnminedTxRecord(id int64, hash []byte,
	rawTx []byte) (unminedTxRecord, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return unminedTxRecord{}, fmt.Errorf("transaction hash: %w", err)
	}

	tx, err := deserializeMsgTx(rawTx)
	if err != nil {
		return unminedTxRecord{}, err
	}

	return unminedTxRecord{id: id, hash: *txHash, tx: tx}, nil
}

// buildUnminedTxRecords decodes backend-specific unmined transaction rows into
// the shared dependency-walk shape.
func buildUnminedTxRecords[T any](rows []T,
	extract extractUnminedTxFn[T]) ([]unminedTxRecord, error) {

	records := make([]unminedTxRecord, 0, len(rows))
	for _, row := range rows {
		id, hash, rawTx := extract(row)

		record, err := newUnminedTxRecord(id, hash, rawTx)
		if err != nil {
			return nil, fmt.Errorf("decode unmined transaction %d: %w", id, err)
		}

		records = append(records, record)
	}

	return records, nil
}

// collectDirectChildTxIDs returns the IDs of unmined transactions that directly
// spend any output created by the provided parent hash.
func collectDirectChildTxIDs(parentHash chainhash.Hash,
	candidates []unminedTxRecord) []int64 {

	parentHashes := map[chainhash.Hash]struct{}{
		parentHash: {},
	}

	childIDs := make([]int64, 0, len(candidates))
	for _, candidate := range candidates {
		if txSpendsAnyParent(candidate.tx, parentHashes) {
			childIDs = append(childIDs, candidate.id)
		}
	}

	return childIDs
}

// collectDescendantTxIDs returns every unmined transaction that depends on any
// of the provided root hashes, including indirect descendants discovered
// through newly invalidated child hashes.
func collectDescendantTxIDs(rootHashes map[chainhash.Hash]struct{},
	candidates []unminedTxRecord) []int64 {

	invalidHashes := make(map[chainhash.Hash]struct{}, len(rootHashes))
	for hash := range rootHashes {
		invalidHashes[hash] = struct{}{}
	}

	invalidIDs := make(map[int64]struct{}, len(candidates))
	for changed := true; changed; {
		changed = false

		for _, candidate := range candidates {
			if _, ok := invalidIDs[candidate.id]; ok {
				continue
			}

			if !txSpendsAnyParent(candidate.tx, invalidHashes) {
				continue
			}

			invalidIDs[candidate.id] = struct{}{}
			invalidHashes[candidate.hash] = struct{}{}
			changed = true
		}
	}

	descendantIDs := make([]int64, 0, len(invalidIDs))
	for _, candidate := range candidates {
		if _, ok := invalidIDs[candidate.id]; ok {
			descendantIDs = append(descendantIDs, candidate.id)
		}
	}

	return descendantIDs
}

// invalidateRollbackDescendants clears spend edges and marks failed every
// unmined descendant discovered from the provided wallet-scoped rollback roots.
func invalidateRollbackDescendants(ctx context.Context,
	rootHashesByWallet map[uint32]map[chainhash.Hash]struct{},
	ops rollbackToBlockOps) error {

	for walletID, rootHashes := range rootHashesByWallet {
		walletID64 := int64(walletID)

		candidates, err := ops.listUnminedTxRecords(ctx, walletID64)
		if err != nil {
			return fmt.Errorf("list unmined rollback descendants for "+
				"wallet %d: %w", walletID, err)
		}

		descendantIDs := collectDescendantTxIDs(rootHashes, candidates)
		if len(descendantIDs) == 0 {
			continue
		}

		for _, descendantID := range descendantIDs {
			err = ops.clearDescendantSpends(ctx, walletID64, descendantID)
			if err != nil {
				return fmt.Errorf("clear rollback descendant spends for "+
					"wallet %d: %w", walletID, err)
			}
		}

		err = ops.markDescendantsFailed(ctx, walletID64, descendantIDs)
		if err != nil {
			return fmt.Errorf("mark rollback descendants failed for "+
				"wallet %d: %w", walletID, err)
		}
	}

	return nil
}

// markRollbackRootsOrphaned rewrites every disconnected coinbase root to the
// orphaned state before descendant invalidation completes.
func markRollbackRootsOrphaned(ctx context.Context,
	rootHashesByWallet map[uint32]map[chainhash.Hash]struct{},
	ops rollbackToBlockOps) error {

	for walletID, rootHashes := range rootHashesByWallet {
		err := ops.markRollbackRootsOrphaned(ctx, walletID, rootHashes)
		if err != nil {
			return fmt.Errorf(
				"mark rollback coinbase roots orphaned for wallet %d: %w",
				walletID, err,
			)
		}
	}

	return nil
}

// rollbackToBlockWithOps runs the shared RollbackToBlock sequence inside one
// backend-specific SQL transaction.
//
// The helper rewinds sync-state heights before deleting blocks, then clears and
// fails any now-invalid unmined descendants rooted in disconnected coinbase
// history so rollback cannot leave dangling references behind.
func rollbackToBlockWithOps(ctx context.Context, height uint32,
	ops rollbackToBlockOps) error {

	rootHashesByWallet, err := ops.listRollbackRootHashes(ctx, height)
	if err != nil {
		return fmt.Errorf("list rollback coinbase roots: %w", err)
	}

	err = ops.rewindWalletSyncStateHeights(ctx, height)
	if err != nil {
		return fmt.Errorf("rewind wallet sync state heights: %w", err)
	}

	err = ops.deleteBlocksAtOrAboveHeight(ctx, height)
	if err != nil {
		return fmt.Errorf("delete blocks at or above height: %w", err)
	}

	err = markRollbackRootsOrphaned(ctx, rootHashesByWallet, ops)
	if err != nil {
		return err
	}

	err = invalidateRollbackDescendants(ctx, rootHashesByWallet, ops)
	if err != nil {
		return err
	}

	return nil
}

// txSpendsAnyParent reports whether the transaction spends any hash in the
// provided parent set.
func txSpendsAnyParent(tx *wire.MsgTx,
	parentHashes map[chainhash.Hash]struct{}) bool {

	for _, txIn := range tx.TxIn {
		if _, ok := parentHashes[txIn.PreviousOutPoint.Hash]; ok {
			return true
		}
	}

	return false
}

// isUnminedStatus reports whether a status still represents an unmined
// transaction that DeleteTx may erase.
func isUnminedStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished:
		return true

	case TxStatusReplaced, TxStatusFailed, TxStatusOrphaned:
		return false

	default:
		return false
	}
}
