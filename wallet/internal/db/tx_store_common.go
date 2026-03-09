package db

// tx_store_common.go holds the shared validation, serialization, and spend
// dependency helpers used by both SQL TxStore backends.

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

	// errInvalidTxStatus indicates that a status string does not map to a
	// supported TxStatus value.
	errInvalidTxStatus = errors.New("invalid transaction status")

	// errCreditIndexOutOfRange indicates that a credited output index does not
	// exist in the serialized transaction.
	errCreditIndexOutOfRange = errors.New("credit index out of range")

	// errDuplicateCreditIndex indicates that CreateTx received the same credit
	// output index more than once.
	errDuplicateCreditIndex = errors.New("duplicate credit index")

	// errDuplicateInputOutPoint indicates that CreateTx received the same
	// previous outpoint more than once.
	errDuplicateInputOutPoint = errors.New("duplicate input outpoint")
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

// parseTxStatus converts a stored status string into the strongly typed
// TxStatus enum used by the public db API.
func parseTxStatus(status string) (TxStatus, error) {

	switch TxStatus(status) {
	case TxStatusPending,
		TxStatusPublished,
		TxStatusReplaced,
		TxStatusFailed,
		TxStatusOrphaned:

		return TxStatus(status), nil

	default:
		return "", fmt.Errorf("status %q: %w", status, errInvalidTxStatus)
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

	seenCredits := make(map[uint32]struct{}, len(params.Credits))
	maxIndex := uint32(len(params.Tx.TxOut))

	for _, credit := range params.Credits {
		if credit.Index >= maxIndex {
			return fmt.Errorf(
				"credit index %d: %w", credit.Index,
				errCreditIndexOutOfRange,
			)
		}

		if _, ok := seenCredits[credit.Index]; ok {
			return fmt.Errorf(
				"credit index %d: %w", credit.Index,
				errDuplicateCreditIndex,
			)
		}

		seenCredits[credit.Index] = struct{}{}
	}

	if !isCoinbase {
		seenInputs := make(map[wire.OutPoint]struct{}, len(params.Tx.TxIn))

		for _, txIn := range params.Tx.TxIn {
			if _, ok := seenInputs[txIn.PreviousOutPoint]; ok {
				return fmt.Errorf(
					"input outpoint %s: %w",
					txIn.PreviousOutPoint, errDuplicateInputOutPoint,
				)
			}

			seenInputs[txIn.PreviousOutPoint] = struct{}{}
		}
	}

	return nil
}

// validateCreateTxStatus enforces the combinations of block assignment,
// wallet-visible status, and coinbase semantics that CreateTx accepts.
func validateCreateTxStatus(status TxStatus, block *Block, isCoinbase bool) error {

	_, err := parseTxStatus(string(status))
	if err != nil {
		return err
	}

	if status == TxStatusOrphaned {
		return errCreateTxOrphanedStatus
	}

	if isCoinbase && block == nil {
		return errCoinbaseRequiresBlock
	}

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

// newLiveTxRecord decodes one normalized live transaction row into the shared
// dependency-walk shape.
func newLiveTxRecord(
	id int64, hash []byte, rawTx []byte,
) (liveTxRecord, error) {

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

	// Keep walking until one full pass finds no new descendants. Each newly
	// invalidated child hash can reveal additional grandchildren on the next
	// iteration.
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
func applyRollbackDescendantInvalidation[
	Row any, ClearParams any, UpdateParams any,
](ctx context.Context,
	rootHashesByWallet map[uint32]map[chainhash.Hash]struct{},
	listUnminedTransactions func(context.Context, int64) ([]Row, error),
	extractLiveTx func(Row) (int64, []byte, []byte),
	clearUtxosSpentByTxID func(context.Context, ClearParams) (int64, error),
	buildClearParams func(walletID int64, descendantID int64) ClearParams,
	updateTransactionStatusByIDs func(context.Context, UpdateParams) (
		int64, error,
	),
	buildUpdateParams func(walletID int64, descendantIDs []int64) UpdateParams,
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
	status string, label string) (*TxInfo, error) {

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
