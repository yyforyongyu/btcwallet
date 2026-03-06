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

	// errInvalidTxStatus indicates that a status string does not map to a
	// supported TxStatus value.
	errInvalidTxStatus = errors.New("invalid transaction status")

	// errCreditIndexOutOfRange indicates that a credited output index does not
	// exist in the serialized transaction.
	errCreditIndexOutOfRange = errors.New("credit index out of range")

	// errDuplicateCreditIndex indicates that CreateTx received the same credit
	// output index more than once.
	errDuplicateCreditIndex = errors.New("duplicate credit index")

	// errDeleteLiveUnconfirmedTxRequired indicates that DeleteTx was
	// called for a transaction that is not part of the live
	// unconfirmed set.
	errDeleteLiveUnconfirmedTxRequired = errors.New(
		"delete requires a live unconfirmed transaction",
	)

	// errDeleteTxHasDependents indicates that DeleteTx was called for a
	// transaction that still has direct child spenders.
	errDeleteTxHasDependents = errors.New(
		"delete requires a leaf transaction",
	)
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

	maxIndex, err := intToUint32(len(params.Tx.TxOut))
	if err != nil {
		return fmt.Errorf("convert tx output count: %w", err)
	}

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

	return nil
}

// validateCreateTxStatus enforces the combinations of block assignment,
// wallet-visible status, and coinbase semantics that CreateTx accepts.
func validateCreateTxStatus(status TxStatus, block *Block,
	isCoinbase bool) error {

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

// txDeleteHooks bundles the backend-specific callbacks used by
// the shared live-unconfirmed delete flow.
type txDeleteHooks struct {
	// LoadMeta resolves the transaction row to evaluate and delete.
	LoadMeta func(context.Context) (txChainMeta, error)

	// ListChildren returns any direct child spenders that still depend on the
	// candidate transaction.
	ListChildren func(context.Context, int64) ([]int64, error)

	// ClearSpentByTx releases wallet-owned inputs previously claimed by the
	// transaction being deleted.
	ClearSpentByTx func(context.Context, int64) error

	// DeleteUtxosByTx removes wallet-owned outputs created by the transaction.
	DeleteUtxosByTx func(context.Context, int64) error

	// DeleteTx removes the transaction row itself and reports affected rows.
	DeleteTx func(context.Context) (int64, error)
}

// buildTxDeleteHooks wires backend-specific delete callbacks into
// the shared txDeleteHooks container.
func buildTxDeleteHooks(
	loadMeta func(context.Context) (txChainMeta, error),
	listChildren func(context.Context, int64) ([]int64, error),
	clearSpentByTx func(context.Context, int64) error,
	deleteUtxosByTx func(context.Context, int64) error,
	deleteTx func(context.Context) (int64, error),
) txDeleteHooks {

	return txDeleteHooks{
		LoadMeta:        loadMeta,
		ListChildren:    listChildren,
		ClearSpentByTx:  clearSpentByTx,
		DeleteUtxosByTx: deleteUtxosByTx,
		DeleteTx:        deleteTx,
	}
}

// deleteTxCommon removes one live unconfirmed leaf transaction through the
// backend-specific callbacks supplied in txDeleteHooks.
func deleteTxCommon(ctx context.Context, txid chainhash.Hash,
	hooks txDeleteHooks) error {

	meta, err := hooks.LoadMeta(ctx)
	if err != nil {
		return err
	}

	if meta.HasBlock || !isLiveUnconfirmedStatus(meta.Status) {
		return fmt.Errorf("transaction %s: %w", txid,
			errDeleteLiveUnconfirmedTxRequired)
	}

	childIDs, err := hooks.ListChildren(ctx, meta.ID)
	if err != nil {
		return err
	}

	if len(childIDs) > 0 {
		return fmt.Errorf("transaction %s: %w", txid,
			errDeleteTxHasDependents)
	}

	err = hooks.ClearSpentByTx(ctx, meta.ID)
	if err != nil {
		return err
	}

	err = hooks.DeleteUtxosByTx(ctx, meta.ID)
	if err != nil {
		return err
	}

	rows, err := hooks.DeleteTx(ctx)
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("transaction %s: %w", txid, ErrTxNotFound)
	}

	return nil
}

// isLiveUnconfirmedStatus reports whether a transaction remains part of the
// live unconfirmed graph that ordinary DeleteTx calls are allowed to mutate.
func isLiveUnconfirmedStatus(status TxStatus) bool {
	switch status {
	case TxStatusPending, TxStatusPublished:
		return true

	case TxStatusReplaced, TxStatusFailed, TxStatusOrphaned:
		return false
	}

	return false
}
