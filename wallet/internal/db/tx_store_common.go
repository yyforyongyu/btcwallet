package db

import (
	"bytes"
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

	// errDeleteLiveUnconfirmedTxRequired indicates that DeleteTx was called for a
	// transaction that is not part of the live unconfirmed set.
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
