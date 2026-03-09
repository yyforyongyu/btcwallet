package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

var (
	// errInvalidLockID indicates that a lease row contained bytes that cannot be
	// represented as a fixed-size LockID.
	errInvalidLockID = errors.New("invalid lock id length")

	// errOutputAlreadyLeased indicates that a UTXO lease request conflicted with
	// an existing active lease held by another lock ID.
	errOutputAlreadyLeased = errors.New("output already leased")

	// ErrOutputAlreadyLeased reports that a UTXO lease request conflicted with
	// another active lock on the same output.
	ErrOutputAlreadyLeased = errOutputAlreadyLeased

	// errOutputUnlockNotAllowed indicates that a lease release request used a
	// different lock ID from the currently active lease.
	errOutputUnlockNotAllowed = errors.New("output unlock not allowed")

	// ErrOutputUnlockNotAllowed reports that a UTXO release request used a lock
	// ID different from the active lease.
	ErrOutputUnlockNotAllowed = errOutputUnlockNotAllowed
)

// buildOutPoint converts database tx-hash and output-index fields into a
// wire.OutPoint.
func buildOutPoint(hash []byte, outputIndex uint32) (wire.OutPoint, error) {

	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return wire.OutPoint{}, fmt.Errorf("utxo hash: %w", err)
	}

	return wire.OutPoint{Hash: *txHash, Index: outputIndex}, nil
}

// buildUtxoInfo converts normalized SQL result fields into the public UtxoInfo
// shape returned by the db interfaces.
func buildUtxoInfo(hash []byte, outputIndex uint32, amount int64,
	pkScript []byte, received time.Time, isCoinbase bool,
	blockHeight *uint32) (*UtxoInfo, error) {

	outPoint, err := buildOutPoint(hash, outputIndex)
	if err != nil {
		return nil, err
	}

	height := UnminedHeight
	if blockHeight != nil {
		height = *blockHeight
	}

	return &UtxoInfo{
		OutPoint:     outPoint,
		Amount:       btcutil.Amount(amount),
		PkScript:     pkScript,
		Received:     received.UTC(),
		FromCoinBase: isCoinbase,
		Height:       height,
	}, nil
}

// buildLeasedOutput converts SQL lease-row fields into the public LeasedOutput
// type.
func buildLeasedOutput(hash []byte, outputIndex uint32, lockID []byte,
	expiration time.Time) (*LeasedOutput, error) {

	outPoint, err := buildOutPoint(hash, outputIndex)
	if err != nil {
		return nil, err
	}

	if len(lockID) != len(LockID{}) {
		return nil, fmt.Errorf("lock id: %w", errInvalidLockID)
	}

	var id LockID
	copy(id[:], lockID)

	return &LeasedOutput{
		OutPoint:   outPoint,
		LockID:     id,
		Expiration: expiration.UTC(),
	}, nil
}
