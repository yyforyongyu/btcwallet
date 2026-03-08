package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

var (
	// errInvalidUtxoAmount indicates that a UTXO row contained a
	// negative amount, which would violate wallet value invariants.
	errInvalidUtxoAmount = errors.New("invalid utxo amount")

	// errInvalidConfirmedUtxoHeight indicates that a confirmed
	// UTXO row reused the public unmined-height sentinel instead
	// of a real block height.
	errInvalidConfirmedUtxoHeight = errors.New(
		"invalid confirmed utxo height",
	)

	// errInvalidLockID indicates that a lease row contained bytes
	// that cannot be represented as a fixed-size LockID.
	errInvalidLockID = errors.New("invalid lock id length")

	// errOutputAlreadyLeased indicates that a UTXO lease request
	// conflicted with an existing active lease held by another
	// lock ID.
	errOutputAlreadyLeased = errors.New("output already leased")

	// errOutputUnlockNotAllowed indicates that a lease release request used a
	// different lock ID from the currently active lease.
	errOutputUnlockNotAllowed = errors.New("output unlock not allowed")
)

// utxoLeaseHooks bundles the backend-specific lease queries used by
// the shared acquire and release flows.
type utxoLeaseHooks struct {
	// AcquireLease attempts to create or renew the requested lease and returns
	// the resulting expiration time.
	AcquireLease func(context.Context) (time.Time, error)

	// LookupUtxoID checks whether the requested outpoint still exists as a
	// wallet-owned UTXO when lease acquisition fails.
	LookupUtxoID func(context.Context) (int64, error)

	// ReleaseLease clears the active lease for the resolved UTXO row when the
	// caller presents the correct lock ID.
	ReleaseLease func(context.Context, int64) (int64, error)
}

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

	if amount < 0 {
		return nil, fmt.Errorf("utxo amount %d: %w", amount,
			errInvalidUtxoAmount)
	}

	outPoint, err := buildOutPoint(hash, outputIndex)
	if err != nil {
		return nil, err
	}

	height := UnminedHeight
	if blockHeight != nil {
		if *blockHeight == UnminedHeight {
			return nil, fmt.Errorf("utxo confirmed height %d: %w",
				*blockHeight, errInvalidConfirmedUtxoHeight)
		}

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

// acquireLeaseCommon applies the shared lease acquisition rules.
// Callers may renew their own lease, reclaim an expired lease,
// but must fail if another active lock still owns the UTXO.
func acquireLeaseCommon(ctx context.Context, outPoint wire.OutPoint, id LockID,
	hooks utxoLeaseHooks) (*LeasedOutput, error) {

	expiration, err := hooks.AcquireLease(ctx)
	if err == nil {
		return &LeasedOutput{
			OutPoint:   outPoint,
			LockID:     id,
			Expiration: expiration.UTC(),
		}, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	_, lookupErr := hooks.LookupUtxoID(ctx)
	if lookupErr != nil {
		if errors.Is(lookupErr, sql.ErrNoRows) {
			return nil, fmt.Errorf("utxo %s: %w", outPoint, ErrUtxoNotFound)
		}

		return nil, lookupErr
	}

	return nil, fmt.Errorf("utxo %s: %w", outPoint, errOutputAlreadyLeased)
}

// releaseLeaseCommon applies the shared release rules. The target
// UTXO must exist and the caller's lock ID must match the active
// lease row.
func releaseLeaseCommon(ctx context.Context, outPoint wire.OutPoint,
	hooks utxoLeaseHooks) error {

	utxoID, err := hooks.LookupUtxoID(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("utxo %s: %w", outPoint, ErrUtxoNotFound)
		}

		return err
	}

	rows, err := hooks.ReleaseLease(ctx, utxoID)
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("utxo %s: %w", outPoint, errOutputUnlockNotAllowed)
	}

	return nil
}
