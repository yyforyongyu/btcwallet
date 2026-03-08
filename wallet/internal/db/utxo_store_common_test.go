package db

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

// TestBuildOutPoint verifies the shared outpoint mapper.
//
// Scenario:
// - SQL rows provide both valid and invalid transaction hashes.
// Setup:
// - Build one known hash fixture and one malformed byte slice.
// Action:
// - Convert each hash plus output index through buildOutPoint.
// Assertions:
// - Valid inputs produce the expected wire.OutPoint.
// - Invalid hashes fail loudly.
func TestBuildOutPoint(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{1, 2, 3}

	outPoint, err := buildOutPoint(hash[:], 7)
	require.NoError(t, err)
	require.Equal(t, hash, outPoint.Hash)
	require.Equal(t, uint32(7), outPoint.Index)

	_, err = buildOutPoint([]byte{1, 2, 3}, 0)
	require.Error(t, err)
}

// TestBuildUtxoInfo verifies the shared UTXO row-to-domain mapper.
//
// Scenario:
// - SQL rows describe confirmed, unconfirmed, and malformed wallet outputs.
// Setup:
// - Build one hash fixture plus heights and amounts covering each case.
// Action:
// - Convert each row shape through buildUtxoInfo.
// Assertions:
// - Valid rows preserve amount, outpoint, and UTC timestamp semantics.
// - Invalid negative amounts and impossible confirmed heights are rejected.
func TestBuildUtxoInfo(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{9}
	confirmedHeight := uint32(33)

	confirmed, err := buildUtxoInfo(
		hash[:], 1, 1234, []byte{0x51}, time.Unix(111, 0), true,
		&confirmedHeight,
	)
	require.NoError(t, err)
	require.Equal(t, confirmedHeight, confirmed.Height)
	require.Equal(t, hash, confirmed.OutPoint.Hash)
	require.Equal(t, uint32(1), confirmed.OutPoint.Index)

	unconfirmed, err := buildUtxoInfo(
		hash[:], 2, 5678, []byte{0x52}, time.Unix(222, 0), false, nil,
	)
	require.NoError(t, err)
	require.Equal(t, UnminedHeight, unconfirmed.Height)
	require.Equal(t, time.UTC, unconfirmed.Received.Location())

	maxAmount, err := buildUtxoInfo(
		hash[:], 3, math.MaxInt64, []byte{0x53}, time.Unix(333, 0), false,
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, int64(math.MaxInt64), int64(maxAmount.Amount))

	_, err = buildUtxoInfo(
		hash[:], 4, -1, []byte{0x54}, time.Unix(444, 0), false, nil,
	)
	require.ErrorIs(t, err, errInvalidUtxoAmount)

	invalidConfirmedHeight := UnminedHeight
	_, err = buildUtxoInfo(
		hash[:], 5, 100, []byte{0x55}, time.Unix(555, 0), false,
		&invalidConfirmedHeight,
	)
	require.ErrorIs(t, err, errInvalidConfirmedUtxoHeight)
}

// TestBuildLeasedOutput verifies the shared lease row mapper.
//
// Scenario:
// - SQL lease rows provide both valid and malformed lock IDs.
// Setup:
// - Build one hash fixture plus lease bytes with correct and incorrect sizes.
// Action:
// - Convert the lease rows through buildLeasedOutput.
// Assertions:
// - Valid leases preserve the outpoint, lock ID, and UTC expiration time.
// - Invalid lock IDs fail with errInvalidLockID.
func TestBuildLeasedOutput(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{4, 5, 6}
	lockID := make([]byte, 32)
	lockID[0] = 7

	lease, err := buildLeasedOutput(
		hash[:], 9, lockID, time.Unix(333, 0).In(time.FixedZone("X", 3600)),
	)
	require.NoError(t, err)
	require.Equal(t, hash, lease.OutPoint.Hash)
	require.Equal(t, uint32(9), lease.OutPoint.Index)
	require.Equal(t, byte(7), lease.LockID[0])
	require.Equal(t, time.UTC, lease.Expiration.Location())

	_, err = buildLeasedOutput(hash[:], 0, []byte{1, 2, 3}, time.Now())
	require.ErrorIs(t, err, errInvalidLockID)
}
