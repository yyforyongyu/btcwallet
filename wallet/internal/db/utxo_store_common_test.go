package db

import (
	"database/sql"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

// TestBuildOutPoint verifies the shared outpoint mapper for valid inputs.
//
// Scenario:
// - One normalized outpoint row is converted into the public outpoint shape.
// Setup:
// - Build one known transaction hash fixture.
// Action:
// - Convert the normalized hash and output index through buildOutPoint.
// Assertions:
// - Valid inputs produce the expected wire.OutPoint.
func TestBuildOutPoint(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid normalized outpoint row.
	hash := chainhash.Hash{1, 2, 3}

	// Act: Convert the normalized row.
	outPoint, err := buildOutPoint(hash[:], 7)

	// Assert: The public outpoint preserves the original hash and index.
	require.NoError(t, err)
	require.Equal(t, hash, outPoint.Hash)
	require.Equal(t, uint32(7), outPoint.Index)
}

// TestBuildOutPointInvalidHash verifies that buildOutPoint rejects malformed
// transaction hashes.
//
// Scenario:
// - One normalized outpoint row carries malformed transaction-hash bytes.
// Setup:
// - Build one malformed hash payload.
// Action:
// - Convert the malformed row through buildOutPoint.
// Assertions:
// - Invalid hashes fail loudly.
func TestBuildOutPointInvalidHash(t *testing.T) {
	t.Parallel()

	// Arrange: Build one malformed outpoint row.
	malformedHash := []byte{1, 2, 3}

	// Act: Convert the malformed row.
	_, err := buildOutPoint(malformedHash, 0)

	// Assert: The malformed hash is rejected.
	require.Error(t, err)
}

// TestBuildUtxoInfoConfirmed verifies the shared UTXO row-to-domain mapper for
// confirmed outputs.
//
// Scenario:
// - One confirmed SQL row is converted into the public UtxoInfo shape.
// Setup:
// - Build one known hash fixture and confirmed block height.
// Action:
// - Convert the confirmed row through buildUtxoInfo.
// Assertions:
// - The confirmed row preserves amount, outpoint, and mined height.
func TestBuildUtxoInfoConfirmed(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid confirmed UTXO row.
	hash := chainhash.Hash{9}
	confirmedHeight := uint32(33)

	// Act: Convert the confirmed row.
	confirmed, err := buildUtxoInfo(
		hash[:], 1, 1234, []byte{0x51}, time.Unix(111, 0), true,
		&confirmedHeight,
	)

	// Assert: Confirmed metadata is preserved.
	require.NoError(t, err)
	require.Equal(t, confirmedHeight, confirmed.Height)
	require.Equal(t, hash, confirmed.OutPoint.Hash)
	require.Equal(t, uint32(1), confirmed.OutPoint.Index)
}

// TestBuildUtxoInfoUnconfirmed verifies that buildUtxoInfo maps unconfirmed
// rows onto the public unmined sentinel.
//
// Scenario:
// - One unconfirmed SQL row is converted into the public UtxoInfo shape.
// Setup:
// - Build one known hash fixture with no block height.
// Action:
// - Convert the unconfirmed row through buildUtxoInfo.
// Assertions:
//   - The missing height maps to UnminedHeight and timestamps are normalized to
//     UTC.
func TestBuildUtxoInfoUnconfirmed(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid unconfirmed UTXO row.
	hash := chainhash.Hash{9}

	// Act: Convert the unconfirmed row.
	unconfirmed, err := buildUtxoInfo(
		hash[:], 2, 5678, []byte{0x52}, time.Unix(222, 0), false, nil,
	)

	// Assert: Unconfirmed metadata uses the public unmined sentinel.
	require.NoError(t, err)
	require.Equal(t, UnminedHeight, unconfirmed.Height)
	require.Equal(t, time.UTC, unconfirmed.Received.Location())
}

// TestBuildUtxoInfoMaxAmount verifies that buildUtxoInfo preserves the largest
// valid SQL amount.
//
// Scenario:
// - One SQL row carries the largest valid satoshi amount encodable in int64.
// Setup:
// - Build one known hash fixture and use math.MaxInt64 as the stored amount.
// Action:
// - Convert the row through buildUtxoInfo.
// Assertions:
// - The amount is preserved without truncation.
func TestBuildUtxoInfoMaxAmount(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid row carrying the maximum SQL amount.
	hash := chainhash.Hash{9}

	// Act: Convert the row.
	maxAmount, err := buildUtxoInfo(
		hash[:], 3, math.MaxInt64, []byte{0x53}, time.Unix(333, 0), false,
		nil,
	)

	// Assert: The maximum amount is preserved.
	require.NoError(t, err)
	require.Equal(t, int64(math.MaxInt64), int64(maxAmount.Amount))
}

// TestBuildUtxoInfoInvalidAmount verifies that buildUtxoInfo rejects negative
// SQL amounts.
//
// Scenario:
// - One SQL row carries a negative amount.
// Setup:
// - Build one known hash fixture and a negative stored amount.
// Action:
// - Convert the row through buildUtxoInfo.
// Assertions:
// - The helper returns errInvalidUtxoAmount.
func TestBuildUtxoInfoInvalidAmount(t *testing.T) {
	t.Parallel()

	// Arrange: Build one malformed row carrying a negative amount.
	hash := chainhash.Hash{9}

	// Act: Convert the malformed row.
	_, err := buildUtxoInfo(
		hash[:], 4, -1, []byte{0x54}, time.Unix(444, 0), false, nil,
	)

	// Assert: Negative amounts are rejected.
	require.ErrorIs(t, err, errInvalidUtxoAmount)
}

// TestBuildUtxoInfoInvalidConfirmedHeight verifies that buildUtxoInfo rejects
// impossible confirmed heights.
//
// Scenario:
// - One confirmed SQL row carries the UnminedHeight sentinel.
// Setup:
// - Build one known hash fixture and an impossible confirmed height.
// Action:
// - Convert the row through buildUtxoInfo.
// Assertions:
// - The helper returns errInvalidConfirmedUtxoHeight.
func TestBuildUtxoInfoInvalidConfirmedHeight(t *testing.T) {
	t.Parallel()

	// Arrange: Build one malformed confirmed row.
	hash := chainhash.Hash{9}
	invalidConfirmedHeight := UnminedHeight

	// Act: Convert the malformed row.
	_, err := buildUtxoInfo(
		hash[:], 5, 100, []byte{0x55}, time.Unix(555, 0), false,
		&invalidConfirmedHeight,
	)

	// Assert: Impossible confirmed heights are rejected.
	require.ErrorIs(t, err, errInvalidConfirmedUtxoHeight)
}

// TestBuildUtxoInfoInvalidHash verifies that buildUtxoInfo propagates malformed
// outpoint hashes.
func TestBuildUtxoInfoInvalidHash(t *testing.T) {
	t.Parallel()

	_, err := buildUtxoInfo(
		[]byte{1, 2, 3}, 5, 100, []byte{0x55}, time.Unix(555, 0), false,
		nil,
	)
	require.Error(t, err)
}

// TestBuildLeasedOutput verifies the shared lease row mapper for valid leases.
//
// Scenario:
// - One valid SQL lease row is converted into the public lease shape.
// Setup:
// - Build one hash fixture plus one correctly sized lock ID.
// Action:
// - Convert the valid lease row through buildLeasedOutput.
// Assertions:
// - The lease preserves the outpoint, lock ID, and UTC expiration time.
func TestBuildLeasedOutput(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid lease row.
	hash := chainhash.Hash{4, 5, 6}
	lockID := make([]byte, 32)
	lockID[0] = 7

	// Act: Convert the valid lease row.
	lease, err := buildLeasedOutput(
		hash[:], 9, lockID, time.Unix(333, 0).In(time.FixedZone("X", 3600)),
	)

	// Assert: The public lease view preserves the stored metadata.
	require.NoError(t, err)
	require.Equal(t, hash, lease.OutPoint.Hash)
	require.Equal(t, uint32(9), lease.OutPoint.Index)
	require.Equal(t, byte(7), lease.LockID[0])
	require.Equal(t, time.UTC, lease.Expiration.Location())
}

// TestBuildLeasedOutputInvalidLockID verifies that buildLeasedOutput rejects
// malformed lock IDs.
//
// Scenario:
// - One SQL lease row carries a malformed lock ID payload.
// Setup:
// - Build one hash fixture plus one short lock ID.
// Action:
// - Convert the malformed lease row through buildLeasedOutput.
// Assertions:
// - Invalid lock IDs fail with errInvalidLockID.
func TestBuildLeasedOutputInvalidLockID(t *testing.T) {
	t.Parallel()

	// Arrange: Build one malformed lease row.
	hash := chainhash.Hash{4, 5, 6}
	shortLockID := []byte{1, 2, 3}

	// Act: Convert the malformed lease row.
	_, err := buildLeasedOutput(hash[:], 0, shortLockID, time.Now())

	// Assert: The malformed lock ID is rejected.
	require.ErrorIs(t, err, errInvalidLockID)
}

// TestBuildLeasedOutputInvalidHash verifies that buildLeasedOutput propagates
// malformed outpoint hashes before attempting lock decoding.
func TestBuildLeasedOutputInvalidHash(t *testing.T) {
	t.Parallel()

	lockID := make([]byte, 32)
	_, err := buildLeasedOutput([]byte{1, 2, 3}, 0, lockID, time.Now())
	require.Error(t, err)
}

func TestUtxoInfoFromSqliteRowInvalidOutputIndex(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{1}

	_, err := utxoInfoFromSqliteRow(
		hash[:], -1, 1000, []byte{0x51}, time.Unix(1, 0), false,
		sql.NullInt64{},
	)
	require.ErrorContains(t, err, "utxo output index")
}

func TestUtxoInfoFromSqliteRowInvalidBlockHeight(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{1}

	_, err := utxoInfoFromSqliteRow(
		hash[:], 0, 1000, []byte{0x51}, time.Unix(1, 0), false,
		sql.NullInt64{Int64: -1, Valid: true},
	)
	require.ErrorContains(t, err, "utxo block height")
}

func TestUtxoInfoFromPgRowInvalidOutputIndex(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{1}

	_, err := utxoInfoFromPgRow(
		hash[:], -1, 1000, []byte{0x51}, time.Unix(1, 0), false,
		sql.NullInt32{},
	)
	require.ErrorContains(t, err, "utxo output index")
}

func TestUtxoInfoFromPgRowInvalidBlockHeight(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{1}

	_, err := utxoInfoFromPgRow(
		hash[:], 0, 1000, []byte{0x51}, time.Unix(1, 0), false,
		sql.NullInt32{Int32: -1, Valid: true},
	)
	require.ErrorContains(t, err, "utxo block height")
}
