package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

// TestBuildUtxoInfoMaxAmount verifies that buildUtxoInfo preserves the largest
// valid satoshi amount.
func TestBuildUtxoInfoMaxAmount(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{10}
	info, err := buildUtxoInfo(
		hash[:], 3, int64(btcutil.MaxSatoshi), []byte{0x53},
		time.Unix(333, 0), false, nil,
	)

	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(btcutil.MaxSatoshi), info.Amount)
	require.Equal(t, UnminedHeight, info.Height)
}

// TestBuildUtxoInfoInvalidHash verifies that buildUtxoInfo rejects malformed
// hash bytes.
func TestBuildUtxoInfoInvalidHash(t *testing.T) {
	t.Parallel()

	_, err := buildUtxoInfo(
		[]byte{1, 2, 3}, 6, 1000, []byte{0x56}, time.Unix(666, 0), false, nil,
	)

	require.Error(t, err)
}

// TestBuildLeasedOutputInvalidHash verifies that buildLeasedOutput rejects
// malformed hash bytes.
func TestBuildLeasedOutputInvalidHash(t *testing.T) {
	t.Parallel()

	lockID := make([]byte, 32)
	_, err := buildLeasedOutput([]byte{1, 2, 3}, 7, lockID, time.Unix(777, 0))

	require.Error(t, err)
}

// TestUtxoInfoFromSqliteRowInvalidOutputIndex verifies that the sqlite row
// decoder rejects output indexes outside the uint32 range.
func TestUtxoInfoFromSqliteRowInvalidOutputIndex(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{13}
	_, err := utxoInfoFromSqliteRow(
		hash[:], -1, 1000, []byte{0x57}, time.Unix(888, 0), false,
		sql.NullInt64{},
	)

	require.ErrorContains(t, err, "utxo output index")
}

// TestUtxoInfoFromSqliteRowInvalidBlockHeight verifies that the sqlite row
// decoder rejects invalid confirmed block heights.
func TestUtxoInfoFromSqliteRowInvalidBlockHeight(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{14}
	_, err := utxoInfoFromSqliteRow(
		hash[:], 0, 1000, []byte{0x58}, time.Unix(999, 0), false,
		sql.NullInt64{Int64: -1, Valid: true},
	)

	require.ErrorContains(t, err, "utxo block height")
}

// TestUtxoInfoFromPgRowInvalidOutputIndex verifies that the postgres row
// decoder rejects output indexes outside the uint32 range.
func TestUtxoInfoFromPgRowInvalidOutputIndex(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{15}
	_, err := utxoInfoFromPgRow(
		hash[:], -1, 1000, []byte{0x59}, time.Unix(1000, 0), false,
		sql.NullInt32{},
	)

	require.ErrorContains(t, err, "utxo output index")
}

// TestUtxoInfoFromPgRowInvalidBlockHeight verifies that the postgres row
// decoder rejects invalid confirmed block heights.
func TestUtxoInfoFromPgRowInvalidBlockHeight(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{16}
	_, err := utxoInfoFromPgRow(
		hash[:], 0, 1000, []byte{0x5a}, time.Unix(1001, 0), false,
		sql.NullInt32{Int32: -1, Valid: true},
	)

	require.ErrorContains(t, err, "utxo block height")
}
