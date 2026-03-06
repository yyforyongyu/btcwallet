package db

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

// TestBuildOutPoint verifies the common hash/index conversion shared by both
// SQL backends when building public outpoints.
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

// TestBuildUtxoInfo verifies that the shared row-to-domain mapper preserves the
// expected sentinel semantics for confirmed and unconfirmed outputs.
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
}

// TestBuildLeasedOutput verifies the common conversion used by both SQL
// backends when surfacing active leases.
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
