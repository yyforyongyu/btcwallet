package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/waddrmgr"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestDBBirthdayBlock verifies DBPutBirthdayBlock and DBGetBirthdayBlock.
func TestDBBirthdayBlock(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)

	block := waddrmgr.BlockStamp{
		Height:    100,
		Hash:      chainhash.Hash{0x01},
		Timestamp: time.Unix(1000, 0),
	}

	// 1. Test DBPutBirthdayBlock.
	// Expect SetBirthdayBlock.
	mocks.addrStore.On(
		"SetBirthdayBlock", mock.Anything, block, true,
	).Return(nil).Once()
	// Expect SetSyncedTo.
	mocks.addrStore.On(
		"SetSyncedTo", mock.Anything, &block,
	).Return(nil).Once()

	err := w.DBPutBirthdayBlock(context.Background(), block)
	require.NoError(t, err)

	// 2. Test DBGetBirthdayBlock.
	// Expect BirthdayBlock.
	mocks.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(block, true, nil).Once()

	retBlock, verified, err := w.DBGetBirthdayBlock(context.Background())
	require.NoError(t, err)
	require.True(t, verified)
	require.Equal(t, block, retBlock)
}

// TestDBUnlock verifies DBUnlock.
func TestDBUnlock(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)

	pass := []byte("password")

	// Expect Unlock.
	mocks.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	err := w.DBUnlock(context.Background(), pass)
	require.NoError(t, err)
}

// TestDBDeleteExpiredLockedOutputs verifies DBDeleteExpiredLockedOutputs.
func TestDBDeleteExpiredLockedOutputs(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)

	// Expect DeleteExpiredLockedOutputs.
	mocks.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	err := w.DBDeleteExpiredLockedOutputs(context.Background())
	require.NoError(t, err)
}
