package wallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSyncerInitialization verifies that a new syncer is created with the
// correct default state.
func TestSyncerInitialization(t *testing.T) {
	t.Parallel()

	// Arrange
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}

	// Act
	s := newSyncer(
		Config{RecoveryWindow: 1}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	// Assert
	require.NotNil(t, s)
	require.Equal(t, syncStateBackendSyncing, s.syncState())
	require.False(t, s.isRecoveryMode())
}

// TestSyncerRequestScan verifies that scan requests are correctly accepted
// by the syncer's buffered channel.
func TestSyncerRequestScan(t *testing.T) {
	t.Parallel()

	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(Config{}, mockAddrStore, mockTxStore, mockPublisher)

	req := &scanReq{
		typ: scanTypeRewind,
		startBlock: waddrmgr.BlockStamp{
			Height: 100,
		},
	}

	// Act: Submit request.
	err := s.requestScan(context.Background(), req)

	// Assert: No error (buffer has space).
	require.NoError(t, err)

	// Verify it's in the channel.
	select {
	case received := <-s.scanReqChan:
		require.Equal(t, req, received)
	default:
		require.Fail(t, "request not received")
	}
}

// TestSyncerRequestScanBlocked verifies behavior when the channel is full.
func TestSyncerRequestScanBlocked(t *testing.T) {
	t.Parallel()

	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(Config{}, mockAddrStore, mockTxStore, mockPublisher)

	// Fill the buffer (size 1).
	s.scanReqChan <- &scanReq{}

	// Act: Submit another request with a canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := s.requestScan(ctx, &scanReq{})

	// Assert: Should fail due to context cancellation.
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

// TestSyncerRun verifies the run implementation.
func TestSyncerRun(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
	)

	// 1. initChainSync.
	mockAddrStore.On("Birthday").Return(time.Now()).Maybe()
	mockChain.On("IsCurrent").Return(true).Maybe()
	mockAddrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	mockChain.On("NotifyBlocks").Return(nil).Maybe()

	// Act: Run with canceled context to stop loop immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.run(ctx)
	require.NoError(t, err)
}

// TestWaitUntilBackendSynced verifies polling logic.
func TestWaitUntilBackendSynced(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, nil)

	// 1. First call returns false.
	mockChain.On("IsCurrent").Return(false).Once()
	// 2. Second call returns true.
	mockChain.On("IsCurrent").Return(true).Once()

	err := s.waitUntilBackendSynced(context.Background())
	require.NoError(t, err)
	mockChain.AssertExpectations(t)
}

// TestCheckRollbackNoReorg verifies checkRollback when tips match.
func TestCheckRollbackNoReorg(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockChain := &mockChain{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, nil, nil,
	)

	tip := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}
	mockAddrStore.On("SyncedTo").Return(tip)

	// Mock DBGetSyncedBlocks.
	for i := int32(91); i <= 100; i++ {
		hash := chainhash.Hash{byte(i)}
		mockAddrStore.On(
			"BlockHash", mock.Anything, i,
		).Return(&hash, nil)
	}

	// Mock Remote hashes.
	remoteHashes := make([]chainhash.Hash, 10)
	for i := range 10 {
		remoteHashes[i] = chainhash.Hash{byte(91 + i)}
	}

	mockChain.On(
		"GetBlockHashes", int64(91), int64(100),
	).Return(remoteHashes, nil).Once()

	err := s.checkRollback(context.Background())
	require.NoError(t, err)
}

// TestCheckRollbackDetected verifies checkRollback when reorg is detected.
func TestCheckRollbackDetected(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockChain := &mockChain{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	tip := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}
	mockAddrStore.On("SyncedTo").Return(tip)

	// Mock Local hashes 91-100.
	for i := int32(91); i <= 100; i++ {
		hash := chainhash.Hash{byte(i)}
		mockAddrStore.On(
			"BlockHash", mock.Anything, i,
		).Return(&hash, nil)
	}

	// Mock Remote hashes 91-100. Fork at 95.
	remoteHashes := make([]chainhash.Hash, 10)
	for i := range 10 {
		h := 91 + i
		if h > 95 {
			remoteHashes[i] = chainhash.Hash{0xff} // Mismatch
		} else {
			remoteHashes[i] = chainhash.Hash{byte(h)} // Match
		}
	}

	mockChain.On(
		"GetBlockHashes", int64(91), int64(100),
	).Return(remoteHashes, nil).Once()

	// Fork detected at index 4 (height 95).
	forkHash := chainhash.Hash{byte(95)}
	header := &wire.BlockHeader{Timestamp: time.Now()}
	mockChain.On("GetBlockHeader", &forkHash).Return(header, nil).Once()

	// Expect Rollback.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()
	mockTxStore.On("Rollback", mock.Anything, int32(96)).Return(nil).Once()

	err := s.checkRollback(context.Background())
	require.NoError(t, err)
}

// TestInitChainSync verifies the initial synchronization sequence.
func TestInitChainSync(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain}, mockAddrStore, nil, mockPublisher,
	)

	// 1. waitUntilBackendSynced.
	mockChain.On("IsCurrent").Return(true).Once()

	// 1b. NotifyBlocks.
	mockChain.On("NotifyBlocks").Return(nil).Once()

	// 2. checkRollback.
	tip := waddrmgr.BlockStamp{Height: 0}
	mockAddrStore.On("SyncedTo").Return(tip)

	err := s.initChainSync(context.Background())
	require.NoError(t, err)
}

// TestScanBatchHeadersOnly verifies header-only scan logic.
func TestScanBatchHeadersOnly(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

	hashes := []chainhash.Hash{{0x01}, {0x02}}
	mockChain.On(
		"GetBlockHashes", int64(10), int64(11),
	).Return(hashes, nil).Once()

	headers := []*wire.BlockHeader{
		{Timestamp: time.Unix(100, 0)},
		{Timestamp: time.Unix(200, 0)},
	}
	mockChain.On("GetBlockHeaders", hashes).Return(headers, nil).Once()

	results, err := s.scanBatchHeadersOnly(context.Background(), 10, 11)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, int32(10), results[0].meta.Height)
	require.Equal(t, int32(11), results[1].meta.Height)
}

// TestSyncerLoadScanState verifies full scan state loading.
func TestSyncerLoadScanState(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{
			DB:             db,
			RecoveryWindow: 10,
			ChainParams:    &chaincfg.MainNetParams,
		},
		mockAddrStore, mockTxStore, mockPublisher,
	)

	// 1. mock loadWalletScanData.
	// 1.a. ActiveScopedKeyManagers.
	scopedMgr := &mockAccountStore{}
	mockAddrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()
	// 1.b. ActiveAccounts.
	scopedMgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	// 1.c. DBGetScanData -> FetchScopedKeyManager, AccountProperties,
	// ForEachRelevantActiveAddress, OutputsToWatch.
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Maybe()

	props := &waddrmgr.AccountProperties{
		AccountNumber: 0,
		KeyScope:      waddrmgr.KeyScopeBIP0084,
	}
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(0),
	).Return(props, nil).Once()

	mockAddrStore.On(
		"ForEachRelevantActiveAddress", mock.Anything, mock.Anything,
	).Return(nil).Once()

	mockTxStore.On(
		"OutputsToWatch", mock.Anything,
	).Return([]wtxmgr.Credit(nil), nil).Once()
	// Mock DeriveAddr for lookahead (10 addresses for each branch).
	mockAddr := &mockAddress{}
	mockAddr.On("EncodeAddress").Return("addr")
	mockAddr.On("ScriptAddress").Return([]byte{0x00})
	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(
		mockAddr, []byte{0x00}, nil,
	).Maybe()

	// Act
	state, err := s.loadFullScanState(context.Background())
	require.NoError(t, err)
	require.NotNil(t, state)
}