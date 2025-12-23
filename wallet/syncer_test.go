package wallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
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

// TestScanBatchWithFullBlocks verifies fallback scan logic.
func TestScanBatchWithFullBlocks(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

	// Mock recovery state.
	mockAddrStore := &mockAddrStore{}
	scanState := NewRecoveryState(
		10, &chaincfg.MainNetParams, mockAddrStore,
	)

	hashes := []chainhash.Hash{{0x01}}

	// Create a mock block.
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	blocks := []*wire.MsgBlock{msgBlock}
	mockChain.On(
		"GetBlocks", hashes,
	).Return(blocks, nil).Once()

	results, err := s.scanBatchWithFullBlocks(
		context.Background(), scanState, 10, hashes,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, int32(10), results[0].meta.Height)
}

// TestScanBatchWithCFilters verifies CFilter-based scan logic.
func TestScanBatchWithCFilters(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db}, nil, nil, mockPublisher,
	)

	// Mock recovery state.
	mockAddrStore := &mockAddrStore{}
	scanState := NewRecoveryState(
		10, &chaincfg.MainNetParams, mockAddrStore,
	)

	hashes := []chainhash.Hash{{0x01}}

	// 1. Mock GetCFilters.
	filter, err := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	require.NoError(t, err)
	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()

	// 2. Mock GetBlockHeaders.
	headers := []*wire.BlockHeader{{Timestamp: time.Unix(100, 0)}}
	mockChain.On("GetBlockHeaders", hashes).Return(headers, nil).Once()

	// 3. Mock GetBlocks.
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On("GetBlocks", hashes).Return(
		[]*wire.MsgBlock{msgBlock}, nil,
	).Once()

	// 4. Mock AddrStore failure paths to avoid deep derivation logic.
	mockAddrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(nil, waddrmgr.ErrAddressNotFound).Maybe()
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(nil, waddrmgr.ErrAddressNotFound).Maybe()

	results, err := s.scanBatchWithCFilters(
		context.Background(), scanState, 10, hashes,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, int32(10), results[0].meta.Height)
}

// TestDispatchScanStrategy verifies strategy selection.
func TestDispatchScanStrategy(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)
	scanState := NewRecoveryState(10, &chaincfg.MainNetParams, nil)
	hashes := []chainhash.Hash{{0x01}}

	// 1. SyncMethodFullBlocks.
	s.cfg.SyncMethod = SyncMethodFullBlocks
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))
	mockChain.On(
		"GetBlocks", hashes,
	).Return([]*wire.MsgBlock{msgBlock}, nil).Once()
	results, err := s.dispatchScanStrategy(
		context.Background(), scanState, 10, hashes,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// 2. SyncMethodCFilters.
	s.cfg.SyncMethod = SyncMethodCFilters
	filter, _ := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)
	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return([]*gcs.Filter{filter}, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()
	// Filter N=0 forces GetBlocks.
	mockChain.On(
		"GetBlocks", hashes,
	).Return([]*wire.MsgBlock{msgBlock}, nil).Once()
	results, err = s.dispatchScanStrategy(
		context.Background(), scanState, 10, hashes,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestScanBatch verifies the batch scanning entry point.
func TestScanBatch(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &mockAddrStore{}
	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, nil,
		mockPublisher,
	)

	// Mock loadFullScanState (needed by scanBatch).
	scopedMgr := &mockAccountStore{}
	mockAddrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()
	scopedMgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mockAddrStore.On(
		"FetchScopedKeyManager", mock.Anything,
	).Return(scopedMgr, nil).Maybe()
	scopedMgr.On(
		"AccountProperties", mock.Anything, uint32(0),
	).Return(&waddrmgr.AccountProperties{}, nil).Once()
	mockAddrStore.On(
		"ForEachRelevantActiveAddress", mock.Anything, mock.Anything,
	).Return(nil).Once()

	mockTxStore := &mockTxStore{}
	s.txStore = mockTxStore
	mockTxStore.On(
		"OutputsToWatch", mock.Anything,
	).Return([]wtxmgr.Credit(nil), nil).Once()

	// Mock fetchAndFilterBlocks (called by scanBatch).
	// Since scanState.Empty() is true, it calls scanBatchHeadersOnly.
	hashes := []chainhash.Hash{{0x01}}
	mockChain.On(
		"GetBlockHashes", int64(11), int64(11),
	).Return(hashes, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()

	// DBPutSyncBatch calls SetSyncedTo.
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Once()

	// Act
	err := s.scanBatch(
		context.Background(), waddrmgr.BlockStamp{Height: 10}, 11,
	)
	require.NoError(t, err)
}

// TestFetchAndFilterBlocks verifies the block fetching and filtering helper.
func TestFetchAndFilterBlocks(t *testing.T) {
	t.Parallel()

	mockChain := &mockChain{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(Config{Chain: mockChain}, nil, nil, mockPublisher)

	// RecoveryState created here is empty.
	scanState := NewRecoveryState(10, &chaincfg.MainNetParams, nil)
	hashes := []chainhash.Hash{{0x01}}

	// Since scanState.Empty() is true, it calls scanBatchHeadersOnly.
	mockChain.On(
		"GetBlockHashes", int64(10), int64(11),
	).Return(hashes, nil).Once()
	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return([]*wire.BlockHeader{{}}, nil).Once()

	results, err := s.fetchAndFilterBlocks(
		context.Background(), scanState, 10, 11,
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// TestAdvanceChainSync verifies advancement logic.
func TestAdvanceChainSync(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockChain := &mockChain{}
	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockPublisher := &mockTxPublisher{}
	s := newSyncer(
		Config{Chain: mockChain, DB: db}, mockAddrStore, mockTxStore,
		mockPublisher,
	)

	// Case 1: Already synced.
	mockChain.On(
		"GetBestBlock",
	).Return(&chainhash.Hash{}, int32(100), nil).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	finished, err := s.advanceChainSync(context.Background())
	require.NoError(t, err)
	require.True(t, finished)
	require.Equal(t, syncStateSynced, s.syncState())

	// Case 2: Behind, trigger scan.
	mockChain.On("GetBestBlock").Return(
		&chainhash.Hash{}, int32(105), nil,
	).Once()
	mockAddrStore.On("SyncedTo").Return(
		waddrmgr.BlockStamp{Height: 100},
	).Once()

	// scanBatch calls...
	// loadFullScanState...
	scopedMgr := &mockAccountStore{}
	mockAddrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore{scopedMgr}).Once()
	scopedMgr.On("ActiveAccounts").Return([]uint32{0}).Once()
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
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

	scopedMgr.On(
		"DeriveAddr", mock.Anything, mock.Anything, mock.Anything,
	).Return(
		&mockAddress{}, []byte{}, nil,
	).Maybe()

	// fetchAndFilterBlocks...
	// Since state is NOT empty (contains target 0), it calls
	// GetBlockHashes.
	hashes := []chainhash.Hash{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}}
	mockChain.On(
		"GetBlockHashes", int64(101), int64(105),
	).Return(hashes, nil).Once()

	// dispatchScanStrategy...
	filter, _ := gcs.BuildGCSFilter(
		builder.DefaultP, builder.DefaultM, [16]byte{}, nil,
	)

	filters := make([]*gcs.Filter, 5)
	for i := range 5 {
		filters[i] = filter
	}

	mockChain.On(
		"GetCFilters", hashes, wire.GCSFilterRegular,
	).Return(filters, nil).Once()

	headers := make([]*wire.BlockHeader, 5)
	for i := range 5 {
		headers[i] = &wire.BlockHeader{}
	}

	mockChain.On(
		"GetBlockHeaders", hashes,
	).Return(headers, nil).Once()

	// Filter N=0 forces download of all 5 blocks.
	msgBlock := wire.NewMsgBlock(wire.NewBlockHeader(
		1, &chainhash.Hash{}, &chainhash.Hash{}, 0, 0,
	))

	blocks := make([]*wire.MsgBlock, 5)
	for i := range 5 {
		blocks[i] = msgBlock
	}

	mockChain.On(
		"GetBlocks", hashes,
	).Return(blocks, nil).Once()

	// DBPutSyncBatch...
	mockAddrStore.On(
		"SetSyncedTo", mock.Anything, mock.Anything,
	).Return(nil).Times(5)

	finished, err = s.advanceChainSync(context.Background())
	require.NoError(t, err)
	require.False(t, finished)
}
