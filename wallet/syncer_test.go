package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
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
