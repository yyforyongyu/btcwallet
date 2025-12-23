package wallet

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errDBMock = errors.New("db error")

// TestHandleUnlockReq verifies the unlock request handler.
func TestHandleUnlockReq(t *testing.T) {
	t.Parallel()

	// Arrange
	w, deps := createTestWalletWithMocks(t)

	// Must start wallet to unlock.
	w.state.toStarted()

	pass := []byte("password")
	req := newUnlockReq(UnlockRequest{Passphrase: pass})

	// Expect addrStore.Unlock.
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	// Act
	w.handleUnlockReq(req)

	// Assert
	resp := <-req.resp
	require.NoError(t, resp)
	require.True(t, w.state.isUnlocked())
}

// TestHandleUnlockReq_Errors verifies error paths in handleUnlockReq.
func TestHandleUnlockReq_Errors(t *testing.T) {
	t.Parallel()

	// 1. ErrStateForbidden (Wallet Locked).
	w, deps := createTestWalletWithMocks(t)
	// Wallet stopped -> canUnlock fails.

	pass := []byte("password")
	req := newUnlockReq(UnlockRequest{Passphrase: pass})

	// Act 1: Stopped state.
	w.handleUnlockReq(req)
	err := <-req.resp
	require.ErrorIs(t, err, ErrStateForbidden)

	// Act 2: DBUnlock failure.
	w.state.toStarted() // Now canUnlock passes.

	req = newUnlockReq(UnlockRequest{Passphrase: pass})
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(
		errDBMock,
	).Once()

	w.handleUnlockReq(req)
	err = <-req.resp
	require.ErrorContains(t, err, "db error")
}

// TestHandleLockReq verifies the lock request handler.
func TestHandleLockReq(t *testing.T) {
	t.Parallel()

	// Arrange
	w, deps := createTestWalletWithMocks(t)
	w.state.toStarted()
	w.state.toUnlocked()

	req := newLockReq()

	// Expect addrStore.Lock.
	deps.addrStore.On("Lock").Return(nil).Once()

	// Act
	w.handleLockReq(req)

	// Assert
	resp := <-req.resp
	require.NoError(t, resp)
	require.False(t, w.state.isUnlocked())
}

// TestHandleLockReq_Errors verifies error paths in handleLockReq.
func TestHandleLockReq_Errors(t *testing.T) {
	t.Parallel()

	// Arrange
	w, _ := createTestWalletWithMocks(t)
	// Stopped -> canLock fails.

	req := newLockReq()

	// Act: Stopped.
	w.handleLockReq(req)
	err := <-req.resp
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestMainLoop verifies that the main loop can start and stop correctly.
func TestMainLoop(t *testing.T) {
	t.Parallel()

	w, _ := createTestWalletWithMocks(t)
	ctx, cancel := context.WithCancel(context.Background())
	w.lifetimeCtx = ctx
	w.cancel = cancel

	// Act: Start main loop in a goroutine.
	var testWg sync.WaitGroup
	testWg.Add(1)
	w.wg.Add(1)

	go func() {
		defer testWg.Done()

		w.mainLoop()
	}()

	// Act: Stop main loop.
	cancel()
	testWg.Wait()
}

// TestHandleChangePassphraseReq verifies the change passphrase request
// handler stub.
func TestHandleChangePassphraseReq(t *testing.T) {
	t.Parallel()

	w, _ := createTestWalletWithMocks(t)
	req := newChangePassphraseReq(ChangePassphraseRequest{})

	// Act: Call the stub (should not panic).
	w.handleChangePassphraseReq(req)
}

// TestControllerStart verifies the Start method.
func TestControllerStart(t *testing.T) {
	t.Parallel()

	w, deps := createTestWalletWithMocks(t)

	// Setup mocks for startup sequence.
	// 1. verifyBirthday -> DBGetBirthdayBlock.
	bs := waddrmgr.BlockStamp{Height: 100}
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(bs, true, nil).Once()

	// 2. DBGetAllAccounts -> ActiveScopedKeyManagers.
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()

	// 3. deleteExpiredLockedOutputs.
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// 4. syncer.run.
	deps.syncer.On(
		"run", mock.Anything,
	).Return(nil).Once()

	// Act
	err := w.Start(context.Background())
	require.NoError(t, err)

	// Assert
	require.True(t, w.state.isStarted())

	// Clean up
	_ = w.Stop(context.Background())
	w.wg.Wait()
}

// TestControllerStop verifies the Stop method.
func TestControllerStop(t *testing.T) {
	t.Parallel()

	w, deps := createTestWalletWithMocks(t)

	// Setup for Start.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// Expect run to be called and block until context canceled.
	deps.syncer.On("run", mock.Anything).Run(func(args mock.Arguments) {
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			return
		}
		<-ctx.Done()
	}).Return(nil).Once()

	// Start first.
	require.NoError(t, w.Start(context.Background()))
	require.True(t, w.state.isStarted())

	// Act: Stop.
	err := w.Stop(context.Background())
	require.NoError(t, err)

	// Assert: State is Stopped.
	require.False(t, w.state.isStarted())

	// Act: Stop again (idempotent/safe).
	err = w.Stop(context.Background())
	require.NoError(t, err)
}

// TestControllerLock verifies the Lock method.
func TestControllerLock(t *testing.T) {
	t.Parallel()

	w, deps := createTestWalletWithMocks(t)

	// Setup for Start.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// Expect run.
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Start.
	require.NoError(t, w.Start(context.Background()))

	// Manually unlock state for test.
	w.state.toUnlocked()
	require.True(t, w.state.isUnlocked())

	// Expect addrStore.Lock.
	deps.addrStore.On("Lock").Return(nil).Once()

	// Act: Lock.
	err := w.Lock(context.Background())
	require.NoError(t, err)

	// Assert: State is Locked.
	require.False(t, w.state.isUnlocked())

	// Clean up.
	_ = w.Stop(context.Background())
	w.wg.Wait()
}

// TestControllerUnlock verifies the Unlock method.
func TestControllerUnlock(t *testing.T) {
	t.Parallel()

	w, deps := createTestWalletWithMocks(t)

	// Setup for Start.
	deps.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(waddrmgr.BlockStamp{}, true, nil).Once()
	deps.addrStore.On(
		"ActiveScopedKeyManagers",
	).Return([]waddrmgr.AccountStore(nil)).Once()
	deps.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// Expect run.
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Start.
	require.NoError(t, w.Start(context.Background()))
	require.False(t, w.state.isUnlocked())

	pass := []byte("password")

	// Expect addrStore.Unlock.
	deps.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	// Act: Unlock.
	err := w.Unlock(context.Background(), UnlockRequest{Passphrase: pass})
	require.NoError(t, err)

	// Assert: State is Unlocked.
	require.True(t, w.state.isUnlocked())

	// Clean up.
	_ = w.Stop(context.Background())
	w.wg.Wait()
}

