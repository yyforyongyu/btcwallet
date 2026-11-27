// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
)

// mockCoinSelectionStrategy is a mock implementation of CoinSelectionStrategy.
type mockCoinSelectionStrategy struct {
	mock.Mock
}

var _ CoinSelectionStrategy = (*mockCoinSelectionStrategy)(nil)

// ArrangeCoins implements the CoinSelectionStrategy interface.
func (m *mockCoinSelectionStrategy) ArrangeCoins(coins []Coin,
	feeRate btcutil.Amount) ([]Coin, error) {

	args := m.Called(coins, feeRate)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]Coin), args.Error(1)
}

// mockSpendDetails is a mock implementation of the SpendDetails interface.
type mockSpendDetails struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockSpendDetails implements the
// SpendDetails interface.
var _ SpendDetails = (*mockSpendDetails)(nil)

// Sign implements the SpendDetails interface.
func (m *mockSpendDetails) Sign(params *RawSigParams,
	privKey *btcec.PrivateKey) (RawSignature, error) {

	args := m.Called(params, privKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(RawSignature), args.Error(1)
}

// isSpendDetails implements the SpendDetails interface.
func (m *mockSpendDetails) isSpendDetails() {}

// mockController is a mock implementation of the Controller interface.
type mockController struct {
	mock.Mock
}

// Compile-time check to ensure mockController implements Controller.
var _ Controller = (*mockController)(nil)

// Unlock implements the Controller interface.
func (m *mockController) Unlock(ctx context.Context, req UnlockRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// Lock implements the Controller interface.
func (m *mockController) Lock(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// ChangePassphrase implements the Controller interface.
func (m *mockController) ChangePassphrase(ctx context.Context,
	req ChangePassphraseRequest) error {

	args := m.Called(ctx, req)
	return args.Error(0)
}

// Info implements the Controller interface.
func (m *mockController) Info(ctx context.Context) (*Info, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*Info), args.Error(1)
}

// Resync implements the Controller interface.
func (m *mockController) Resync(ctx context.Context, startHeight uint32) error {
	args := m.Called(ctx, startHeight)
	return args.Error(0)
}

// Rescan implements the Controller interface.
func (m *mockController) Rescan(ctx context.Context, startHeight uint32,
	targets []waddrmgr.AccountScope) error {

	args := m.Called(ctx, startHeight, targets)
	return args.Error(0)
}

// mockChainProcessor is a mock implementation of the chainProcessor interface.
type mockChainProcessor struct {
	mock.Mock

	// sub overrides the lifetime-scoped chain event subscription exposed to
	// Wallet callers in tests.
	sub chain.EventSubscription
}

// A compile-time assertion to ensure that mockChainProcessor implements the
// chainProcessor interface.
var _ chainProcessor = (*mockChainProcessor)(nil)

// watchAddrs delegates address watch registration to the configured test
// subscription.
func (m *mockChainProcessor) watchAddrs(ctx context.Context,
	addrs []address.Address) error {

	if m.sub == nil {
		return ctx.Err()
	}

	return m.sub.WatchAddrs(ctx, addrs)
}

// streamDone returns the completion channel of the configured test
// subscription.
func (m *mockChainProcessor) streamDone() <-chan struct{} {
	if m.sub == nil {
		return nil
	}

	return m.sub.Done()
}

// streamErr returns the terminal error of the configured test subscription.
func (m *mockChainProcessor) streamErr() error {
	if m.sub == nil {
		return nil
	}

	return m.sub.Err()
}

// run implements the chainProcessor interface.
func (m *mockChainProcessor) run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// waitForRetry observes the Wallet's retry deadline in controller tests.
func (m *mockChainProcessor) waitForRetry(ctx context.Context,
	retry <-chan time.Time) error {

	args := m.Called(ctx, retry)
	return args.Error(0)
}

// requestScan implements the chainProcessor interface.
func (m *mockChainProcessor) requestScan(ctx context.Context,
	req *scanReq) error {

	args := m.Called(ctx, req)
	return args.Error(0)
}

// syncState implements the chainProcessor interface.
func (m *mockChainProcessor) syncState() syncState {
	args := m.Called()
	return args.Get(0).(syncState)
}

// syncedTo exposes the processed tip and errors expected by wallet callers.
func (m *mockChainProcessor) syncedTo(ctx context.Context) (waddrmgr.BlockStamp,
	error) {

	args := m.Called(ctx)
	return args.Get(0).(waddrmgr.BlockStamp), args.Error(1)
}

// mockTxPublisher mocks only the syncer's non-creating retry capability.
type mockTxPublisher struct {
	mock.Mock
}

// mockTxPublisher implements the private capability used by syncer fixtures.
var _ txRebroadcaster = (*mockTxPublisher)(nil)

// rebroadcast exposes each background retry to the test's declared expectation.
func (m *mockTxPublisher) rebroadcast(ctx context.Context,
	tx *wire.MsgTx) error {

	args := m.Called(ctx, tx)
	return args.Error(0)
}

// stubChainEventSub overrides selected subscription channels or errors in unit
// tests while optionally delegating watch registration to base.
type stubChainEventSub struct {
	events <-chan chain.Event
	done   <-chan struct{}
	err    error
	base   chain.EventSubscription
}

// A compile-time assertion that stubChainEventSub implements
// chain.EventSubscription.
var _ chain.EventSubscription = stubChainEventSub{}

// Events returns the overridden events channel or delegates to base.
func (s stubChainEventSub) Events() <-chan chain.Event {
	if s.events != nil {
		return s.events
	}

	if s.base != nil {
		return s.base.Events()
	}

	return nil
}

// Done returns the overridden done channel or delegates to base.
func (s stubChainEventSub) Done() <-chan struct{} {
	if s.done != nil {
		return s.done
	}

	if s.base != nil {
		return s.base.Done()
	}

	return nil
}

// Err returns the overridden error or delegates to base.
func (s stubChainEventSub) Err() error {
	if s.err != nil {
		return s.err
	}

	if s.base != nil {
		return s.base.Err()
	}

	return nil
}

// WatchAddrs delegates to base when present.
func (s stubChainEventSub) WatchAddrs(ctx context.Context,
	addrs []address.Address) error {

	if s.base != nil {
		return s.base.WatchAddrs(ctx, addrs)
	}

	return ctx.Err()
}

// WatchOutputs delegates to base when present.
func (s stubChainEventSub) WatchOutputs(ctx context.Context,
	outpoints []*wire.OutPoint) error {

	if s.base != nil {
		return s.base.WatchOutputs(ctx, outpoints)
	}

	return ctx.Err()
}
