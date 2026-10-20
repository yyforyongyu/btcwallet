package wallet

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newChainEventTestWallet reuses the joined request-loop fixture for dispatcher
// contract tests whose processor outcomes are supplied by mockChainSyncer.
func newChainEventTestWallet(t *testing.T, name string,
	id uint32) (*Wallet, *mockWalletDeps) {

	t.Helper()

	w, deps := createTestWalletWithMocks(t)
	w.cfg.Name = name
	w.id = id
	startLoadedWalletForTest(t, w)
	deps.vault.On("Lock").Return().Once()

	return w, deps
}

// TestManagerChainEventOrder verifies complete, identically ordered fanout
// including normalized header-only progress, filtered blocks, and mempool txs.
func TestManagerChainEventOrder(t *testing.T) {
	t.Parallel()

	// Arrange: Publish two strict processors in reverse map insertion order;
	// expectations require Wallet-ID order and the same mixed event sequence.
	first, firstDeps := newChainEventTestWallet(t, "first", 1)
	second, secondDeps := newChainEventTestWallet(t, "second", 2)
	manager := testSQLManager(t, &walletmock.Store{})
	manager.wallets[second.cfg.Name] = second
	manager.wallets[first.cfg.Name] = first
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Height: 1},
	}
	tx := chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}}
	filtered := chain.FilteredBlockConnected{
		Block: &wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 2}},
	}
	events := []struct {
		input any
		want  any
	}{
		{
			input: chain.BlockConnected(*block),
			want:  chain.FilteredBlockConnected{Block: block},
		},
		{
			input: filtered,
			want:  filtered,
		},
		{
			input: tx,
			want:  tx,
		},
	}

	calls := make([]*mock.Call, 0, 2*len(events))
	for _, event := range events {
		calls = append(calls, firstDeps.syncer.On(
			"requestChainEvent", mock.Anything, event.want,
			(<-chan struct{})(manager.chainDone), first.syncDone,
		).Return(nil).Once())
		calls = append(calls, secondDeps.syncer.On(
			"requestChainEvent", mock.Anything, event.want,
			(<-chan struct{})(manager.chainDone), second.syncDone,
		).Return(nil).Once())
	}

	mock.InOrder(calls...)

	// Act: Submit normalized source events synchronously through Manager;
	// no consumer reads the maintained notification source in this test.
	results := make([]error, 0, len(events))
	for _, event := range events {
		results = append(results, manager.dispatchChainEvent(
			t.Context(), event.input,
		))
	}

	// Assert: Each complete fanout succeeds; fixture-owned mock verification
	// checks every exact target, payload, order, and single delivery.
	for _, err := range results {
		require.NoError(t, err)
	}
}

// TestManagerChainEventRejectsDisconnect prevents prepared connected fanout
// from reaching the legacy per-Wallet rollback handler.
func TestManagerChainEventRejectsDisconnect(t *testing.T) {
	t.Parallel()

	// Arrange: A strict registered processor and Store permit no event or
	// rollback call; only normal fixture shutdown may touch the Vault.
	w, _ := newChainEventTestWallet(t, "first", 1)
	manager := testSQLManager(t, &walletmock.Store{})
	manager.wallets[w.cfg.Name] = w

	// Act: Submit a disconnect to the prepared connected-event entry point.
	err := manager.dispatchChainEvent(
		t.Context(), chain.BlockDisconnected{},
	)

	// Assert: Rejection is local validation and does not stop the Manager or
	// transfer ownership of the disconnect to any processor.
	require.ErrorIs(t, err, db.ErrInvalidParam)
	require.True(t, manager.started.Load())
}

// TestManagerChainEventFailureStopsManager prevents a processor error after
// partial delivery from leaving an incomplete active set running.
func TestManagerChainEventFailureStopsManager(t *testing.T) {
	t.Parallel()

	// Arrange: The first target accepts an event; the second rejects it.
	// Existing aggregate teardown must join both before returning the cause.
	first, firstDeps := newChainEventTestWallet(t, "first", 1)
	second, secondDeps := newChainEventTestWallet(t, "second", 2)
	manager := testSQLManager(t, &walletmock.Store{})
	manager.wallets[first.cfg.Name] = first
	manager.wallets[second.cfg.Name] = second
	event := chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}}
	failure := errors.New("processor failed")
	mock.InOrder(
		firstDeps.syncer.On(
			"requestChainEvent", mock.Anything, event,
			(<-chan struct{})(manager.chainDone), first.syncDone,
		).Return(nil).Once(),
		secondDeps.syncer.On(
			"requestChainEvent", mock.Anything, event,
			(<-chan struct{})(manager.chainDone), second.syncDone,
		).Return(failure).Once(),
	)

	// Act: Fail the accepted fanout, then attempt later delivery through the
	// same Manager after its terminal cleanup has completed.
	err := manager.dispatchChainEvent(t.Context(), event)
	later := manager.dispatchChainEvent(t.Context(), event)

	// Assert: The primary processor error survives cleanup, both Wallets
	// are inert, and no later event can reach the already closed Store.
	require.ErrorIs(t, err, failure)
	require.ErrorIs(t, later, ErrManagerStopped)
	require.Nil(t, manager.backend)
	require.Empty(t, manager.wallets)
	require.ErrorIs(t, first.state.validateStarted(), ErrWalletStopped)
	require.ErrorIs(t, second.state.validateStarted(), ErrWalletStopped)
}

// chainEventWalletData supplies real private startup and sync-worker reads at
// height zero. Expected maintenance counts make readiness deterministic rather
// than leaving an unsynced fixture unable to receive prepared delivery.
func chainEventWalletData(t *testing.T, name string, id uint32,
	events int) (*walletData, *mockWalletDeps) {

	t.Helper()

	_, deps := createTestWalletWithMocks(t)
	deps.store.On("GetWallet", mock.Anything, name).Return(
		&db.WalletInfo{
			BirthdayBlock: &db.Block{},
			SyncedTo:      &db.Block{},
		}, nil,
	).Times(3 + events)
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: id,
	}).Return([]db.AccountInfo(nil), nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything, id).Return(nil).Once()
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID:      id,
		SkipBalance:   true,
		ChainSyncOnly: true,
	}).Return([]db.AccountInfo(nil), nil).Once()
	expectImportedScanAddressPage(
		deps.store, id, page.Result[db.AddressInfo, uint32]{},
	)
	deps.store.On("ListOutputsToWatch", mock.Anything, id).
		Return([]db.UtxoInfo(nil), nil).Once()
	deps.store.On("ListTxns", mock.Anything, mock.Anything).
		Return([]db.TxInfo(nil), nil).Times(1 + events)
	deps.vault.On("Lock").Return().Once()

	return &walletData{
		id:          id,
		name:        name,
		store:       deps.store,
		vault:       deps.vault,
		isWatchOnly: true,
	}, deps
}

// expectChainEventSource supplies only existing worker initialization and
// maintenance calls. A readiness token marks every actual notification wait;
// the caller's existing fixture remains the sole mock-verification owner.
func expectChainEventSource(backend *bwmock.Chain, wallets, waits int,
	ready chan<- struct{}, source <-chan any) {

	for range wallets {
		backend.On("IsCurrent").Return(true).Once()
		backend.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
			Return(nil).Once()
		backend.On("NotifyBlocks").Return(nil).Once()
	}

	for range waits {
		backend.On("GetBestBlock").Return(
			&chainhash.Hash{}, int32(0), nil,
		).Once()
		backend.On("Notifications").Run(func(mock.Arguments) {
			ready <- struct{}{}
		}).Return(source).Once()
	}
}

// TestManagerChainEventRegistration fixes startup and Create membership at the
// same admission boundary without replaying an older event to the new Wallet.
func TestManagerChainEventRegistration(t *testing.T) {
	t.Parallel()

	// Arrange: Start the complete durable pair on real workers, then
	// prepare a third Wallet for Create. Each worker reaches receipt.
	first, firstDeps := chainEventWalletData(t, "first", 1, 2)
	second, secondDeps := chainEventWalletData(t, "second", 2, 2)
	third, thirdDeps := chainEventWalletData(t, "third", 3, 1)
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).
		Return([]*walletData{first, second}, nil).Once()

	params := managerLifecycleCreateParams("third")
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(third, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	manager.chainDone = make(chan struct{})
	source, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)

	ready := make(chan struct{}, 8)
	expectChainEventSource(source, 3, 8, ready, nil)

	event := chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}}

	processors := []struct {
		store  *walletmock.Store
		id     uint32
		events int
	}{
		{
			store:  firstDeps.store,
			id:     1,
			events: 2,
		},
		{
			store:  secondDeps.store,
			id:     2,
			events: 2,
		},
		{
			store:  thirdDeps.store,
			id:     3,
			events: 1,
		},
	}
	for _, processor := range processors {
		for range processor.events {
			// This registration-only record has no owned effects; each
			// receipt still reaches the prepared batch boundary below.
			processor.store.On(
				"ResolveOwnedAddresses", mock.Anything,
				matchResolveOwnedAddressesQuery(processor.id),
			).Return(map[string]*db.AddressInfo{}, nil).Once()
		}
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) {
			close(entered)
			<-release
		}).Return(nil).Once()
	firstDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Return(nil).Once()
	secondDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Return(nil).Twice()
	thirdDeps.store.On("ApplyTxBatch", mock.Anything, mock.Anything).
		Return(nil).Once()

	loaded, err := manager.Start(t.Context())
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	<-ready
	<-ready

	// Act: Hold an admitted event before Create can publish. After
	// it settles, publish the third processor and deliver again.
	delivered := make(chan error, 1)
	go func() {
		delivered <- manager.dispatchChainEvent(t.Context(), event)
	}()

	<-entered

	type createResult struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createResult, 1)
	go func() {
		w, createErr := manager.Create(params)
		created <- createResult{
			wallet: w,
			err:    createErr,
		}
	}()

	close(release)
	require.NoError(t, <-delivered)

	result := <-created

	for range 3 {
		<-ready
	}

	err = manager.dispatchChainEvent(t.Context(), event)

	for range 3 {
		<-ready
	}

	// Assert: Startup contributes both durable Wallets, Create
	// contributes only to the later fanout, and exact Store calls
	// prove that no old delivery reached the new processor.
	require.NoError(t, result.err)
	require.Equal(t, uint32(3), result.wallet.ID())
	require.NoError(t, err)
}

// TestManagerChainEventWorkerExit prevents partial fanout from waiting forever
// when the actual sync worker ends without canceling Wallet lifetime.
func TestManagerChainEventWorkerExit(t *testing.T) {
	t.Parallel()

	// Arrange: Start a real second worker on an open source, while the first
	// target's strict processor closes that source after accepting the event.
	first, firstDeps := newChainEventTestWallet(t, "first", 1)
	data, deps := chainEventWalletData(t, "second", 2, 0)
	ready := make(chan struct{}, 1)
	source := make(chan any)
	expectChainEventSource(deps.chain, 1, 1, ready, source)
	second := newManagedWallet(Config{
		Name:        "second",
		Chain:       deps.chain,
		ChainParams: &chainParams,
	}, data)
	require.NoError(t, second.start(t.Context()))
	<-ready

	manager := testSQLManager(t, &walletmock.Store{})
	manager.wallets[first.cfg.Name] = first
	manager.wallets[second.cfg.Name] = second
	event := chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}}
	firstDeps.syncer.On("requestChainEvent", mock.Anything, event,
		(<-chan struct{})(manager.chainDone), first.syncDone,
	).Run(func(mock.Arguments) {
		close(source)
		<-second.syncDone
	}).Return(nil).Once()

	// Act: The real second processor has permanently exited by the time its
	// prepared handoff begins; no external Stop is used to release the send.
	err := manager.dispatchChainEvent(t.Context(), event)

	// Assert: A dead processor makes partial fanout fail and closes Store
	// only through joined aggregate teardown, rather than reporting success.
	require.ErrorIs(t, err, ErrWalletStopped)
	require.Nil(t, manager.backend)
	require.Empty(t, manager.wallets)
	require.ErrorIs(t, second.state.validateStarted(), ErrWalletStopped)
}

// TestManagerChainEventBlockPayload verifies atomic no-match progress and
// matching isolation when real processors consume the same block payload.
func TestManagerChainEventBlockPayload(t *testing.T) {
	t.Parallel()

	// Arrange: Share immutable source records between real processors. Each
	// Store receives its own Wallet batch; neither matching pass may edit the
	// source transaction, script, order, or block metadata.
	addr, err := address.NewAddressPubKeyHash(make([]byte, 20), &chainParams)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: script})

	received := time.Unix(1, 0)
	record, err := wtxmgr.NewTxRecordFromMsgTx(tx, received)
	require.NoError(t, err)

	original := *record
	original.MsgTx = *record.MsgTx.Copy()
	original.SerializedTx = bytes.Clone(record.SerializedTx)
	empty := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{1}, Height: 1},
		Time:  time.Unix(1, 0),
	}
	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{2}, Height: 2},
		Time:  time.Unix(2, 0),
	}
	originalBlock := block
	event := chain.FilteredBlockConnected{
		Block:       &block,
		RelevantTxs: []*wtxmgr.TxRecord{record},
	}
	storedEmptyBlock, err := storeBlockFromBlockMeta(empty)
	require.NoError(t, err)

	ready := make(chan struct{}, 6)

	wallets := make([]*Wallet, 0, 2)
	for i, name := range []string{"first", "second"} {
		w, deps := createTestWalletWithMocks(t)
		w.id = uint32(i + 1)
		w.cfg.Name = name
		s := newSyncer(w.cfg, nil, nil, w, w.store, w.id)
		w.sync = s
		w.state = newWalletState(s)

		deps.vault.On("Lock").Return().Once()
		deps.chain.On("Notifications").Run(func(mock.Arguments) {
			ready <- struct{}{}
		}).Return((<-chan any)(nil)).Times(3)
		deps.store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{SyncedTo: &db.Block{}}, nil,
		).Once()
		deps.store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{SyncedTo: &db.Block{Height: 1}}, nil,
		).Once()
		deps.store.On("ApplyTxBatch", mock.Anything, db.TxBatchParams{
			WalletID:     w.id,
			Transactions: []db.CreateTxParams{},
			SyncedTo:     storedEmptyBlock,
		}).Return(nil).Once()
		// Both processors match the shared record independently, so the
		// second matching pass must receive the original transaction data.
		deps.store.On("ResolveOwnedAddresses", mock.Anything,
			matchResolveOwnedAddressesQuery(w.id, script),
		).Return(ownedAddrsResult(script), nil).Once()
		deps.store.On("ApplyTxBatch", mock.Anything,
			matchBlockTxBatch(w.id, tx, addr, received, &block),
		).Return(nil).Once()
		startLoadedWalletForTest(t, w)

		// Pump the existing processor loop under Wallet's joined lifecycle;
		// maintenance/source initialization belongs to the other regressions.
		w.wg.Go(func() {
			for {
				err := s.waitForEvent(w.lifetimeCtx)
				if err != nil {
					return
				}
			}
		})
		wallets = append(wallets, w)
	}

	manager := testSQLManager(t, &walletmock.Store{})
	for _, w := range wallets {
		manager.wallets[w.cfg.Name] = w

		<-ready
	}

	// Act: Advance an empty block for every Wallet, then deliver the shared
	// filtered payload. Tokens ensure both workers are parked before cleanup.
	noMatchErr := manager.dispatchChainEvent(
		t.Context(), chain.BlockConnected(empty),
	)

	for range 2 {
		<-ready
	}

	payloadErr := manager.dispatchChainEvent(t.Context(), event)

	for range 2 {
		<-ready
	}

	// Assert: Batches include each Wallet's tip with its effects, even for
	// zero transactions, and the second processor sees the original payload.
	require.NoError(t, noMatchErr)
	require.NoError(t, payloadErr)
	require.Equal(t, original, *record)
	require.Equal(t, originalBlock, block)
	require.Equal(t, []*wtxmgr.TxRecord{record}, event.RelevantTxs)
}

// TestManagerChainEventWalletRelevance prevents shared prepared records from
// leaking into another Wallet's persisted history or transaction subscription.
func TestManagerChainEventWalletRelevance(t *testing.T) {
	t.Parallel()

	// Arrange: Run two real SQLite Wallets against a genesis-only backend.
	// Explicit notification-wait tokens keep delivery on the existing workers;
	// the first Wallet alone derives the receiving script used by this block.
	manager, source, recipient := newLiveWatchManager(t)
	ready := make(chan struct{}, 6)

	source.On("IsCurrent").Unset()
	source.On("IsCurrent").Return(true).Twice()
	source.On("NotifyBlocks").Return(nil).Twice()
	source.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Return(nil).Times(3)
	source.On("Notifications").Run(func(mock.Arguments) {
		ready <- struct{}{}
	}).Return((<-chan any)(nil)).Times(6)

	params := sqliteCreateParams(t)
	params.Name = "unrelated"
	unrelated, err := manager.Create(params)
	require.NoError(t, err)

	wallets := []*Wallet{recipient, unrelated}
	recv, err := recipient.NewAddress(t.Context(), NewAccountSelectorByName(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
	), false)
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(recv.Addr)
	require.NoError(t, err)

	funding := subscriptionTx(script, 87)
	funding.AddTxOut(&wire.TxOut{Value: 1000, PkScript: script})

	child := subscriptionTx([]byte{txscript.OP_TRUE}, 88)
	child.TxIn[0].PreviousOutPoint = wire.OutPoint{Hash: funding.TxHash()}
	spend := subscriptionTx([]byte{txscript.OP_TRUE}, 89)
	spend.TxIn[0].PreviousOutPoint = wire.OutPoint{
		Hash: funding.TxHash(), Index: 1,
	}

	// The existing post-event maintenance rebroadcasts only the relevant
	// unmined spend. Report it already known so this adds no publication write
	// or extra observation to the prepared-event regression.
	source.On("TestMempoolAccept", mock.MatchedBy(
		func(txns []*wire.MsgTx) bool {
			return len(txns) == 1 && txns[0].TxHash() == spend.TxHash()
		},
	), float64(0)).Return(nil, chain.ErrTxAlreadyInMempool).Once()

	records := make([]*wtxmgr.TxRecord, 0, 3)
	for _, tx := range []*wire.MsgTx{funding, child, spend} {
		record, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Unix(1, 0))
		require.NoError(t, err)

		records = append(records, record)
	}

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{87}, Height: 1},
		Time:  time.Unix(1, 0),
	}
	events, cancel, err := wallets[0].SubscribeTxns(t.Context())
	require.NoError(t, err)

	defer cancel()

	unrelatedEvents, cancelUnrelated, err := wallets[1].SubscribeTxns(
		t.Context(),
	)
	require.NoError(t, err)

	defer cancelUnrelated()

	<-ready
	<-ready

	// Act: Commit a payment with its debit-only same-block child in one
	// prepared block, then submit an unmined spend of its other owned output.
	// Wait tokens also settle ordinary worker maintenance before assertions.
	blockErr := manager.dispatchChainEvent(t.Context(),
		chain.FilteredBlockConnected{
			Block:       &block,
			RelevantTxs: records[:2],
		},
	)

	<-ready
	<-ready

	spendErr := manager.dispatchChainEvent(t.Context(), chain.RelevantTx{
		TxRecord: records[2],
	})

	<-ready
	<-ready

	// Assert: Public history and observations contain all three relevant
	// transactions only in the recipient. The unmatched Wallet advances its
	// atomic checkpoint without a transaction row or a notification.
	require.NoError(t, blockErr)
	require.NoError(t, spendErr)

	for _, record := range records {
		_, err := wallets[0].GetTx(t.Context(), record.Hash)
		require.NoError(t, err)
		_, err = wallets[1].GetTx(t.Context(), record.Hash)
		require.ErrorIs(t, err, ErrTxNotFound)

		select {
		case event := <-events:
			require.Equal(t, record.Hash, event.Detail.Hash)
		default:
			t.Fatal("recipient lost a committed transaction observation")
		}
	}

	history, err := wallets[0].ListTxns(t.Context(), 0, -1)
	require.NoError(t, err)
	require.Len(t, history, 3)
	history, err = wallets[1].ListTxns(t.Context(), 0, -1)
	require.NoError(t, err)
	require.Empty(t, history)

	for _, w := range wallets {
		info, err := w.Info(t.Context())
		require.NoError(t, err)
		require.Equal(t, block.Height, info.SyncedTo.Height)
		require.Equal(t, block.Hash, info.SyncedTo.Hash)
	}

	select {
	case event := <-unrelatedEvents:
		t.Fatalf("unrelated Wallet received transaction observation: %v", event)
	default:
	}
}

// TestManagerChainEventBlockedStop proves a backpressured handoff, failed
// partial delivery, and later admission settle before shared Store closure.
func TestManagerChainEventBlockedStop(t *testing.T) {
	t.Parallel()

	// Arrange: Hold the second existing worker in an accepted rewind. The
	// first target completes, leaving the prepared send blocked on that busy
	// worker; cancellation is observed before allowing its Store call to end.
	first, firstDeps := newChainEventTestWallet(t, "first", 1)
	second, deps := createTestWalletWithMocks(t)
	second.cfg.Name = "second"
	second.id = 2
	s := newSyncer(second.cfg, nil, nil, second, second.store, second.id)
	second.sync = s
	second.state = newWalletState(s)
	s.state.Store(uint32(syncStateSynced))
	deps.vault.On("Lock").Return().Once()
	deps.chain.On("Notifications").Return((<-chan any)(nil)).Once()
	deps.store.On("GetWallet", mock.Anything, "second").Return(
		&db.WalletInfo{SyncedTo: &db.Block{Height: 10}}, nil,
	).Once()
	fork := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{5},
		Height:    5,
		Timestamp: time.Unix(5, 0),
	}
	entered := make(chan struct{})
	draining := make(chan struct{})
	release := make(chan struct{})
	deps.store.On("RewindWallet", mock.Anything,
		matchRewindWalletParams(second.id, fork),
	).Run(func(args mock.Arguments) {
		close(entered)
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			panic("rewind has no context")
		}
		<-ctx.Done()
		close(draining)
		<-release
	}).Return(context.Canceled).Once()
	startLoadedWalletForTest(t, second)
	require.NoError(t, s.requestScan(t.Context(), &scanReq{
		typ:        scanTypeRewind,
		startBlock: fork,
	}))

	workerResult := make(chan error, 1)
	second.wg.Go(func() {
		workerResult <- s.waitForEvent(second.lifetimeCtx)
	})
	<-entered

	manager := testSQLManager(t, &walletmock.Store{})
	manager.wallets[first.cfg.Name] = first
	manager.wallets[second.cfg.Name] = second
	storeClosed := make(chan struct{})
	backend, ok := manager.backend.(*sqlManagerBackend)
	require.True(t, ok)

	backend.closeFn = func() error {
		close(storeClosed)
		return nil
	}
	// Even an aborted assertion must release owned Store work before the
	// existing fixture attempts its Manager/Wallet joins.
	releaseWork := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseWork)

	applied := make(chan struct{})
	event := chain.RelevantTx{TxRecord: &wtxmgr.TxRecord{}}
	firstDeps.syncer.On("requestChainEvent", mock.Anything, event,
		(<-chan struct{})(manager.chainDone), first.syncDone,
	).Run(func(mock.Arguments) {
		close(applied)
	}).Return(nil).Once()

	// Act: Stop while one target has applied and another cannot receive.
	// A concurrent later admission must also reject without Store access.
	delivered := make(chan error, 1)
	later := make(chan error, 1)
	stopped := make(chan error, 1)

	go func() {
		delivered <- manager.dispatchChainEvent(t.Context(), event)
	}()

	<-applied

	go func() { later <- manager.dispatchChainEvent(t.Context(), event) }()
	go func() { stopped <- manager.Stop() }()

	<-draining

	// Assert: Cancellation can release delivery waits, but neither caller
	// nor storage may outlive the still-held processor. Release then join all.
	select {
	case <-storeClosed:
		t.Fatal("Store closes before accepted worker joins")
	default:
	}

	require.Empty(t, delivered)
	require.Empty(t, stopped)
	releaseWork()
	require.ErrorIs(t, <-delivered, ErrManagerStopped)
	require.ErrorIs(t, <-later, ErrManagerStopped)
	require.NoError(t, <-stopped)
	require.ErrorIs(t, <-workerResult, context.Canceled)
	<-storeClosed
}

// TestWalletID verifies that Wallet.ID returns the cached runtime ID.
func TestWalletID(t *testing.T) {
	t.Parallel()

	w := &Wallet{id: 42}

	require.Equal(t, uint32(42), w.ID())
}

// TestManagerBuildsWalletsFromRuntimePolicy verifies sibling SQL Wallets use
// identical Manager policy while retaining independent mutable snapshots.
func TestManagerBuildsWalletsFromRuntimePolicy(t *testing.T) {
	t.Parallel()

	// Arrange: Configure two exact Store creations and a distinctive Manager
	// snapshot shared by both identity-only creation requests.
	const secondWalletName = "second"

	store := &walletmock.Store{}
	for i, name := range []string{"first", secondWalletName} {
		walletID := uint32(i + 1)
		store.On(
			"CreateWallet", mock.Anything,
			mock.MatchedBy(func(params db.CreateWalletParams) bool {
				return params.Name == name
			}),
		).Return(&db.WalletInfo{
			ID:          walletID,
			Name:        name,
			IsWatchOnly: true,
		}, nil).Once()
		store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
		).Once()
		store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
			WalletID: walletID,
		}).
			Return([]db.AccountInfo{}, nil).Once()
		store.On("DeleteExpiredLeases", mock.Anything, walletID).
			Return(nil).Once()
	}

	chainSource := createTestChain(t)
	manager := testSQLManager(t, store)
	manager.config.ChainSource = chainSource
	manager.config.SyncMethod = SyncMethodFullBlocks
	manager.config.WalletSyncRetryInterval = 2 * time.Second
	manager.config.RecoveryWindow = 12
	manager.config.AutoLockDuration = 3 * time.Minute
	manager.config.MaxCFilterItems = 50
	params := CreateWalletParams{
		Mode:              ModeShell,
		WatchOnly:         true,
		PrivatePassphrase: []byte("private"),
	}

	// Act: Create two Wallets with different durable names, then mutate one
	// Wallet's network snapshot after both are assembled.
	params.Name = "first"
	first, err := manager.Create(params)
	require.NoError(t, err)

	params.Name = secondWalletName
	second, err := manager.Create(params)
	require.NoError(t, err)

	first.cfg.ChainParams.Name = "mutated"

	// Assert: Verify the caller-owned source is shared while scalar policy is
	// identical, network snapshots are independent, and each Store call occurs
	// exactly once.
	require.Same(t, chainSource, first.cfg.Chain)
	require.Same(t, chainSource, second.cfg.Chain)
	require.Equal(t, SyncMethodFullBlocks, first.cfg.SyncMethod)
	require.Equal(t, first.cfg.SyncMethod, second.cfg.SyncMethod)
	require.Equal(t, 2*time.Second, first.cfg.WalletSyncRetryInterval)
	require.Equal(t, first.cfg.WalletSyncRetryInterval,
		second.cfg.WalletSyncRetryInterval)
	require.Equal(t, uint32(12), first.cfg.RecoveryWindow)
	require.Equal(t, first.cfg.RecoveryWindow, second.cfg.RecoveryWindow)
	require.Equal(t, 3*time.Minute, first.cfg.AutoLockDuration)
	require.Equal(t, first.cfg.AutoLockDuration, second.cfg.AutoLockDuration)
	require.Equal(t, uint32(50), first.cfg.MaxCFilterItems)
	require.Equal(t, first.cfg.MaxCFilterItems, second.cfg.MaxCFilterItems)
	require.NotEqual(t, first.cfg.ChainParams.Name,
		second.cfg.ChainParams.Name)
}

// TestManagerCreateSuccess verifies that a wallet can be successfully created
// in various modes. It checks that the Manager correctly initializes the
// wallet structure and registers it for tracking.
func TestManagerCreateSuccess(t *testing.T) {
	t.Parallel()

	// Pre-calculate common setup values to be used in multiple test cases.
	// This ensures we have valid cryptographic material ready for import
	// scenarios.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	// Create an account XPub for ModeShell testing.
	// Derive account key: m/44'/0'/0'
	acctKey, err := rootKey.Derive(hdkeychain.HardenedKeyStart + 44)
	require.NoError(t, err)
	acctKey, err = acctKey.Derive(hdkeychain.HardenedKeyStart + 0)
	require.NoError(t, err)
	acctKey, err = acctKey.Derive(hdkeychain.HardenedKeyStart + 0)
	require.NoError(t, err)
	acctXPub, err := acctKey.Neuter()
	require.NoError(t, err)

	// Arrange: Define test cases for different creation modes.
	tests := []struct {
		name   string
		params CreateWalletParams
	}{

		{
			name: "ModeGenSeed",
			params: CreateWalletParams{
				Mode:              ModeGenSeed,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeImportSeed",
			params: CreateWalletParams{
				Mode:              ModeImportSeed,
				Seed:              seed,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeImportExtKey",
			params: CreateWalletParams{
				Mode:              ModeImportExtKey,
				RootKey:           rootKey,
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			},
		},
		{
			name: "ModeShell",
			params: CreateWalletParams{
				Mode: ModeShell,
				InitialAccounts: []ImportAccountParams{{
					XPub:                 acctXPub,
					MasterKeyFingerprint: 0,
					Name:                 "test-shell-account",
					AddrType:             waddrmgr.NestedWitnessPubKey,
				}},
				WatchOnly: true,
				Birthday:  time.Now(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := testKVDBManager(t)

			// Act: Attach the durable identity to the mode-specific request and
			// create it through the Manager-owned runtime policy.
			params := tc.params
			params.Name = testWalletName
			params.PubPassphrase = []byte("public")
			w, err := m.Create(params)

			// Verify that the wallet was created successfully and returned
			// without error.
			require.NoError(t, err)
			require.NotNil(t, w)
			require.Zero(t, w.ID())

			// Verify internal state: Ensure the manager is tracking the
			// newly created wallet in its internal map, keyed by the
			// durable request name.
			m.RLock()
			loadedW, ok := m.wallets[testWalletName]
			m.RUnlock()
			require.True(t, ok)
			require.Same(t, w, loadedW)

			// If ModeShell, verify account was imported.
			if tc.params.Mode == ModeShell {
				info, err := w.cache.GetAccount(
					t.Context(), db.GetAccountQuery{
						WalletID: w.id,
						Scope: db.KeyScope(
							waddrmgr.KeyScopeBIP0049Plus,
						),
						Name: &tc.params.InitialAccounts[0].Name,
					},
				)
				require.NoError(t, err)
				require.Equal(
					t, tc.params.InitialAccounts[0].Name,
					info.AccountName,
				)
			}
		})
	}
}

// TestCreateWalletParamsPolicy verifies the complete creation-mode matrix and
// proves every rejected combination fails before backend creation.
func TestCreateWalletParamsPolicy(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)
	rootXPub, err := rootKey.Neuter()
	require.NoError(t, err)

	accountKey, err := rootKey.Derive(hdkeychain.HardenedKeyStart + 44)
	require.NoError(t, err)
	accountKey, err = accountKey.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)
	accountKey, err = accountKey.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)
	accountXPub, err := accountKey.Neuter()
	require.NoError(t, err)

	initialXPub := []ImportAccountParams{
		{
			XPub:     accountXPub,
			AddrType: waddrmgr.WitnessPubKey,
		},
	}
	initialXPrv := []ImportAccountParams{{XPub: rootKey}}
	initialNil := []ImportAccountParams{{}}

	tests := []struct {
		name       string
		params     CreateWalletParams
		valid      bool
		wantErrMsg string
	}{
		{
			name:   "generated seed spendable",
			params: CreateWalletParams{Mode: ModeGenSeed},
			valid:  true,
		},
		{
			name:   "imported seed spendable",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed},
			valid:  true,
		},
		{
			name: "private root spendable",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootKey},
			valid: true,
		},
		{
			name: "watch-only shell with XPub",
			params: CreateWalletParams{Mode: ModeShell, WatchOnly: true,
				InitialAccounts: initialXPub},
			valid: true,
		},
		{
			name:   "unknown mode",
			params: CreateWalletParams{Mode: ModeUnknown},
		},
		{
			name:   "generated seed watch-only",
			params: CreateWalletParams{Mode: ModeGenSeed, WatchOnly: true},
		},
		{
			name:   "generated seed with explicit seed",
			params: CreateWalletParams{Mode: ModeGenSeed, Seed: seed},
		},
		{
			name:   "generated seed with root key",
			params: CreateWalletParams{Mode: ModeGenSeed, RootKey: rootKey},
		},
		{
			name: "generated seed with initial account",
			params: CreateWalletParams{Mode: ModeGenSeed,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "imported seed watch-only",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed,
				WatchOnly: true},
		},
		{
			name:   "imported seed missing seed",
			params: CreateWalletParams{Mode: ModeImportSeed},
		},
		{
			name: "imported seed with root key",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed,
				RootKey: rootKey},
		},
		{
			name: "imported seed with initial account",
			params: CreateWalletParams{Mode: ModeImportSeed, Seed: seed,
				InitialAccounts: initialXPub,
			},
		},
		{
			name: "private root watch-only",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootKey, WatchOnly: true},
		},
		{
			name:   "extended root missing key",
			params: CreateWalletParams{Mode: ModeImportExtKey},
		},
		{
			name: "XPub root spendable",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootXPub},
		},
		{
			name: "XPub root watch-only",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootXPub, WatchOnly: true},
		},
		{
			name: "extended root with seed",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey: rootKey, Seed: seed},
		},
		{
			name: "extended root with initial account",
			params: CreateWalletParams{Mode: ModeImportExtKey,
				RootKey:         rootKey,
				InitialAccounts: initialXPub,
			},
		},
		{
			name:   "spendable shell",
			params: CreateWalletParams{Mode: ModeShell},
		},
		{
			name: "shell with seed",
			params: CreateWalletParams{Mode: ModeShell, Seed: seed,
				WatchOnly: true},
		},
		{
			name: "shell with root key",
			params: CreateWalletParams{Mode: ModeShell, RootKey: rootKey,
				WatchOnly: true},
		},
		{
			name: "shell with nil account key",
			params: CreateWalletParams{Mode: ModeShell, WatchOnly: true,
				InitialAccounts: initialNil,
			},
			wantErrMsg: "needs XPub",
		},
		{
			name: "shell with private account key",
			params: CreateWalletParams{Mode: ModeShell, WatchOnly: true,
				InitialAccounts: initialXPrv,
			},
			wantErrMsg: "needs XPub, not XPrv",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Install a strict backend expectation only when the
			// input is valid enough to reach durable creation. Invalid cases
			// intentionally leave the mock with no accepted calls.
			backend := &managerBackendMock{}
			params := tc.params
			params.Name = testWalletName

			if tc.valid {
				backend.On(
					"create", mock.Anything, params,
					mock.Anything,
				).Return(nil, errManagerBackendCreate).Once()
			}

			m := &Manager{
				wallets: make(map[string]*Wallet),
				backend: backend,
				config: ManagerConfig{
					ChainSource: &bwmock.Chain{},
					ChainParams: chainParams,
				},
			}

			m.started.Store(true)

			// Act: Ask Manager to create from the selected parameter shape,
			// allowing validation to decide whether backend mutation begins.
			wallet, err := m.Create(params)

			// Assert: Valid parameters reach exactly one expected backend
			// call; invalid parameters stop at validation with no mock call.
			require.Nil(t, wallet)

			if tc.valid {
				require.ErrorIs(t, err, errManagerBackendCreate)
			} else {
				require.ErrorIs(t, err, ErrWalletParams)

				if tc.wantErrMsg != "" {
					require.ErrorContains(t, err, tc.wantErrMsg)
				}
			}

			backend.AssertExpectations(t)
		})
	}
}

var errManagerBackendCreate = errors.New("backend create called")

// managerBackendMock is the strict Manager storage-boundary test double.
type managerBackendMock struct {
	mock.Mock
}

// managerBackendMock implements managerBackend.
var _ managerBackend = (*managerBackendMock)(nil)

// listWallets returns the durable data configured by the current test.
func (b *managerBackendMock) listWallets(
	ctx context.Context) ([]*walletData, error) {

	args := b.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	//nolint:forcetypeassert // The strict expectation owns this return type.
	return args.Get(0).([]*walletData), args.Error(1)
}

// create returns the storage result configured by the current test.
func (b *managerBackendMock) create(ctx context.Context,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) (
	*walletData, error) {

	args := b.Called(ctx, params, rootKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	//nolint:forcetypeassert // The strict expectation owns this return type.
	return args.Get(0).(*walletData), args.Error(1)
}

// close returns the configured backend ownership-release result.
func (b *managerBackendMock) close() error {
	args := b.Called()
	return args.Error(0)
}

// newManagerLifecycleTest supplies strict backend and chain dependencies;
// fixture cleanup joins runtime work before verifying their expected calls.
func newManagerLifecycleTest(t *testing.T,
	backend *managerBackendMock) *Manager {

	t.Helper()

	chain := &bwmock.Chain{}
	manager := &Manager{
		wallets: make(map[string]*Wallet),
		backend: backend,
		config: ManagerConfig{
			ChainSource: chain,
			ChainParams: chainParams,
		},
	}

	// LIFO cleanup keeps the mocked dependencies alive until shutdown joins.
	t.Cleanup(func() {
		backend.AssertExpectations(t)
		chain.AssertExpectations(t)
	})
	t.Cleanup(func() {
		_ = manager.Stop()
	})

	return manager
}

// TestManagerStartStopPublishesStableSet verifies only the admitted Start
// returns the complete ordered set, without rebuilding an active runtime.
func TestManagerStartStopPublishesStableSet(t *testing.T) {
	t.Parallel()

	// Arrange: Hold discovery to exercise overlapping Start admission, then
	// use real Wallet startup dependencies to verify ordered publication.
	entered := make(chan struct{})
	release := make(chan struct{})

	data := make([]*walletData, 0, 2)
	for i, name := range []string{"first", "second"} {
		_, deps := createTestWalletWithMocks(t)
		id := uint32(i + 1)

		deps.store.On("GetWallet", mock.Anything, name).Return(
			&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
		).Once()
		deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
			WalletID: id,
		}).Return([]db.AccountInfo{}, nil).Once()
		deps.store.On("DeleteExpiredLeases", mock.Anything, id).
			Return(nil).Once()
		deps.vault.On("Lock").Return().Once()
		data = append(data, &walletData{
			id:    id,
			name:  name,
			store: deps.store,
			vault: deps.vault,
		})
	}

	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return(data, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	chain, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chain.On("IsCurrent").Return(false).Maybe()

	// Carry both results so rejected calls cannot leak partially built sets.
	type startOutcome struct {
		wallets []*Wallet
		err     error
	}

	result := make(chan startOutcome, 1)

	// Act: Attempt another Start during discovery and after publication.
	// Only the first call owns startup; neither rejected call may list again.
	go func() {
		wallets, err := manager.Start(t.Context())
		result <- startOutcome{
			wallets: wallets,
			err:     err,
		}
	}()

	<-entered

	overlapping, overlapErr := manager.Start(t.Context())

	close(release)

	first := <-result
	repeated, repeatErr := manager.Start(t.Context())

	// Assert: Rejections return no pointers, while the admitted call exposes
	// every durable Wallet in the backend's stable identifier order. The
	// repeated-start diagnostic explains the rejection to callers.
	require.ErrorIs(t, overlapErr, ErrStateForbidden)
	require.Nil(t, overlapping)
	require.ErrorIs(t, repeatErr, ErrStateForbidden)
	require.ErrorContains(t, repeatErr, "already started")
	require.Nil(t, repeated)
	require.NoError(t, first.err)
	require.Len(t, first.wallets, 2)

	for i, w := range first.wallets {
		require.Equal(t, uint32(i+1), w.ID())
	}
}

// TestManagerStartFailureCleansPartialSet prevents another Start from
// observing success while a failed attempt still owns partial runtime cleanup.
func TestManagerStartFailureCleansPartialSet(t *testing.T) {
	t.Parallel()

	// Arrange: The second Wallet fails its birthday read. Hold the first
	// Wallet's real vault cleanup so another Start must reject until the
	// admitted call finishes cleaning up its partially started set.
	_, firstDeps := createTestWalletWithMocks(t)
	_, secondDeps := createTestWalletWithMocks(t)
	startErr := errors.New("birthday unavailable")

	firstDeps.store.On("GetWallet", mock.Anything, "first").Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
	).Once()
	firstDeps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 1,
	}).Return([]db.AccountInfo{}, nil).Once()
	firstDeps.store.On("DeleteExpiredLeases", mock.Anything, uint32(1)).
		Return(nil).Once()
	secondDeps.store.On("GetWallet", mock.Anything, "second").
		Return(nil, startErr).Once()

	cleanupEntered := make(chan struct{})
	releaseCleanup := make(chan struct{})
	firstDeps.vault.On("Lock").Run(func(mock.Arguments) {
		close(cleanupEntered)
		<-releaseCleanup
	}).Return().Once()

	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{
		{
			id:    1,
			name:  "first",
			store: firstDeps.store,
			vault: firstDeps.vault,
		},
		{
			id:    2,
			name:  "second",
			store: secondDeps.store,
			vault: secondDeps.vault,
		},
	}, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	chain, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chain.On("IsCurrent").Return(false).Maybe()

	// Preserve both return values to detect any partial Wallet publication
	// alongside the primary startup failure.
	type startOutcome struct {
		wallets []*Wallet
		err     error
	}

	firstResult := make(chan startOutcome, 1)

	// Act: Reject another Start while the original attempt is held in
	// cleanup, then collect its failure and check terminal admission.
	go func() {
		wallets, err := manager.Start(t.Context())
		firstResult <- startOutcome{
			wallets: wallets,
			err:     err,
		}
	}()

	<-cleanupEntered

	second, secondErr := manager.Start(t.Context())
	select {
	case result := <-firstResult:
		close(releaseCleanup)
		t.Fatalf("Start returned before cleanup completed: %v", result.err)
	default:
	}

	close(releaseCleanup)

	first := <-firstResult
	terminalWallets, terminalErr := manager.Start(t.Context())

	// Assert: No partial pointers escape either call. The admitted call
	// returns its primary failure after storage closes; a later Start
	// cannot reuse the failed Manager.
	require.Nil(t, second)
	require.ErrorIs(t, secondErr, ErrStateForbidden)
	require.Nil(t, first.wallets)
	require.ErrorIs(t, first.err, startErr)
	require.Nil(t, terminalWallets)
	require.ErrorIs(t, terminalErr, ErrManagerStopped)

	w, err := manager.Create(CreateWalletParams{})
	require.Nil(t, w)
	require.ErrorIs(t, err, ErrManagerStopped)
}

// TestManagerStartCancellationCleansUp verifies the caller's cancellation
// reaches discovery and its failure returns only after storage cleanup.
func TestManagerStartCancellationCleansUp(t *testing.T) {
	t.Parallel()

	// Arrange: Discovery waits on the supplied context. The close callback
	// signals the cleanup boundary that must precede the caller's result.
	entered := make(chan struct{})
	closed := make(chan struct{})
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Run(func(args mock.Arguments) {
		close(entered)
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			t.Error("discovery requires a context")

			return
		}

		<-ctx.Done()
	}).Return(nil, context.Canceled).Once()
	backend.On("close").Run(func(mock.Arguments) {
		close(closed)
	}).Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	result := make(chan error, 1)

	// Act: Cancel only after discovery has begun, exercising cancellation
	// of accepted work rather than a request rejected before admission.
	go func() {
		_, err := manager.Start(ctx)
		result <- err
	}()

	<-entered
	cancel()

	err := <-result

	// Assert: The caller receives cancellation after synchronous cleanup,
	// with no detached attempt left to hold the backend open.
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-closed:
	default:
		t.Fatal("Start returned before closing storage")
	}
}

// TestManagerStartCanceledBeforeAdmission verifies canceled startup leaves
// constructor-owned resources available for a later live-context Start.
func TestManagerStartCanceledBeforeAdmission(t *testing.T) {
	t.Parallel()

	// Arrange: Only the later live-context Start may discover Wallets. The
	// fixture closes storage and verifies both strict expectations afterward.
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{}, nil).Once()
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Reject cancellation before admission, then start the same Manager
	// with a live context to prove the rejected call left it usable.
	canceledWallets, canceledErr := manager.Start(ctx)
	wallets, err := manager.Start(t.Context())

	// Assert: The canceled call exposes no handles, while subsequent startup
	// returns the empty durable set without repeating discovery.
	require.Nil(t, canceledWallets)
	require.ErrorIs(t, canceledErr, context.Canceled)
	require.NoError(t, err)
	require.Empty(t, wallets)
}

// TestManagerStopWaitsForCleanup verifies shutdown blocks through backend
// closure, and a repeated Stop has no remaining work.
func TestManagerStopWaitsForCleanup(t *testing.T) {
	t.Parallel()

	// Arrange: Hold closure of the database opened by construction, before
	// any Start has claimed the guard. Shutdown must still reject startup.
	entered := make(chan struct{})
	release := make(chan struct{})
	closeErr := errors.New("backend close")
	backend := &managerBackendMock{}
	backend.On("close").Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return(closeErr).Once()
	manager := newManagerLifecycleTest(t, backend)

	first := make(chan error, 1)
	second := make(chan error, 1)
	callingStop := make(chan struct{})

	// Act: Hold shutdown, reject Start, and overlap another
	// Stop. Both Stop callers check the shared completion boundary directly.
	go func() {
		err := manager.Stop()

		select {
		case <-release:
		default:
			t.Error("Stop returned before cleanup was released")
		}

		first <- err
	}()

	<-entered

	wallets, startErr := manager.Start(t.Context())
	go func() {
		close(callingStop)

		err := manager.Stop()

		select {
		case <-release:
		default:
			t.Error("concurrent Stop returned before cleanup was released")
		}

		second <- err
	}()

	<-callingStop
	close(release)

	firstErr := <-first
	secondErr := <-second
	repeatedErr := manager.Stop()

	// Assert: Only the call doing cleanup returns its failure. Neither
	// overlapping nor repeated calls create detached work or replay errors.
	require.Nil(t, wallets)
	require.ErrorIs(t, startErr, ErrStateForbidden)
	require.ErrorIs(t, firstErr, closeErr)
	require.NoError(t, secondErr)
	require.NoError(t, repeatedErr)
}

// TestManagerStopWaitsForStart verifies Stop lets synchronous startup settle
// before closing its storage, and cannot return while that work is still held.
func TestManagerStopWaitsForStart(t *testing.T) {
	t.Parallel()

	// Arrange: Discovery holds the Manager's accepted startup work. Closure
	// checks that this dependency has settled before it releases storage.
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Run(func(mock.Arguments) {
		close(entered)
		<-release
	}).Return([]*walletData{}, nil).Once()
	backend.On("close").Run(func(mock.Arguments) {
		select {
		case <-release:
		default:
			t.Error("backend closed during discovery")
		}
	}).Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	started := make(chan error, 1)
	stopped := make(chan error, 1)
	callingStop := make(chan struct{})

	// Act: Queue Stop behind accepted discovery, then let startup settle.
	// After shutdown, attempt Start again to check terminal admission.
	go func() {
		_, err := manager.Start(t.Context())
		started <- err
	}()

	<-entered

	go func() {
		close(callingStop)

		err := manager.Stop()

		select {
		case <-release:
		default:
			t.Error("Stop returned during discovery")
		}

		stopped <- err
	}()

	<-callingStop

	close(release)

	startErr := <-started
	stopErr := <-stopped
	terminalWallets, terminalErr := manager.Start(t.Context())

	// Assert: The admitted Start finishes normally; Stop waits and cleans up
	// exactly once. Terminal startup cannot publish another runtime set.
	require.NoError(t, startErr)
	require.NoError(t, stopErr)
	require.Nil(t, terminalWallets)
	require.ErrorIs(t, terminalErr, ErrManagerStopped)
}

// TestManagerCreateBeforeStart verifies creation rejects an inactive Manager
// before request validation or durable storage access.
func TestManagerCreateBeforeStart(t *testing.T) {
	t.Parallel()

	// Arrange: Leave the Manager unstarted and expect only fixture cleanup.
	// An empty request distinguishes lifecycle admission from validation.
	backend := &managerBackendMock{}
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)

	// Act: Submit creation before any Start has admitted runtime work.
	w, err := manager.Create(CreateWalletParams{})

	// Assert: No Wallet escapes and the lifecycle sentinel takes precedence
	// over request errors; unexpected backend access fails the strict mock.
	require.Nil(t, w)
	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestManagerCreateAfterStop verifies creation rejects a terminal Manager
// without accessing its closed storage or validating the request.
func TestManagerCreateAfterStop(t *testing.T) {
	t.Parallel()

	// Arrange: Complete terminal shutdown before attempting creation. The
	// strict close expectation also covers the fixture's later no-op Stop.
	backend := &managerBackendMock{}
	backend.On("close").Return(nil).Once()
	manager := newManagerLifecycleTest(t, backend)
	require.NoError(t, manager.Stop())

	// Act: Submit an empty request after shutdown has released storage.
	w, err := manager.Create(CreateWalletParams{})

	// Assert: Terminal admission returns no Wallet and preserves the stopped
	// identity instead of reaching validation or closed backend dependencies.
	require.Nil(t, w)
	require.ErrorIs(t, err, ErrManagerStopped)
}

// managerLifecycleCreateParams returns a rootless request so lifecycle tests
// exercise admission and teardown without unrelated random key derivation.
func managerLifecycleCreateParams(name string) CreateWalletParams {
	return CreateWalletParams{
		Name:              name,
		Mode:              ModeShell,
		WatchOnly:         true,
		PrivatePassphrase: []byte("private"),
	}
}

// TestManagerCreateRejectsInvalidInitialAccounts verifies bad import inputs
// cannot persist a candidate or stop an existing Wallet.
func TestManagerCreateRejectsInvalidInitialAccounts(t *testing.T) {
	t.Parallel()

	// Arrange: Use a valid account key and change only its network or address
	// type, so each request reaches the import checks missing from preflight.
	key, _ := importAccountTestKey(t, 44)
	wrongNetwork, err := key.CloneWithVersion(
		chaincfg.MainNetParams.HDPublicKeyID[:],
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      *hdkeychain.ExtendedKey
		addrType waddrmgr.AddressType
	}{
		{
			name:     "wrong network",
			key:      wrongNetwork,
			addrType: waddrmgr.WitnessPubKey,
		},
		{
			name:     "unsupported address type",
			key:      key,
			addrType: waddrmgr.PubKeyHash,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Keep one Wallet running in real storage to detect
			// both unwanted shutdown and a leftover candidate row.
			m := testSQLiteManager(t)
			existing, err := m.Create(
				managerLifecycleCreateParams("existing"),
			)
			require.NoError(t, err)

			params := managerLifecycleCreateParams("candidate")
			params.InitialAccounts = []ImportAccountParams{
				{
					Name:     "initial-account",
					XPub:     tc.key,
					AddrType: tc.addrType,
				},
			}

			// Act: Request another Wallet with invalid initial account
			// input while the first Wallet is still in use.
			candidate, err := m.Create(params)

			// Assert: The request fails without a handle. A public read
			// still works, and corrected input can use the same Wallet
			// name, proving no durable candidate was left behind.
			require.Nil(t, candidate)
			require.ErrorIs(t, err, ErrWalletParams)

			_, err = existing.ListAccounts(t.Context())
			require.NoError(t, err)

			params.InitialAccounts[0].XPub = key
			params.InitialAccounts[0].AddrType = waddrmgr.WitnessPubKey
			candidate, err = m.Create(params)
			require.NoError(t, err)
			require.NotNil(t, candidate)
		})
	}
}

// TestManagerCreateLifecycleSerializesStop verifies accepted creation finishes
// startup before Stop can close storage, and real chain work drains first.
func TestManagerCreateLifecycleSerializesStop(t *testing.T) {
	t.Parallel()

	// Arrange: Block the candidate's runtime read and its chain worker at
	// separate dependencies. Storage closure checks that both have returned.
	_, deps := createTestWalletWithMocks(t)
	startupEntered := make(chan struct{})
	releaseStartup := make(chan struct{})
	chainEntered := make(chan struct{})
	releaseChain := make(chan struct{})

	deps.store.On("GetWallet", mock.Anything, "created").
		Run(func(mock.Arguments) {
			close(startupEntered)
			<-releaseStartup
		}).Return(&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil).Once()
	deps.store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 1,
	}).Return([]db.AccountInfo{}, nil).Once()
	deps.store.On("DeleteExpiredLeases", mock.Anything, uint32(1)).
		Return(nil).Once()
	vaultLock := deps.vault.On("Lock").Return().Once()

	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{}, nil).Once()

	params := managerLifecycleCreateParams("created")
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(&walletData{
			id:    1,
			name:  params.Name,
			store: deps.store,
			vault: deps.vault,
		}, nil).Once()
	// Vault locking follows worker joins, so storage must close after it.
	backend.On("close").Return(nil).Once().NotBefore(vaultLock)

	manager := newManagerLifecycleTest(t, backend)
	chain, ok := manager.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chain.On("IsCurrent").Run(func(mock.Arguments) {
		close(chainEntered)
		<-releaseChain
	}).Return(false).Once()

	_, err := manager.Start(t.Context())
	require.NoError(t, err)

	type createOutcome struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createOutcome, 1)
	stopped := make(chan error, 1)

	// Act: Accept creation, queue Stop behind its lock, and advance startup
	// into a real chain call before allowing that worker to drain.
	go func() {
		w, err := manager.Create(params)
		created <- createOutcome{
			wallet: w,
			err:    err,
		}
	}()

	<-startupEntered

	go func() { stopped <- manager.Stop() }()

	close(releaseStartup)

	outcome := <-created

	<-chainEntered
	close(releaseChain)

	stopErr := <-stopped

	// Assert: Create publishes a started pointer, whose owned worker joins
	// before the one storage close and whose retained API is then terminal.
	require.NoError(t, outcome.err)
	require.NotNil(t, outcome.wallet)
	require.NoError(t, stopErr)
	require.ErrorIs(t, outcome.wallet.Lock(t.Context()), ErrWalletStopped)
}

// TestManagerCreateLifecycleStartFailureStopsManager verifies a committed
// candidate's startup failure preserves its primary error through teardown.
func TestManagerCreateLifecycleStartFailureStopsManager(t *testing.T) {
	t.Parallel()

	// Arrange: Commit a candidate whose birthday read fails, with an unrelated
	// backend close failure to distinguish creation from the cleanup result.
	_, deps := createTestWalletWithMocks(t)
	createErr := errors.New("candidate birthday")
	closeErr := errors.New("backend close")

	deps.store.On("GetWallet", mock.Anything, "candidate").
		Return(nil, createErr).Once()

	params := managerLifecycleCreateParams("candidate")
	backend := &managerBackendMock{}
	backend.On("listWallets", mock.Anything).Return([]*walletData{}, nil).Once()
	backend.On("create", mock.Anything, params, mock.Anything).
		Return(&walletData{
			id:    1,
			name:  params.Name,
			store: deps.store,
			vault: deps.vault,
		}, nil).Once()
	// Hold storage closure so returning a primary Create error cannot hide
	// unfinished terminal cleanup. A concurrent Stop must join that cleanup.
	closing := make(chan struct{})
	release := make(chan struct{})
	backend.On("close").Run(func(mock.Arguments) {
		close(closing)
		<-release
	}).Return(closeErr).Once()

	manager := newManagerLifecycleTest(t, backend)
	_, err := manager.Start(t.Context())
	require.NoError(t, err)

	// Carry both Create results across the blocked cleanup boundary so an
	// inactive candidate cannot escape even when startup reports an error.
	type createOutcome struct {
		wallet *Wallet
		err    error
	}

	created := make(chan createOutcome, 1)
	stopped := make(chan error, 1)

	// Act: Fail post-commit startup, join its held cleanup through Stop, and
	// release storage closure only after checking Create has not returned.
	go func() {
		w, err := manager.Create(params)
		created <- createOutcome{
			wallet: w,
			err:    err,
		}
	}()

	<-closing

	go func() { stopped <- manager.Stop() }()

	select {
	case result := <-created:
		close(release)
		t.Fatalf("Create returned before cleanup completed: %v", result.err)
	default:
	}

	close(release)

	outcome := <-created
	stopErr := <-stopped

	// Assert: No candidate escapes and Create preserves the primary failure
	// and cleanup error only after teardown finishes. Stop has no remaining
	// work and does not replay that earlier call's errors.
	require.Nil(t, outcome.wallet)
	require.ErrorIs(t, outcome.err, createErr)
	require.ErrorIs(t, outcome.err, closeErr)
	require.NoError(t, stopErr)
}

// TestSQLManagerBackendListsWallets verifies ordered complete listing and
// all-or-nothing iterator failures.
func TestSQLManagerBackendListsWallets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rows      []db.WalletInfo
		iterErr   error
		wantIDs   []uint32
		wantNames []string
	}{
		{
			name:      "empty store",
			wantIDs:   []uint32{},
			wantNames: []string{},
		},
		{
			name: "ordered store rows",
			rows: []db.WalletInfo{
				{
					ID:   4,
					Name: "first",
				},
				{
					ID:   9,
					Name: "second",
				},
			},
			wantIDs:   []uint32{4, 9},
			wantNames: []string{"first", "second"},
		},
		{
			name:    "iterator failure",
			iterErr: errDBMock,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Yield ordered rows and an optional terminal error from
			// the Store iterator used by the backend discovery boundary.
			store := &walletmock.Store{}
			sequence := iter.Seq2[db.WalletInfo, error](func(
				yield func(db.WalletInfo, error) bool) {

				for _, row := range test.rows {
					if !yield(row, nil) {
						return
					}
				}

				if test.iterErr != nil {
					yield(db.WalletInfo{}, test.iterErr)
				}
			})
			store.On(
				"IterWallets", mock.Anything, mock.Anything,
			).Return(sequence, nil).Once()

			backend := &sqlManagerBackend{store: store}

			// Act: Resolve the complete startup listing through the SQL
			// backend boundary rather than calling the Store directly.
			wallets, err := backend.listWallets(t.Context())

			// Assert: Iterator failure prevents a partial handoff; otherwise
			// the non-nil result preserves each durable ID and name exactly.
			if test.iterErr != nil {
				require.ErrorIs(t, err, test.iterErr)
				require.Nil(t, wallets)
			} else {
				require.NoError(t, err)
				require.NotNil(t, wallets)

				ids := make([]uint32, 0, len(wallets))
				names := make([]string, 0, len(wallets))

				for _, wallet := range wallets {
					ids = append(ids, wallet.id)
					names = append(names, wallet.name)
				}

				require.Equal(t, test.wantIDs, ids)
				require.Equal(t, test.wantNames, names)
			}

			store.AssertExpectations(t)
		})
	}
}

// TestKVDBManagerBackendListsZeroOrOneWallet verifies legacy startup listing
// treats an uninitialized database as empty and an initialized database as the
// backend's sole anonymous Wallet, without inventing another identity.
func TestKVDBManagerBackendListsZeroOrOneWallet(t *testing.T) {
	t.Parallel()

	t.Run("empty database", func(t *testing.T) {
		t.Parallel()

		// Arrange: Open a fresh legacy database whose address and transaction
		// namespaces have never been created.
		manager := testKVDBManager(t)
		backend, ok := manager.backend.(*kvdbManagerBackend)
		require.True(t, ok)

		// Act: List startup data through the backend's zero-or-one boundary.
		wallets, err := backend.listWallets(t.Context())

		// Assert: Absence is a successful, initialized empty result rather
		// than an attempted load or a missing-Wallet error.
		require.NoError(t, err)
		require.NotNil(t, wallets)
		require.Empty(t, wallets)
	})

	t.Run("initialized database", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create and close the sole legacy Wallet with a non-empty
		// public passphrase, then configure a new Manager with the same bytes.
		// Mutating the caller slice after construction proves listing uses the
		// Manager's immutable copy through the existing load path.
		dbPath := testKVDBPath(t)
		pubPassphrase := []byte("startup-public")
		creator := testKVDBManagerAt(t, dbPath)
		_, err := creator.Create(CreateWalletParams{
			Name:              testWalletName,
			Mode:              ModeShell,
			WatchOnly:         true,
			PubPassphrase:     pubPassphrase,
			PrivatePassphrase: []byte("private"),
			Birthday:          time.Now(),
		})
		require.NoError(t, err)
		require.NoError(t, creator.Stop())

		manager, err := NewManager(t.Context(), ManagerConfig{
			Backend:           DBBackendKVDB,
			DataSource:        dbPath,
			ChainParams:       chainParams,
			ChainSource:       &bwmock.Chain{},
			KVDBPubPassphrase: pubPassphrase,
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = manager.Stop()
		})

		pubPassphrase[0] ^= 0xff

		backend, ok := manager.backend.(*kvdbManagerBackend)
		require.True(t, ok)

		// Act: List the occupied database through the backend boundary.
		wallets, err := backend.listWallets(t.Context())

		// Assert: The existing loader returns one Wallet under kvdb's absent
		// durable name rather than inventing an alias or a second identity.
		require.NoError(t, err)
		require.Len(t, wallets, 1)
		require.Empty(t, wallets[0].name)
	})
}

// TestManagerCreateRejectsMissingIdentityBeforeAssembly verifies Create
// rejects an absent durable key before Store work.
func TestManagerCreateRejectsMissingIdentityBeforeAssembly(t *testing.T) {
	t.Parallel()

	// Arrange: Give Create a strict Store mock with no expectations. The
	// otherwise empty request makes the missing durable identity the only
	// relevant input.
	store := &walletmock.Store{}
	manager := testSQLManager(t, store)

	// Act: Invoke Create without the durable identity required for cache and
	// Store selection.
	w, err := manager.Create(CreateWalletParams{})

	// Assert: The identity error is primary, no partial Wallet escapes, and
	// the strict Store confirms validation happened before durable work or
	// Wallet assembly.
	require.ErrorIs(t, err, ErrMissingParam)
	require.ErrorContains(t, err, "Name")
	require.Nil(t, w)
}

// TestManagerString verifies that the String representation of the Manager
// correctly lists the tracked wallets in alphabetical order.
func TestManagerString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(*Manager)
		expected string
	}{
		{
			name:     "empty",
			setup:    func(m *Manager) {},
			expected: "active_wallets=[]",
		},
		{
			name: "multiple sorted",
			setup: func(m *Manager) {
				m.wallets["wallet-b"] = &Wallet{}
				m.wallets["wallet-a"] = &Wallet{}
			},
			expected: "active_wallets=[wallet-a wallet-b]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := testKVDBManager(t)
			tc.setup(m)
			require.Equal(t, tc.expected, m.String())
		})
	}
}

// TestManagerDeriveFromSeed verifies the internal helper method
// deriveFromSeed, checking that it correctly derives a master private key
// from a seed and validates inputs.
func TestManagerDeriveFromSeed(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		require.NoError(t, err)

		key, err := m.deriveFromSeed(seed)

		// Verify we got a valid private extended key.
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})

	t.Run("Empty Seed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveFromSeed(nil)
		require.ErrorIs(t, err, ErrWalletParams)
		require.ErrorContains(t, err, "seed is required")
		require.Nil(t, key)
	})

	t.Run("Invalid Seed Length", func(t *testing.T) {
		t.Parallel()

		// Providing a seed that is too short for hdkeychain.NewMaster.
		key, err := m.deriveFromSeed([]byte{0x01})
		require.ErrorContains(t, err, "failed to derive master key")
		require.Nil(t, key)
	})
}

// TestManagerGenRootKey verifies the internal helper method genRootKey,
// ensuring it generates a random seed and derives a valid master key.
func TestManagerGenRootKey(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)

	// With no configured kvdb path there is no legacy wallet to recover, so
	// genRootKey takes the fresh-generation branch.
	key, err := m.genRootKey()

	// Verify we got a valid private extended key.
	require.NoError(t, err)
	require.NotNil(t, key)
	require.True(t, key.IsPrivate())
}

// TestManagerDeriveRootKey verifies the high-level key derivation logic,
// checking that it correctly dispatches to the appropriate helper based on
// the creation mode.
func TestManagerDeriveRootKey(t *testing.T) {
	t.Parallel()

	m := testKVDBManager(t)

	// ModeShell should return nil/nil because it has no root key.
	t.Run("ModeShell", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(CreateWalletParams{Mode: ModeShell})
		require.NoError(t, err)
		require.Nil(t, key)
	})

	// ModeGenSeed should return a newly generated private key.
	t.Run("ModeGenSeed", func(t *testing.T) {
		t.Parallel()

		key, err := m.deriveRootKey(CreateWalletParams{Mode: ModeGenSeed})
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, key.IsPrivate())
	})
}

// TestManagerKVDBCreateWatchOnlyShell verifies that the legacy kvdb backend
// creates a rootless watch-only wallet with an empty private passphrase,
// preserving the behavior of the legacy watch-only constructor.
func TestManagerKVDBCreateWatchOnlyShell(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:          testWalletName,
		Mode:          ModeShell,
		WatchOnly:     true,
		PubPassphrase: []byte("public"),
		Birthday:      time.Now(),
	}

	w, err := testKVDBManager(t).Create(params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.True(t, w.IsWatchOnly())

	// No root key was supplied, so no master fingerprint is cached. The value
	// is unobservable on a watch-only wallet regardless: it is reported only
	// for derived accounts, which such a wallet cannot have.
	require.Zero(t, w.masterFingerprint)
}

// TestManagerKVDBRejectsSecondCreate verifies the legacy backend enforces its
// one-Wallet limit even when the second request has another runtime name.
func TestManagerKVDBRejectsSecondCreate(t *testing.T) {
	t.Parallel()

	// Arrange: Create the one Wallet the kvdb backend can keep open.
	m := testKVDBManager(t)
	params := CreateWalletParams{
		Name:              "first",
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	first, err := m.Create(params)
	require.NoError(t, err)
	require.NotNil(t, first)

	// Act: Attempt to create a sibling identity through the same Manager.
	params.Name = "second"
	second, err := m.Create(params)

	// Assert: The backend reports its single-Wallet constraint and does not
	// return a second runtime instance.
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "one wallet per database")
	require.Nil(t, second)
}

// TestManagerCreateFailureLeavesManagerReusable verifies that a failed Create
// leaves no durable trace in the Manager: the wallet is not published, the name
// is still free, and the database the Manager opened is released exactly once
// by Stop. The harness relies on this — it registers the Manager before any
// Create so that a failing Create still releases the database it opened.
func TestManagerCreateFailureLeavesManagerReusable(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		manager func(testing.TB) *Manager
	}{
		{
			name:    "kvdb",
			manager: testKVDBManager,
		},
		{
			name:    "sqlite",
			manager: testSQLiteManager,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := tc.manager(t)
			// Arrange + Act: a seed too short for BIP32 fails root
			// derivation, after the Manager has already opened its
			// database.
			seed, err := hdkeychain.GenerateSeed(
				hdkeychain.RecommendedSeedLen,
			)
			require.NoError(t, err)

			w, err := m.Create(CreateWalletParams{
				Name:              testWalletName,
				Mode:              ModeImportSeed,
				Seed:              seed[:hdkeychain.MinSeedBytes-1],
				PubPassphrase:     []byte("public"),
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			})
			require.ErrorIs(t, err, hdkeychain.ErrInvalidSeedLen)
			require.Nil(t, w)

			// Assert: nothing was published, so the name is free and
			// a corrected create succeeds over the same database.
			w, err = m.Create(CreateWalletParams{
				Name:              testWalletName,
				Mode:              ModeImportSeed,
				Seed:              seed,
				PubPassphrase:     []byte("public"),
				PrivatePassphrase: []byte("private"),
				Birthday:          time.Now(),
			})
			require.NoError(t, err)
			require.NotNil(t, w)

			// Stop releases the one database the Manager owns. It is
			// called once, after quiescence.
			require.NoError(t, m.Stop())
		})
	}
}

// TestManagerCreateImportsDeclaredAccount verifies pre-start SQL imports use
// the same declared scope/schema and encoded account number as public imports.
func TestManagerCreateImportsDeclaredAccount(t *testing.T) {
	t.Parallel()

	// Arrange: use generic XPub version bytes with lnd's custom witness scope,
	// requesting SQL chain exclusion through the same pre-start import input.
	m := testSQLiteManager(t)
	key, _ := importAccountTestKey(t, 44)
	scope := waddrmgr.KeyScope{Purpose: 1017, Coin: 0}
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]
	params := managerLifecycleCreateParams("declared-initial")
	params.InitialAccounts = []ImportAccountParams{
		{
			Name:        testAccountName,
			XPub:        key,
			Scope:       &scope,
			AddrSchema:  &schema,
			NoChainSync: true,
		},
	}

	// Act: create the shell with its initial imported account before startup,
	// then inspect the returned account through the started public interface.
	w, err := m.Create(params)
	require.NoError(t, err)
	info, err := w.GetAccount(t.Context(), scope, testAccountName)

	// Assert: initial import retains declared identity and a present-zero
	// fingerprint, effective witness schema and persisted SQL chain exclusion.
	require.NoError(t, err)
	require.True(t, info.IsImported)
	require.True(t, info.NoChainSync)
	require.Equal(t, AccountNumber(0), *info.AccountNumber)
	require.Equal(t, scope, info.KeyScope)
	require.Equal(t, schema, info.AddrSchema)
	require.Equal(t, MasterFingerprint(0), *info.MasterKeyFingerprint)
}

// TestManagerCreateImportsDeclaredKVDBAccount verifies initial kvdb imports
// use the same custom scope, schema and known number as live imports.
func TestManagerCreateImportsDeclaredKVDBAccount(t *testing.T) {
	t.Parallel()

	// Arrange: a generic account XPub declares lnd's custom key-family scope.
	// Its explicit witness schema supplies the missing canonical scope default.
	m := testKVDBManager(t)
	key, _ := importAccountTestKey(t, 84)
	scope := waddrmgr.KeyScope{Purpose: 1017, Coin: 0}
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]
	params := managerLifecycleCreateParams("kvdb-initial")
	params.InitialAccounts = []ImportAccountParams{
		{
			Name:       testAccountName,
			XPub:       key,
			Scope:      &scope,
			AddrSchema: &schema,
		},
	}

	// Act: create and start the Wallet with its declared import before startup.
	w, err := m.Create(params)
	require.NoError(t, err)
	info, err := w.GetAccount(t.Context(), scope, testAccountName)

	// Assert: declaration metadata survives Manager preflight and native kvdb
	// persistence, including account zero and its caller-supplied fingerprint.
	require.NoError(t, err)
	require.True(t, info.IsImported)
	require.Equal(t, AccountNumber(0), *info.AccountNumber)
	require.Equal(t, scope, info.KeyScope)
	require.Equal(t, schema, info.AddrSchema)
	require.Equal(t, MasterFingerprint(0), *info.MasterKeyFingerprint)
}
