// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// InsecurePubPassphrase is the default outer encryption passphrase used
	// for public data (everything but private keys).  Using a non-default
	// public passphrase can prevent an attacker without the public
	// passphrase from discovering all past and future wallet addresses if
	// they gain access to the wallet database.
	//
	// NOTE: at time of writing, public encryption only applies to public
	// data in the waddrmgr namespace.  Transactions are not yet encrypted.
	InsecurePubPassphrase = "public"

	// recoveryBatchSize is the default number of blocks that will be
	// scanned successively by the recovery manager, in the event that the
	// wallet is started in recovery mode.
	recoveryBatchSize = 2000

	// defaultSyncRetryInterval is the default amount of time to wait
	// between re-tries on errors during initial sync.
	defaultSyncRetryInterval = 5 * time.Second
)

var (
	// ErrNotSynced describes an error where an operation cannot complete
	// due wallet being out of sync (and perhaps currently syncing with)
	// the remote chain server.
	ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

	// ErrWalletShuttingDown is an error returned when we attempt to make a
	// request to the wallet but it is in the process of or has already shut
	// down.
	ErrWalletShuttingDown = errors.New("wallet shutting down")

	// ErrUnknownTransaction is returned when an attempt is made to label
	// a transaction that is not known to the wallet.
	ErrUnknownTransaction = errors.New("cannot label transaction not " +
		"known to wallet")

	// ErrTxLabelExists is returned when a transaction already has a label
	// and an attempt has been made to label it without setting overwrite
	// to true.
	ErrTxLabelExists = errors.New("transaction already labelled")

	// ErrNoTx is returned when a transaction can not be found.
	ErrNoTx = errors.New("can not find transaction")

	// ErrTxUnsigned is returned when a transaction is created in the
	// watch-only mode where we can select coins but not sign any inputs.
	ErrTxUnsigned = errors.New("watch-only wallet, transaction not signed")

	// Namespace bucket keys.
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// Coin represents a spendable UTXO which is available for coin selection.
type Coin struct {
	wire.TxOut

	wire.OutPoint
}

// CoinSelectionStrategy is an interface that represents a coin selection
// strategy. A coin selection strategy is responsible for ordering, shuffling or
// filtering a list of coins before they are passed to the coin selection
// algorithm.
type CoinSelectionStrategy interface {
	// ArrangeCoins takes a list of coins and arranges them according to the
	// specified coin selection strategy and fee rate.
	ArrangeCoins(eligible []Coin, feeSatPerKb btcutil.Amount) ([]Coin,
		error)
}

var (
	// CoinSelectionLargest always picks the largest available utxo to add
	// to the transaction next.
	CoinSelectionLargest CoinSelectionStrategy = &LargestFirstCoinSelector{}

	// CoinSelectionRandom randomly selects the next utxo to add to the
	// transaction. This strategy prevents the creation of ever smaller
	// utxos over time.
	CoinSelectionRandom CoinSelectionStrategy = &RandomCoinSelector{}
)

type Wallet struct {
	publicPassphrase []byte

	// Data stores
	db        walletdb.DB
	// store is the new database interface.
	store db.Store

	// The following fields are used to track the wallet's sync state.

	chainClient        chain.Interface
	chainSvr           chain.Interface
	chainClientLock    sync.Mutex
	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex

	newAddrMtx sync.Mutex

	lockedOutpoints    map[wire.OutPoint]struct{}
	lockedOutpointsMtx sync.Mutex

	recovering     atomic.Value
	recoveryWindow uint32

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	rescanAddJob        chan *RescanJob
	rescanBatch         chan *rescanBatch
	rescanNotifications chan interface{} // From chain server
	rescanProgress      chan *RescanProgressMsg
	rescanFinished      chan *RescanFinishedMsg

	// Channel for transaction creation requests.
	createTxRequests chan createTxRequest

	NtfnServer *NotificationServer

	chainParams *chaincfg.Params
	wg          sync.WaitGroup

	started bool
	quit    chan struct{}
	quitMu  sync.Mutex

	// syncRetryInterval is the amount of time to wait between re-tries on
	// errors during initial sync.
	syncRetryInterval time.Duration
}

// ResetLockedOutpoints resets all locked outpoints.
func (w *Wallet) ResetLockedOutpoints() {
	// TODO(yy): implement
}

// ListAllTransactions returns a list of all transactions.
func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// ListAddressTransactions returns a list of all transactions for a set of addresses.
func (w *Wallet) ListAddressTransactions(hash160Map map[string]struct{}) (
	[]btcjson.ListTransactionsResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// SignTransaction signs a transaction.
func (w *Wallet) SignTransaction(tx *wire.MsgTx,
	hashType txscript.SigHashType,
	prevScripts [][]byte,
	inputValues []btcutil.Amount) (*wire.MsgTx, bool, error) {
	// TODO(yy): implement
	return nil, false, nil
}

// NewBlockIdentifierFromHash creates a new block identifier from a hash.
func NewBlockIdentifierFromHash(hash *chainhash.Hash) *BlockIdentifier {
	return &BlockIdentifier{Hash: hash}
}

// NewBlockIdentifierFromHeight creates a new block identifier from a height.
func NewBlockIdentifierFromHeight(height int32) *BlockIdentifier {
	return &BlockIdentifier{Height: height}
}

// ListTransactions returns a list of the most recent transactions.
func (w *Wallet) ListTransactions(skip, count int,
	account string) ([]btcjson.ListTransactionsResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// ListSinceBlock returns a list of transactions that have occurred since a
// given block.
func (w *Wallet) ListSinceBlock(startBlock *chainhash.Hash,
	minconf int32) ([]btcjson.ListTransactionsResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses, sorted by address.
func (w *Wallet) SortedActivePaymentAddresses() []btcutil.Address {
	// TODO(yy): implement
	return nil
}

// LockedOutpoints returns a slice of all locked outpoints.
func (w *Wallet) LockedOutpoints() []wire.OutPoint {
	// TODO(yy): implement
	return nil
}

// AccountBalances returns the balances for a set of accounts.
func (w *Wallet) AccountBalances(keyScope waddrmgr.KeyScope,
	minconf int32) ([]AccountBalanceResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// RecvCategory is the category of a received transaction.
type RecvCategory int

const (
	// RecvCategoryReceive is the category for a regular receive.
	RecvCategoryReceive RecvCategory = iota
	// RecvCategoryGenerate is the category for a coinbase generation.
	RecvCategoryGenerate
)

// TotalReceivedForAddr returns the total received amount for an address.
func (w *Wallet) TotalReceivedForAddr(addr btcutil.Address, minconf int32) (btcutil.Amount, error) {
	// TODO(yy): implement
	return 0, nil
}

// TotalReceivedForAccounts returns the total received amount for a set of accounts.
func (w *Wallet) TotalReceivedForAccounts(keyScope waddrmgr.KeyScope,
	minconf int32) ([]TotalReceivedForAccountsResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// TotalReceivedForAccountsResult is the result of the TotalReceivedForAccounts command.
type TotalReceivedForAccountsResult struct {
	AccountName      string
	TotalReceived    btcutil.Amount
	LastConfirmation int32
}

// AccountBalanceResult is the result of the AccountBalances command.
type AccountBalanceResult struct {
	AccountName    string
	AccountBalance btcutil.Amount
}

// DumpWIFPrivateKey returns the WIF-encoded private key for an address.
func (w *Wallet) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	// TODO(yy): implement
	return "", nil
}

// ID returns the wallet's ID.
func (w *Wallet) ID() uint64 {
	// TODO(yy): implement
	return 0
}

// Name returns the wallet's name.
func (w *Wallet) Name() string {
	// TODO(yy): implement
	return ""
}

// Start starts the goroutines necessary to manage a wallet.
func (w *Wallet) Start() {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		// Restart the wallet goroutines after shutdown finishes.
		w.WaitForShutdown()
		w.quit = make(chan struct{})
	default:
		// Ignore when the wallet is still running.
		if w.started {
			w.quitMu.Unlock()
			return
		}
		w.started = true
	}
	w.quitMu.Unlock()

	w.wg.Add(1)
	go w.txCreator()
}

// SynchronizeRPC associates the wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This method is unstable and will be removed when all syncing logic is moved
// outside of the wallet package.
func (w *Wallet) SynchronizeRPC(chainClient chain.Interface) {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		w.quitMu.Unlock()
		return
	default:
	}
	w.quitMu.Unlock()

	// TODO: Ignoring the new client when one is already set breaks callers
	// who are replacing the client, perhaps after a disconnect.
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClientLock.Unlock()
		return
	}
	w.chainClient = chainClient

	// If the chain client is a NeutrinoClient instance, set a birthday so
	// we don't download all the filters as we go.
	walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
	if err != nil {
		log.Errorf("could not get wallet info: %v", err)
		return
	}
	birthday := walletInfo.Birthday
	switch cc := chainClient.(type) {
	case *chain.NeutrinoClient:
		cc.SetStartTime(birthday)
	case *chain.BitcoindClient:
		cc.SetBirthday(birthday)
	}
	w.chainClientLock.Unlock()

	// TODO: It would be preferable to either run these goroutines
	// separately from the wallet (use wallet mutator functions to
	// make changes from the RPC client) and not have to stop and
	// restart them each time the client disconnects and reconnets.
	w.wg.Add(4)
	go w.handleChainNotifications()
	go w.rescanBatchHandler()
	go w.rescanProgressHandler()
	go w.rescanRPCHandler()
}

// requireChainClient marks that a wallet method can only be completed when the
// consensus RPC server is set.  This function and all functions that call it
// are unstable and will need to be moved when the syncing code is moved out of
// the wallet.
func (w *Wallet) requireChainClient() (chain.Interface, error) {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	if chainClient == nil {
		return nil, errors.New("blockchain RPC is inactive")
	}
	return chainClient, nil
}

// ChainClient returns the optional consensus RPC client associated with the
// wallet.
//
// This function is unstable and will be removed once sync logic is moved out of
// the wallet.
func (w *Wallet) ChainClient() chain.Interface {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	return chainClient
}

// quitChan atomically reads the quit channel.
func (w *Wallet) quitChan() <-chan struct{} {
	w.quitMu.Lock()
	c := w.quit
	w.quitMu.Unlock()
	return c
}

// ShuttingDown returns whether the wallet is currently in the process of
// shutting down or not.
func (w *Wallet) ShuttingDown() bool {
	select {
	case <-w.quitChan():
		return true
	default:
		return false
	}
}

// WaitForShutdown blocks until all wallet goroutines have finished executing.
func (w *Wallet) WaitForShutdown() {
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClient.WaitForShutdown()
	}
	w.chainClientLock.Unlock()
	w.wg.Wait()
}

// SynchronizingToNetwork returns whether the wallet is currently synchronizing
// with the Bitcoin network.
func (w *Wallet) SynchronizingToNetwork() bool {
	// At the moment, RPC is the only synchronization method.  In the
	// future, when SPV is added, a separate check will also be needed, or
	// SPV could always be enabled if RPC was not explicitly specified when
	// creating the wallet.
	w.chainClientSyncMtx.Lock()
	syncing := w.chainClient != nil
	w.chainClientSyncMtx.Unlock()
	return syncing
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (w *Wallet) ChainSynced() bool {
	w.chainClientSyncMtx.Lock()
	synced := w.chainClientSynced
	w.chainClientSyncMtx.Unlock()
	return synced
}

// SetChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with rpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainClientSyncMtx.Lock()
	w.chainClientSynced = synced
	w.chainClientSyncMtx.Unlock()
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData() ([]btcutil.Address, []wtxmgr.Credit, error) {
	addrs, err := w.store.ListAddresses(context.Background(), db.ListAddressesQuery{
		WalletID: w.ID(),
	})
	if err != nil {
		return nil, nil, err
	}
	addresses := make([]btcutil.Address, len(addrs))
	for i, addr := range addrs {
		addresses[i] = addr.Address
	}

	// Before requesting the list of spendable UTXOs, we'll delete any
	// expired output locks.
	leasedOutputs, err := w.store.ListLeasedOutputs(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for _, leasedOutput := range leasedOutputs {
		if time.Now().After(leasedOutput.Expiration) {
			w.UnlockOutpoint(leasedOutput.Outpoint)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	utxos, err := w.store.ListUTXOs(context.Background(), db.ListUtxosQuery{
		WalletID: w.ID(),
	})
	if err != nil {
		return nil, nil, err
	}

	unspent := make([]wtxmgr.Credit, len(utxos))
	for i, utxo := range utxos {
		unspent[i] = wtxmgr.Credit{
			OutPoint: utxo.OutPoint,
			BlockMeta: wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Height: utxo.Height,
				},
			},
			Amount:   utxo.Amount,
			PkScript: utxo.PkScript,
		}
	}

	return addresses, unspent, err
}

// syncWithChain brings the wallet up to date with the current chain server
// connection. It creates a rescan request and blocks until the rescan has
// finished. The birthday block can be passed in, if set, to ensure we can
// properly detect if it gets rolled back.
func (w *Wallet) syncWithChain(birthdayStamp *waddrmgr.BlockStamp) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// Neutrino relies on the information given to it by the cfheader server
	// so it knows exactly whether it's synced up to the server's state or
	// not, even on dev chains. To recover a Neutrino wallet, we need to
	// make sure it's synced before we start scanning for addresses,
	// otherwise we might miss some if we only scan up to its current sync
	// point.
	neutrinoRecovery := chainClient.BackEnd() == "neutrino" &&
		w.recoveryWindow > 0

	// We'll wait until the backend is synced to ensure we get the latest
	// MaxReorgDepth blocks to store. We don't do this for development
	// environments as we can't guarantee a lively chain, except for
	// Neutrino, where the cfheader server tells us what it believes the
	// chain tip is.
	if !w.isDevEnv() || neutrinoRecovery {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return err
		}
		log.Debug("Chain backend synced to tip!")
	}

	// If we've yet to find our birthday block, we'll do so now.
	if birthdayStamp == nil {
		var err error
		walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
		if err != nil {
			return err
		}
		birthdayStamp, err = locateBirthdayBlock(
			chainClient, walletInfo.Birthday,
		)
		if err != nil {
			return fmt.Errorf("unable to locate birthday block: %w",
				err)
		}

		// We'll also determine our initial sync starting height. This
		// is needed as the wallet can now begin storing blocks from an
		// arbitrary height, rather than all the blocks from genesis, so
		// we persist this height to ensure we don't store any blocks
		// before it.
		startHeight := birthdayStamp.Height

		// With the starting height obtained, get the remaining block
		// details required by the wallet.
		startHash, err := chainClient.GetBlockHash(int64(startHeight))
		if err != nil {
			return err
		}
		startHeader, err := chainClient.GetBlockHeader(startHash)
		if err != nil {
			return err
		}

		err = w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
			WalletID: w.ID(),
			SyncState: db.SyncState{
				SyncedTo:  *startHash,
				Height:    startHeight,
				Timestamp: startHeader.Timestamp,
			},
			BirthdayBlock: birthdayStamp,
		})
		if err != nil {
			return fmt.Errorf("unable to persist initial sync "+
				"data: %w", err)
		}
	}

	// If the wallet requested an on-chain recovery of its funds, we'll do
	// so now.
	if w.recoveryWindow > 0 {
		if err := w.recovery(chainClient, birthdayStamp); err != nil {
			return fmt.Errorf("unable to perform wallet recovery: "+
				"%w", err)
		}
	}

	// Compare previously-seen blocks against the current chain. If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	rollback := false
	walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
	if err != nil {
		return err
	}
	rollbackStamp := waddrmgr.BlockStamp{
		Hash:      walletInfo.SyncState.SyncedTo,
		Height:    walletInfo.SyncState.Height,
		Timestamp: walletInfo.SyncState.Timestamp,
	}
	for height := rollbackStamp.Height; true; height-- {
		chainHash, err := chainClient.GetBlockHash(int64(height))
		if err != nil {
			return err
		}
		header, err := chainClient.GetBlockHeader(chainHash)
		if err != nil {
			return err
		}

		rollbackStamp.Hash = *chainHash
		rollbackStamp.Height = height
		rollbackStamp.Timestamp = header.Timestamp

		if bytes.Equal(walletInfo.SyncState.SyncedTo[:], chainHash[:]) {
			break
		}
		rollback = true
	}

	// If a rollback did not happen, we can proceed safely.
	if rollback {
		// Otherwise, we'll mark this as our new synced height.
		err := w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
			WalletID: w.ID(),
			SyncState: db.SyncState{
				SyncedTo:  rollbackStamp.Hash,
				Height:    rollbackStamp.Height,
				Timestamp: rollbackStamp.Timestamp,
			},
		})
		if err != nil {
			return err
		}

		// If the rollback happened to go beyond our birthday stamp,
		// we'll need to find a new one by syncing with the chain again
		// until finding one.
		if rollbackStamp.Height <= birthdayStamp.Height &&
			rollbackStamp.Hash != birthdayStamp.Hash {

			err := w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
				WalletID:      w.ID(),
				BirthdayBlock: &rollbackStamp,
			})
			if err != nil {
				return err
			}
		}

		// Finally, we'll roll back our transaction store to reflect the
		// stale state. `Rollback` unconfirms transactions at and beyond
		// the passed height, so add one to the new synced-to height to
		// prevent unconfirming transactions in the synced-to block.
		err = w.store.Rollback(context.Background(), rollbackStamp.Height+1)
		if err != nil {
			return err
		}
	}

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// rpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all rpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	if err := chainClient.NotifyBlocks(); err != nil {
		return err
	}

	// Finally, we'll trigger a wallet rescan and request notifications for
	// transactions sending to all wallet addresses and spending all wallet
	// UTXOs.
	addrs, unspent, err := w.activeData()
	if err != nil {
		return err
	}

	return w.rescanWithTarget(addrs, unspent, nil)
}

// isDevEnv determines whether the wallet is currently under a local developer
// environment, e.g. simnet or regtest.
func (w *Wallet) isDevEnv() bool {
	switch uint32(w.chainParams.Net) {
	case uint32(chaincfg.RegressionNetParams.Net):
	case uint32(chaincfg.SimNetParams.Net):
	default:
		return false
	}
	return true
}

// waitUntilBackendSynced blocks until the chain backend considers itself
// "current".
func (w *Wallet) waitUntilBackendSynced(chainClient chain.Interface) error {
	// We'll poll every second to determine if our chain considers itself
	// "current".
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if chainClient.IsCurrent() {
				return nil
			}
		case <-w.quitChan():
			return ErrWalletShuttingDown
		}
	}
}

// locateBirthdayBlock returns a block that meets the given birthday timestamp
// by a margin of +/-2 hours. This is safe to do as the timestamp is already 2
// days in the past of the actual timestamp.
func locateBirthdayBlock(chainClient chainConn,
	birthday time.Time) (*waddrmgr.BlockStamp, error) {

	// Retrieve the lookup range for our block.
	startHeight := int32(0)
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return nil, err
	}

	log.Debugf("Locating suitable block for birthday %v between blocks "+
		"%v-%v", birthday, startHeight, bestHeight)

	var (
		birthdayBlock *waddrmgr.BlockStamp
		left, right   = startHeight, bestHeight
	)

	// Binary search for a block that meets the birthday timestamp by a
	// margin of +/-2 hours.
	for {
		// Retrieve the timestamp for the block halfway through our
		// range.
		mid := left + (right-left)/2
		hash, err := chainClient.GetBlockHash(int64(mid))
		if err != nil {
			return nil, err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return nil, err
		}

		log.Debugf("Checking candidate block: height=%v, hash=%v, "+
			"timestamp=%v", mid, hash, header.Timestamp)

		// If the search happened to reach either of our range extremes,
		// then we'll just use that as there's nothing left to search.
		if mid == startHeight || mid == bestHeight || mid == left {
			birthdayBlock = &waddrmgr.BlockStamp{
				Hash:      *hash,
				Height:    mid,
				Timestamp: header.Timestamp,
			}
			break
		}

		// The block's timestamp is more than 2 hours after the
		// birthday, so look for a lower block.
		if header.Timestamp.Sub(birthday) > birthdayBlockDelta {
			right = mid
			continue
		}

		// The birthday is more than 2 hours before the block's
		// timestamp, so look for a higher block.
		if header.Timestamp.Sub(birthday) < -birthdayBlockDelta {
			left = mid
			continue
		}

		birthdayBlock = &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    mid,
			Timestamp: header.Timestamp,
		}
		break
	}

	log.Debugf("Found birthday block: height=%d, hash=%v, timestamp=%v",
		birthdayBlock.Height, birthdayBlock.Hash,
		birthdayBlock.Timestamp)

	return birthdayBlock, nil
}

// recoverySyncer is used to synchronize wallet and address manager locking
// with the end of recovery. (*Wallet).recovery will store a recoverySyncer
// when invoked, and will close the done chan upon exit. Setting the quit flag
// will cause recovery to end after the current batch of blocks.
type recoverySyncer struct {
	done chan struct{}
	quit uint32 // atomic
}

// recovery attempts to recover any unspent outputs that pay to any of our
// addresses starting from our birthday, or the wallet's tip (if higher), which
// would indicate resuming a recovery after a restart.
func (w *Wallet) recovery(chainClient chain.Interface,
	birthdayBlock *waddrmgr.BlockStamp) error {

	log.Infof("RECOVERY MODE ENABLED -- rescanning for used addresses "+
		"with recovery_window=%d", w.recoveryWindow)

	// Wallet locking must synchronize with the end of recovery, since use of
	// keys in recovery is racy with manager IsLocked checks, which could
	// result in enrypting data with a zeroed key.
	syncer := &recoverySyncer{done: make(chan struct{})}
	w.recovering.Store(syncer)
	defer close(syncer.done)

	// We'll initialize the recovery manager with a default batch size of
	// 2000.
	recoveryMgr := NewRecoveryManager(
		w.recoveryWindow, recoveryBatchSize, w.chainParams,
	)

	// In the event that this recovery is being resumed, we will need to
	// repopulate all found addresses from the database. Ideally, for basic
	// recovery, we would only do so for the default scopes, but due to a
	// bug in which the wallet would create change addresses outside of the
	// default scopes, it's necessary to attempt all registered key scopes.
	scopedMgrs := make(map[waddrmgr.KeyScope]waddrmgr.AccountStore)
	for _, keyScope := range []waddrmgr.KeyScope{
		waddrmgr.KeyScopeBIP0044,
		waddrmgr.KeyScopeBIP0049Plus,
		waddrmgr.KeyScopeBIP0084,
	} {
		scopedMgrs[keyScope] = newAccountStore(
			w.store, w.ID(), keyScope,
		)
	}
	utxos, err := w.store.ListUTXOs(context.Background(), db.ListUtxosQuery{
		WalletID: w.ID(),
	})
	if err != nil {
		return err
	}

	credits := make([]wtxmgr.Credit, len(utxos))
	for i, utxo := range utxos {
		credits[i] = wtxmgr.Credit{
			OutPoint: utxo.OutPoint,
			BlockMeta: wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Height: utxo.Height,
				},
			},
			Amount:       utxo.Amount,
			PkScript:     utxo.PkScript,
			FromCoinBase: utxo.FromCoinBase,
		}
	}
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)
		return recoveryMgr.Resurrect(addrMgrNS, scopedMgrs, credits)
	})
	if err != nil {
		return err
	}

	// Fetch the best height from the backend to determine when we should
	// stop.
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return err
	}

	// Now we can begin scanning the chain from the wallet's current tip to
	// ensure we properly handle restarts. Since the recovery process itself
	// acts as rescan, we'll also update our wallet's synced state along the
	// way to reflect the blocks we process and prevent rescanning them
	// later on.
	//
	// NOTE: We purposefully don't update our best height since we assume
	// that a wallet rescan will be performed from the wallet's tip, which
	// will be of bestHeight after completing the recovery process.
	var blocks []*waddrmgr.BlockStamp
	walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
	if err != nil {
		return err
	}
	startHeight := walletInfo.SyncState.Height + 1
	for height := startHeight; height <= bestHeight; height++ {
		if atomic.LoadUint32(&syncer.quit) == 1 {
			return errors.New("recovery: forced shutdown")
		}

		hash, err := chainClient.GetBlockHash(int64(height))
		if err != nil {
			return err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return err
		}
		blocks = append(blocks, &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    height,
			Timestamp: header.Timestamp,
		})

		// It's possible for us to run into blocks before our birthday
		// if our birthday is after our reorg safe height, so we'll make
		// sure to not add those to the batch.
		if height >= birthdayBlock.Height {
			recoveryMgr.AddToBlockBatch(
				hash, height, header.Timestamp,
			)
		}

		// We'll perform our recovery in batches of 2000 blocks.  It's
		// possible for us to reach our best height without exceeding
		// the recovery batch size, so we can proceed to commit our
		// state to disk.
		recoveryBatch := recoveryMgr.BlockBatch()
		if len(recoveryBatch) == recoveryBatchSize || height == bestHeight {
			err := w.recoverScopedAddresses(
				chainClient, recoveryBatch,
				recoveryMgr.State(), scopedMgrs,
			)
			if err != nil {
				return err
			}

			// TODO: Any error here will roll back this
			// entire tx. This may cause the in memory sync
			// point to become desyncronized. Refactor so
			// that this cannot happen.
			for _, block := range blocks {
				err := w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
					WalletID: w.ID(),
					SyncState: db.SyncState{
						SyncedTo:  block.Hash,
						Height:    block.Height,
						Timestamp: block.Timestamp,
					},
				})
				if err != nil {
					return err
				}
			}

			if len(recoveryBatch) > 0 {
				log.Infof("Recovered addresses from blocks "+
					"%d-%d", recoveryBatch[0].Height,
					recoveryBatch[len(recoveryBatch)-1].Height)
			}

			// Clear the batch of all processed blocks to reuse the
			// same memory for future batches.
			blocks = blocks[:0]
			recoveryMgr.ResetBlockBatch()
		}
	}

	return nil
}

// recoverScopedAddresses scans a range of blocks in attempts to recover any
// previously used addresses for a particular account derivation path. At a high
// level, the algorithm works as follows:
//
//  1. Ensure internal and external branch horizons are fully expanded.
//  2. Filter the entire range of blocks, stopping if a non-zero number of
//     address are contained in a particular block.
//  3. Record all internal and external addresses found in the block.
//  4. Record any outpoints found in the block that should be watched for spends
//  5. Trim the range of blocks up to and including the one reporting the addrs.
//  6. Repeat from (1) if there are still more blocks in the range.
//
// TODO(conner): parallelize/pipeline/cache intermediate network requests
func (w *Wallet) recoverScopedAddresses(
	chainClient chain.Interface,
	batch []wtxmgr.BlockMeta,
	recoveryState *RecoveryState,
	scopedMgrs map[waddrmgr.KeyScope]waddrmgr.AccountStore) error {

	// If there are no blocks in the batch, we are done.
	if len(batch) == 0 {
		return nil
	}

	log.Infof("Scanning %d blocks for recoverable addresses", len(batch))

expandHorizons:
	for scope, scopedMgr := range scopedMgrs {
		scopeState := recoveryState.StateForScope(scope)
		err := w.expandScopeHorizons(scopedMgr, scopeState)
		if err != nil {
			return err
		}
	}

	// With the internal and external horizons properly expanded, we now
	// construct the filter blocks request. The request includes the range
	// of blocks we intend to scan, in addition to the scope-index -> addr
	// map for all internal and external branches.
	filterReq := newFilterBlocksRequest(batch, recoveryState)

	// Initiate the filter blocks request using our chain backend. If an
	// error occurs, we are unable to proceed with the recovery.
	filterResp, err := chainClient.FilterBlocks(filterReq)
	if err != nil {
		return err
	}

	// If the filter response is empty, this signals that the rest of the
	// batch was completed, and no other addresses were discovered. As a
	// result, no further modifications to our recovery state are required
	// and we can proceed to the next batch.
	if filterResp == nil {
		return nil
	}

	// Otherwise, retrieve the block info for the block that detected a
	// non-zero number of address matches.
	block := batch[filterResp.BatchIndex]

	// Log any non-trivial findings of addresses or outpoints.
	logFilterBlocksResp(block, filterResp)

	// Report any external or internal addresses found as a result of the
	// appropriate branch recovery state. Adding indexes above the
	// last-found index of either will result in the horizons being expanded
	// upon the next iteration. Any found addresses are also marked used
	// using the scoped key manager.
	err = w.extendFoundAddresses(filterResp, scopedMgrs, recoveryState)
	if err != nil {
		return err
	}

	// Update the global set of watched outpoints with any that were found
	// in the block.
	for outPoint, addr := range filterResp.FoundOutPoints {
		outPoint := outPoint
		recoveryState.AddWatchedOutPoint(&outPoint, addr)
	}

	// Finally, record all of the relevant transactions that were returned
	// in the filter blocks response. This ensures that these transactions
	// and their outputs are tracked when the final rescan is performed.
	for _, txn := range filterResp.RelevantTxns {
		// For each transaction, we'll determine which of its outputs
		// are credits to the wallet.
		var credits []db.CreditData
		for i, txOut := range txn.TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txOut.PkScript, w.chainParams,
			)
			if err != nil {
				continue
			}
			if len(addrs) != 1 {
				continue
			}
			addr := addrs[0]

			isOurAddress := false
			for scope := range scopedMgrs {
				scopeState := recoveryState.StateForScope(scope)

				for _, branchAddr := range scopeState.ExternalBranch.Addrs() {
					if branchAddr.String() == addr.String() {
						isOurAddress = true
						break
					}
				}
				if isOurAddress {
					break
				}

				for _, branchAddr := range scopeState.InternalBranch.Addrs() {
					if branchAddr.String() == addr.String() {
						isOurAddress = true
						break
					}
				}
				if isOurAddress {
					break
				}
			}

			if isOurAddress {
				credits = append(credits, db.CreditData{
					Index:   uint32(i),
					Address: addr,
				})
			}
		}

		// Create the transaction record. We don't check the error
		// as the transaction might already exist if we're resuming
		// a recovery.
		//
		// TODO(yy): check for specific error type.
		txHash := txn.TxHash()
		err = w.store.CreateTx(context.Background(), db.CreateTxParams{
			WalletID: w.ID(),
			Tx:       txn,
			Credits:  credits,
		})
		if err != nil {
			log.Warnf("Failed to create tx: %v", err)
		}

		// Now, update the transaction with the block information.
		err = w.store.UpdateTx(context.Background(), db.UpdateTxParams{
			WalletID: w.ID(),
			TxHash:   txHash,
			Data: db.TxUpdateData{
				BlockMeta: db.BlockMeta{
					Hash:   filterResp.BlockMeta.Hash,
					Height: filterResp.BlockMeta.Height,
					Time:   filterResp.BlockMeta.Time,
				},
			},
		})
		if err != nil {
			return err
		}
	}

	// Update the batch to indicate that we've processed all block through
	// the one that returned found addresses.
	batch = batch[filterResp.BatchIndex+1:]

	// If this was not the last block in the batch, we will repeat the
	// filtering process again after expanding our horizons.
	if len(batch) > 0 {
		goto expandHorizons
	}

	return nil
}

// expandScopeHorizons ensures that the ScopeRecoveryState has an adequately
// sized look ahead for both its internal and external branches. The keys
// derived here are added to the scope's recovery state, but do not affect the
// persistent state of the wallet. If any invalid child keys are detected, the
// horizon will be properly extended such that our lookahead always includes the
// proper number of valid child keys.
func (w *Wallet) expandScopeHorizons(
	scopedMgr waddrmgr.AccountStore,
	scopeState *ScopeRecoveryState) error {

	// Compute the current external horizon and the number of addresses we
	// must derive to ensure we maintain a sufficient recovery window for
	// the external branch.
	exHorizon, exWindow := scopeState.ExternalBranch.ExtendHorizon()
	count, childIndex := uint32(0), exHorizon
	for count < exWindow {
		keyPath := externalKeyPath(childIndex)
		addr, err := w.store.DeriveFromKeyPath(context.Background(), db.KeyScope{
			Purpose: scopedMgr.Scope().Purpose,
			Coin:    scopedMgr.Scope().Coin,
		}, keyPath)
		switch {
		case err == hdkeychain.ErrInvalidChild:
			// Record the existence of an invalid child with the
			// external branch's recovery state. This also
			// increments the branch's horizon so that it accounts
			// for this skipped child index.
			scopeState.ExternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		// Register the newly generated external address and child index
		// with the external branch recovery state.
		scopeState.ExternalBranch.AddAddr(childIndex, addr.Address())

		childIndex++
		count++
	}

	// Compute the current internal horizon and the number of addresses we
	// must derive to ensure we maintain a sufficient recovery window for
	// the internal branch.
	inHorizon, inWindow := scopeState.InternalBranch.ExtendHorizon()
	count, childIndex = 0, inHorizon
	for count < inWindow {
		keyPath := internalKeyPath(childIndex)
		addr, err := w.store.DeriveFromKeyPath(context.Background(), db.KeyScope{
			Purpose: scopedMgr.Scope().Purpose,
			Coin:    scopedMgr.Scope().Coin,
		}, keyPath)
		switch {
		case err == hdkeychain.ErrInvalidChild:
			// Record the existence of an invalid child with the
			// internal branch's recovery state. This also
			// increments the branch's horizon so that it accounts
			// for this skipped child index.
			scopeState.InternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		// Register the newly generated internal address and child index
		// with the internal branch recovery state.
		scopeState.InternalBranch.AddAddr(childIndex, addr.Address())

		childIndex++
		count++
	}

	return nil
}

// externalKeyPath returns the relative external derivation path /0/0/index.
func externalKeyPath(index uint32) waddrmgr.DerivationPath {
	return waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          waddrmgr.ExternalBranch,
		Index:           index,
	}
}

// internalKeyPath returns the relative internal derivation path /0/1/index.
func internalKeyPath(index uint32) waddrmgr.DerivationPath {
	return waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          waddrmgr.InternalBranch,
		Index:           index,
	}
}

// newFilterBlocksRequest constructs FilterBlocksRequests using our current
// block range, scoped managers, and recovery state.
func newFilterBlocksRequest(batch []wtxmgr.BlockMeta,
	recoveryState *RecoveryState) *chain.FilterBlocksRequest {

	filterReq := &chain.FilterBlocksRequest{
		Blocks:           batch,
		ExternalAddrs:    make(map[waddrmgr.ScopedIndex]btcutil.Address),
		InternalAddrs:    make(map[waddrmgr.ScopedIndex]btcutil.Address),
		WatchedOutPoints: recoveryState.WatchedOutPoints(),
	}

	// Populate the external and internal addresses by merging the addresses
	// sets belong to all currently tracked scopes.
	for scope, scopeState := range recoveryState.scopes {
		for index, addr := range scopeState.ExternalBranch.Addrs() {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: scope,
				Index: index,
			}
			filterReq.ExternalAddrs[scopedIndex] = addr
		}
		for index, addr := range scopeState.InternalBranch.Addrs() {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: scope,
				Index: index,
			}
			filterReq.InternalAddrs[scopedIndex] = addr
		}
	}

	return filterReq
}

// extendFoundAddresses accepts a filter blocks response that contains addresses
// found on chain, and advances the state of all relevant derivation paths to
// match the highest found child index for each branch.
func (w *Wallet) extendFoundAddresses(
	filterResp *chain.FilterBlocksResponse,
	scopedMgrs map[waddrmgr.KeyScope]waddrmgr.AccountStore,
	recoveryState *RecoveryState) error {

	// Mark all recovered external addresses as used. This will be done only
	// for scopes that reported a non-zero number of external addresses in
	// this block.
	for scope, indexes := range filterResp.FoundExternalAddrs {
		// First, report all external child indexes found for this
		// scope. This ensures that the external last-found index will
		// be updated to include the maximum child index seen thus far.
		scopeState := recoveryState.StateForScope(scope)
		for index := range indexes {
			scopeState.ExternalBranch.ReportFound(index)
		}

		scopedMgr := scopedMgrs[scope]

		// Now, with all found addresses reported, derive and extend all
		// external addresses up to and including the current last found
		// index for this scope.
		exNextUnfound := scopeState.ExternalBranch.NextUnfound()

		exLastFound := exNextUnfound
		if exLastFound > 0 {
			exLastFound--
		}

		err := scopedMgr.ExtendExternalAddresses(
			nil, waddrmgr.DefaultAccountNum, exLastFound,
		)
		if err != nil {
			return err
		}

		// Finally, with the scope's addresses extended, we mark used
		// the external addresses that were found in the block and
		// belong to this scope.
		for index := range indexes {
			addr := scopeState.ExternalBranch.GetAddr(index)
			err := w.store.MarkAddressAsUsed(context.Background(), db.MarkAddressAsUsedParams{
				WalletID: w.ID(),
				Address:  addr,
			})
			if err != nil {
				return err
			}
		}
	}

	// Mark all recovered internal addresses as used. This will be done only
	// for scopes that reported a non-zero number of internal addresses in
	// this block.
	for scope, indexes := range filterResp.FoundInternalAddrs {
		// First, report all internal child indexes found for this
		// scope. This ensures that the internal last-found index will
		// be updated to include the maximum child index seen thus far.
		scopeState := recoveryState.StateForScope(scope)
		for index := range indexes {
			scopeState.InternalBranch.ReportFound(index)
		}

		scopedMgr := scopedMgrs[scope]

		// Now, with all found addresses reported, derive and extend all
		// internal addresses up to and including the current last found
		// index for this scope.
		inNextUnfound := scopeState.InternalBranch.NextUnfound()

		inLastFound := inNextUnfound
		if inLastFound > 0 {
			inLastFound--
		}
		err := scopedMgr.ExtendInternalAddresses(
			nil, waddrmgr.DefaultAccountNum, inLastFound,
		)
		if err != nil {
			return err
		}

		// Finally, with the scope's addresses extended, we mark used
		// the internal addresses that were found in the blockand belong
		// to this scope.
		for index := range indexes {
			addr := scopeState.InternalBranch.GetAddr(index)
			err := w.store.MarkAddressAsUsed(context.Background(), db.MarkAddressAsUsedParams{
				WalletID: w.ID(),
				Address:  addr,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// logFilterBlocksResp provides useful logging information when filtering
// succeeded in finding relevant transactions.
func logFilterBlocksResp(block wtxmgr.BlockMeta,
	resp *chain.FilterBlocksResponse) {

	// Log the number of external addresses found in this block.
	var nFoundExternal int
	for _, indexes := range resp.FoundExternalAddrs {
		nFoundExternal += len(indexes)
	}
	if nFoundExternal > 0 {
		log.Infof("Recovered %d external addrs at height=%d hash=%v",
			nFoundExternal, block.Height, block.Hash)
	}

	// Log the number of internal addresses found in this block.
	var nFoundInternal int
	for _, indexes := range resp.FoundInternalAddrs {
		nFoundInternal += len(indexes)
	}
	if nFoundInternal > 0 {
		log.Infof("Recovered %d internal addrs at height=%d hash=%v",
			nFoundInternal, block.Height, block.Hash)
	}

	// Log the number of outpoints found in this block.
	nFoundOutPoints := len(resp.FoundOutPoints)
	if nFoundOutPoints > 0 {
		log.Infof("Found %d spends from watched outpoints at "+
			"height=%d hash=%v",
			nFoundOutPoints, block.Height, block.Hash)
	}
}

type (
	createTxRequest struct {
		coinSelectKeyScope    *waddrmgr.KeyScope
		changeKeyScope        *waddrmgr.KeyScope
		account               uint32
		outputs               []*wire.TxOut
		minconf               int32
		feeSatPerKB           btcutil.Amount
		coinSelectionStrategy CoinSelectionStrategy
		dryRun                bool
		resp                  chan createTxResponse
		selectUtxos           []wire.OutPoint
		allowUtxo             func(wtxmgr.Credit) bool
	}
	createTxResponse struct {
		tx  *txauthor.AuthoredTx
		err error
	}
)

// LockedOutpoint returns whether an outpoint has been marked as locked and
// should not be used as an input for created transactions.
func (w *Wallet) LockedOutpoint(op wire.OutPoint) bool {
	w.lockedOutpointsMtx.Lock()
	_, ok := w.lockedOutpoints[op]
	w.lockedOutpointsMtx.Unlock()
	return ok
}

// managedAddress is a wrapper for db.AddressInfo that implements the
// waddrmgr.ManagedAddress interface.
type managedAddress struct {
	info db.AddressInfo
}

// InternalAccount returns the internal account the address is
// associated with.
func (m *managedAddress) InternalAccount() uint32 {
	return m.info.Account
}

// Address returns a btcutil.Address for the backing address.
func (m *managedAddress) Address() btcutil.Address {
	return m.info.Address
}

// AddrHash returns the key or script hash related to the address
func (m *managedAddress) AddrHash() []byte {
	return m.info.Address.ScriptAddress()
}

// Imported returns true if the backing address was imported instead
// of being part of an address chain.
func (m *managedAddress) Imported() bool {
	// TODO(yy): implement this
	return false
}

// Internal returns true if the backing address was created for internal
// use such as a change output of a transaction.
func (m *managedAddress) Internal() bool {
	return m.info.Internal
}

// Compressed returns true if the backing address is compressed.
func (m *managedAddress) Compressed() bool {
	return m.info.Compressed
}

// Used returns true if the backing address has been used in a transaction.
func (m *managedAddress) Used(ns walletdb.ReadBucket) bool {
	return m.info.Used
}

// AddrType returns the address type of the managed address. This can
// be used to quickly discern the address type without further
// processing
func (m *managedAddress) AddrType() waddrmgr.AddressType {
	return waddrmgr.AddressType(m.info.AddrType)
}

// AddressInfoDeprecated returns detailed information about a managed address,
// including its derivation path and whether it's compressed.
//
// Deprecated: This method leaks internal waddrmgr types. Callers
// should use specific methods such as AccountOfAddress,
// IsInternalAddress, etc. instead.
func (w *Wallet) AddressInfoDeprecated(a btcutil.Address) (
	waddrmgr.ManagedAddress, error) {
	info, err := w.store.GetAddress(context.Background(), db.GetAddressQuery{
		WalletID: w.ID(),
		Address:  a,
	})
	if err != nil {
		return nil, err
	}

	return &managedAddress{info: info}, nil
}

// txCreator is responsible for the input selection and creation of
// transactions.  These functions are the responsibility of this method
// (designed to be run as its own goroutine) since input selection must be
// serialized, or else it is possible to create double spends by choosing the
// same inputs for multiple transactions.  Along with input selection, this
// method is also responsible for the signing of transactions, since we don't
// want to end up in a situation where we run out of inputs as multiple
// transactions are being created.  In this situation, it would then be possible
// for both requests, rather than just one, to fail due to not enough available
// inputs.
func (w *Wallet) txCreator() {
	quit := w.quitChan()
out:
	for {
		select {
		case txr := <-w.createTxRequests:
			// If the wallet can be locked because it contains
			// private key material, we need to prevent it from
			// doing so while we are assembling the transaction.
			release := func() {}
			walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
			if err != nil {
				txr.resp <- createTxResponse{nil, err}
				continue
			}
			if !walletInfo.IsWatchOnly {
				heldUnlock, err := w.holdUnlock()
				if err != nil {
					txr.resp <- createTxResponse{nil, err}
					continue
				}

				release = heldUnlock.release
			}

			tx, err := w.txToOutputs(
				txr.outputs, txr.coinSelectKeyScope,
				txr.changeKeyScope, txr.account, txr.minconf,
				txr.feeSatPerKB, txr.coinSelectionStrategy,
				txr.dryRun, txr.selectUtxos, txr.allowUtxo,
			)

			release()
			txr.resp <- createTxResponse{tx, err}
		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// txCreateOptions is a set of optional arguments to modify the tx creation
// process. This can be used to do things like use a custom coin selection
// scope, which otherwise will default to the specified coin selection scope.
type txCreateOptions struct {
	changeKeyScope *waddrmgr.KeyScope
	selectUtxos    []wire.OutPoint
	allowUtxo      func(wtxmgr.Credit) bool
}

// TxCreateOption is a set of optional arguments to modify the tx creation
// process. This can be used to do things like use a custom coin selection
// scope, which otherwise will default to the specified coin selection scope.
type TxCreateOption func(*txCreateOptions)

// defaultTxCreateOptions is the default set of options.
func defaultTxCreateOptions() *txCreateOptions {
	return &txCreateOptions{}
}

// WithCustomChangeScope can be used to specify a change scope for the change
// address. If unspecified, then the same scope will be used for both inputs
// and the change addr. Not specifying any scope at all (nil) will use all
// available coins and the default change scope (P2TR).
func WithCustomChangeScope(changeScope *waddrmgr.KeyScope) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.changeKeyScope = changeScope
	}
}

// WithCustomSelectUtxos is used to specify the inputs to be used while
// creating txns.
func WithCustomSelectUtxos(utxos []wire.OutPoint) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.selectUtxos = utxos
	}
}

// WithUtxoFilter is used to restrict the selection of the internal wallet
// inputs by further external conditions. Utxos which pass the filter are
// considered when creating the transaction.
func WithUtxoFilter(allowUtxo func(utxo wtxmgr.Credit) bool) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.allowUtxo = allowUtxo
	}
}

// CreateSimpleTx creates a new signed transaction spending unspent outputs with
// at least minconf confirmations spending to any number of address/amount
// pairs. Only unspent outputs belonging to the given key scope and account will
// be selected, unless a key scope is not specified. In that case, inputs from all
// accounts may be selected, no matter what key scope they belong to. This is
// done to handle the default account case, where a user wants to fund a PSBT
// with inputs regardless of their type (NP2WKH, P2WKH, etc.). Change and an
// appropriate transaction fee are automatically included, if necessary. All
// transaction creation through this function is serialized to prevent the
// creation of many transactions which spend the same outputs.
//
// A set of functional options can be passed in to apply modifications to the
// tx creation process such as using a custom change scope, which otherwise
// defaults to the same as the specified coin selection scope.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true SHOULD NOT be broadcast.
func (w *Wallet) CreateSimpleTx(coinSelectKeyScope *waddrmgr.KeyScope,
	account uint32, outputs []*wire.TxOut, minconf int32,
	satPerKb btcutil.Amount, coinSelectionStrategy CoinSelectionStrategy,
	dryRun bool, optFuncs ...TxCreateOption) (*txauthor.AuthoredTx, error) {

	opts := defaultTxCreateOptions()
	for _, optFunc := range optFuncs {
		optFunc(opts)
	}

	// If the change scope isn't set, then it should be the same as the
	// coin selection scope in order to match existing behavior.
	if opts.changeKeyScope == nil {
		opts.changeKeyScope = coinSelectKeyScope
	}

	req := createTxRequest{
		coinSelectKeyScope:    coinSelectKeyScope,
		changeKeyScope:        opts.changeKeyScope,
		account:               account,
		outputs:               outputs,
		minconf:               minconf,
		feeSatPerKB:           satPerKb,
		coinSelectionStrategy: coinSelectionStrategy,
		dryRun:                dryRun,
		resp:                  make(chan createTxResponse),
		selectUtxos:           opts.selectUtxos,
		allowUtxo:             opts.allowUtxo,
	}
	w.createTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

type (
	heldUnlock chan struct{}
)

// Unlock unlocks the wallet's address manager and relocks it after timeout has
// expired.  If the wallet is already unlocked and the new passphrase is
// correct, the current timeout is replaced with the new one.  The wallet will
// be locked if the passphrase is incorrect or any other error occurs during the
// unlock.
func (w *Wallet) Unlock(passphrase []byte, lock <-chan time.Time) error {
	return w.store.Unlock(context.Background(), passphrase)
}

// Lock locks the wallet's address manager.
func (w *Wallet) Lock() {
	w.store.Lock(context.Background())
}

// Locked returns whether the account manager for a wallet is locked.
func (w *Wallet) Locked() bool {
	return w.store.IsLocked(context.Background())
}

// holdUnlock prevents the wallet from being locked.  The heldUnlock object
// *must* be released, or the wallet will forever remain unlocked.
//
// TODO: To prevent the above scenario, perhaps closures should be passed
// to the walletLocker goroutine and disallow callers from explicitly
// handling the locking mechanism.
func (w *Wallet) holdUnlock() (heldUnlock, error) {
	return nil, nil
}

// release releases the hold on the unlocked-state of the wallet and allows the
// wallet to be locked again.  If a lock timeout has already expired, the
// wallet is locked again as soon as release is called.
func (c heldUnlock) release() {
}

// ChangePrivatePassphrase attempts to change the passphrase for a wallet from
// old to new.  Changing the passphrase is synchronized with all other address
// manager locking and unlocking.  The lock state will be the same as it was
// before the password change.
func (w *Wallet) ChangePrivatePassphrase(old, new []byte) error {
	return w.store.ChangePassphrase(context.Background(), old, new, true)
}

// ChangePublicPassphrase modifies the public passphrase of the wallet.
func (w *Wallet) ChangePublicPassphrase(old, new []byte) error {
	return w.store.ChangePassphrase(context.Background(), old, new, false)
}

// ChangePassphrases modifies the public and private passphrase of the wallet
// atomically.
func (w *Wallet) ChangePassphrases(publicOld, publicNew, privateOld,
	privateNew []byte) error {
	err := w.store.ChangePassphrase(context.Background(), publicOld, publicNew, false)
	if err != nil {
		return err
	}
	return w.store.ChangePassphrase(context.Background(), privateOld, privateNew, true)
}

// UnlockOutpoint unlocks a previously locked UTXO, making it available
// for coin selection again.
func (w *Wallet) UnlockOutpoint(op wire.OutPoint) {
	// TODO(yy): implement
}

// SyncedTo returns details about the block height and hash that the
// address manager is synced through at the very least.
func (w *Wallet) SyncedTo() waddrmgr.BlockStamp {
	walletInfo, err := w.store.GetWallet(context.Background(), w.Name())
	if err != nil {
		log.Errorf("could not get wallet info: %v", err)
		return waddrmgr.BlockStamp{}
	}
	syncState := walletInfo.SyncState
	return waddrmgr.BlockStamp{
		Hash:      syncState.SyncedTo,
		Height:    syncState.Height,
		Timestamp: syncState.Timestamp,
	}
}

// SendOutputsWithInput is a variant of SendOutputs that allows
// specifying a particular input to use for the transaction.
func (w *Wallet) SendOutputsWithInput(outputs []*wire.TxOut,
	coinSelectKeyScope *waddrmgr.KeyScope, account uint32,
	minconf int32, satPerKb btcutil.Amount,
	strategy CoinSelectionStrategy, label string,
	inputs []wire.OutPoint) (*wire.MsgTx, error) {
	// TODO(yy): implement
	return nil, nil
}

// SendOutputs funds, signs, and broadcasts a Bitcoin transaction
// paying out to the specified outputs.
func (w *Wallet) SendOutputs(outputs []*wire.TxOut,
	coinSelectKeyScope *waddrmgr.KeyScope, account uint32,
	minconf int32, satPerKb btcutil.Amount,
	strategy CoinSelectionStrategy, label string) (*wire.MsgTx, error) {
	// TODO(yy): implement
	return nil, nil
}

// RemoveDescendants removes all transactions from the wallet that
// spend outputs from the passed transaction.
func (w *Wallet) RemoveDescendants(tx *wire.MsgTx) error {
	// TODO(yy): implement
	return nil
}

// ReleaseOutputDeprecated unlocks an output, allowing it to be available for
// coin selection if it remains unspent.
func (w *Wallet) ReleaseOutputDeprecated(id wtxmgr.LockID, op wire.OutPoint) error {
	// TODO(yy): implement
	return nil
}

// PublishTransaction broadcasts a transaction to the network.
func (w *Wallet) PublishTransaction(tx *wire.MsgTx, label string) error {
	// TODO(yy): implement
	return nil
}

// NotificationServer returns the internal NotificationServer.
func (w *Wallet) NotificationServer() *NotificationServer {
	return w.NtfnServer
}

// LockOutpoint locks a specific UTXO, preventing it from being used in
// coin selection.
func (w *Wallet) LockOutpoint(op wire.OutPoint) {
	// TODO(yy): implement
}

// ListUnspentDeprecated returns all unspent transaction outputs for a given
// account and confirmation requirement.
func (w *Wallet) ListUnspentDeprecated(minconf, maxconf int32, accountName string) (
	[]*btcjson.ListUnspentResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// ListLeasedOutputsDeprecated returns a list of all currently leased outputs.
func (w *Wallet) ListLeasedOutputsDeprecated() ([]*ListLeasedOutputResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// LeaseOutputDeprecated locks an output to the given ID, preventing it from
// being available for coin selection.
func (w *Wallet) LeaseOutputDeprecated(id wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {
	// TODO(yy): implement
	return time.Time{}, nil
}

// InitAccounts initializes the accounts for all the key families.
func (w *Wallet) InitAccounts(scope *waddrmgr.ScopedKeyManager, convertToWatchOnly bool,
	account uint32) error {
	// TODO(yy): implement
	return nil
}

// HaveAddress returns whether the wallet is the owner of the address a.
func (w *Wallet) HaveAddress(a btcutil.Address) (bool, error) {
	_, err := w.store.GetAddress(context.Background(), db.GetAddressQuery{
		WalletID: w.ID(),
		Address:  a,
	})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, db.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// GetTransactions returns a slice of transaction details for
// transactions which fall in the given range of blocks.
func (w *Wallet) GetTransactions(start *BlockIdentifier, end *BlockIdentifier,
	accountFilter string, txFilter <-chan struct{}) (
	*GetTransactionsResult, error) {
	// TODO(yy): implement
	return nil, nil
}

// DeriveFromKeyPathAddAccount derives a key from the wallet's root
// key, also creating a new account if it doesn't exist.
func (w *Wallet) DeriveFromKeyPathAddAccount(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {
	// TODO(yy): implement
	return nil, nil
}

// DeriveFromKeyPath derives a key from the wallet's root key.
func (w *Wallet) DeriveFromKeyPath(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {
	// TODO(yy): implement
	return nil, nil
}

// Database returns the underlying walletdb database.
func (w *Wallet) Database() walletdb.DB {
	return w.db
}

// ChainParams returns the chain parameters for the wallet.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// BirthdayBlock returns the wallet's birthday block.
func (w *Wallet) BirthdayBlock() (*waddrmgr.BlockStamp, error) {
	// TODO(yy): implement
	return nil, nil
}


// AddScopeManager adds a new scope manager to the wallet.
func (w *Wallet) AddScopeManager(scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema) (
	waddrmgr.AccountStore, error) {
	// TODO(yy): implement
	return nil, nil
}

// AccountProperties returns the properties for a specific account.
func (w *Wallet) AccountProperties(scope waddrmgr.KeyScope, account uint32) (*waddrmgr.AccountProperties, error) {
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	info, err := w.store.GetAccount(context.Background(), db.GetAccountQuery{
		WalletID:      w.ID(),
		Scope:         dbScope,
		AccountNumber: &account,
	})
	if err != nil {
		return nil, err
	}

	return &waddrmgr.AccountProperties{
		AccountNumber:    info.AccountNumber,
		AccountName:      info.AccountName,
		ExternalKeyCount: info.ExternalKeyCount,
		InternalKeyCount: info.InternalKeyCount,
		ImportedKeyCount: info.ImportedKeyCount,
	}, nil
}

// AccountName returns the name of an account.
func (w *Wallet) AccountName(scope waddrmgr.KeyScope, account uint32) (string, error) {
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	info, err := w.store.GetAccount(context.Background(), db.GetAccountQuery{
		WalletID:      w.ID(),
		Scope:         dbScope,
		AccountNumber: &account,
	})
	if err != nil {
		return "", err
	}

	return info.AccountName, nil
}

// AccountNumber returns the account number for an account name under a
// particular key scope.
func (w *Wallet) AccountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error) {
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	info, err := w.store.GetAccount(context.Background(), db.GetAccountQuery{
		WalletID: w.ID(),
		Scope:    dbScope,
		Name:     &accountName,
	})
	if err != nil {
		return 0, err
	}

	return info.AccountNumber, nil
}

// AccountManagedAddresses returns the managed addresses for every created
// address for an account.
func (w *Wallet) AccountManagedAddresses(scope waddrmgr.KeyScope,
	accountNum uint32) ([]db.AddressInfo, error) {

	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	// TODO(yy): filter by account number
	return w.store.ListAddresses(context.Background(), db.ListAddressesQuery{
		WalletID: w.ID(),
		Scope:    dbScope,
	})
}

// PrivKeyForAddress returns the private key for a given address.
func (w *Wallet) PrivKeyForAddress(a btcutil.Address) (*btcec.PrivateKey, error) {
	privKey, _, err := w.store.GetPrivateKey(context.Background(), a)
	return privKey, err
}

// NewChangeAddress returns a new change address for a given account and scope.
func (w *Wallet) NewChangeAddress(account uint32, scope waddrmgr.KeyScope) (
	btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *Wallet) CalculateBalance(confirmations int32) (btcutil.Amount, error) {
	return w.store.Balance(context.Background(), confirmations)
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance for each account.
// This function also takes a required confirmation parameter, which is the
// same as CalculateBalance.
func (w *Wallet) CalculateAccountBalances(
	confirmations int32) (map[string]Balances, error) {

	// First, fetch all accounts to get their names.
	accounts, err := w.store.ListAccounts(context.Background(), db.ListAccountsQuery{
		WalletID: w.ID(),
	})
	if err != nil {
		return nil, err
	}

	// Create a map to hold the balances for each account.
	balances := make(map[string]Balances)
	for _, acc := range accounts {
		balances[acc.AccountName] = Balances{}
	}

	// Now, fetch all UTXOs and aggregate their values by account.
	utxos, err := w.store.ListUTXOs(context.Background(), db.ListUtxosQuery{
		WalletID: w.ID(),
		MinConfs: confirmations,
	})
	if err != nil {
		return nil, err
	}

	for _, utxo := range utxos {
		// TODO(yy): get chain params from somewhere else.
		addr := extractAddrFromPKScript(utxo.PkScript, nil)
		if addr == nil {
			continue
		}

		// Now that we have the address, we'll look up which account it
		// belongs to.
		addrInfo, err := w.store.GetAddress(context.Background(), db.GetAddressQuery{
			WalletID: w.ID(),
			Address:  addr,
		})
		if err != nil {
			continue
		}

		// Find the account name for the account number.
		var accName string
		for _, acc := range accounts {
			if acc.AccountNumber == addrInfo.Account {
				accName = acc.AccountName
				break
			}
		}

		// Add the UTXO's value to the account's balance.
		accBalance := balances[accName]
		accBalance.Total += utxo.Amount
		if confirmations > 0 {
			accBalance.Spendable += utxo.Amount
		}
		balances[accName] = accBalance
	}

	return balances, nil
}

// LastAccountName returns the name of the last account in the wallet.
func (w *Wallet) LastAccountName(scope waddrmgr.KeyScope) (string, error) {
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}
	accounts, err := w.store.ListAccounts(context.Background(), db.ListAccountsQuery{
		WalletID: w.ID(),
		Scope:    &dbScope,
	})
	if err != nil {
		return "", err
	}
	if len(accounts) == 0 {
		return "", errors.New("no accounts found")
	}

	return accounts[len(accounts)-1].AccountName, nil
}

// NextExternalAddresses returns the next n external addresses from an account.
func (w *Wallet) NextExternalAddresses(scope waddrmgr.KeyScope,
	accountName string, n uint32) ([]btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// NextInternalAddresses returns the next n internal addresses from an account.
func (w *Wallet) NextInternalAddresses(scope waddrmgr.KeyScope,
	accountName string, n uint32) ([]btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// NewExternalAddress returns a new external address for an account.
func (w *Wallet) NewExternalAddress(scope waddrmgr.KeyScope,
	accountName string) (btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// NewInternalAddress returns a new internal address for an account.
func (w *Wallet) NewInternalAddress(scope waddrmgr.KeyScope,
	accountName string) (btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// LastUsedAddress returns the last used address for an account.
func (w *Wallet) LastUsedAddress(scope waddrmgr.KeyScope,
	accountName string) (btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// SetUsedAddress marks an address as used.
func (w *Wallet) SetUsedAddress(scope waddrmgr.KeyScope,
	accountName string, address btcutil.Address) error {
	// TODO(yy): implement
	return nil
}

// FundTransaction funds a transaction.
func (w *Wallet) FundTransaction(scope waddrmgr.KeyScope,
	accountName string, satPerKb btcutil.Amount,
	outputs []*wire.TxOut, minconf int32,
	strategy CoinSelectionStrategy) (*wire.MsgTx, error) {
	// TODO(yy): implement
	return nil, nil
}

// SignAndSendTransaction signs and sends a transaction.
func (w *Wallet) SignAndSendTransaction(scope waddrmgr.KeyScope,
	accountName string, tx *wire.MsgTx,
	prevScripts map[wire.OutPoint][]byte,
	inputValues map[wire.OutPoint]btcutil.Amount) (*chainhash.Hash, error) {
	// TODO(yy): implement
	return nil, nil
}

// SendToAddresses sends a transaction to a set of addresses.
func (w *Wallet) SendToAddresses(scope waddrmgr.KeyScope,
	accountName string, satPerKb btcutil.Amount,
	outputs map[string]btcutil.Amount, minconf int32,
	strategy CoinSelectionStrategy) (*chainhash.Hash, error) {
	// TODO(yy): implement
	return nil, nil
}

// SendAll sends all funds in an account to a set of addresses.
func (w *Wallet) SendAll(scope waddrmgr.KeyScope,
	accountName string, satPerKb btcutil.Amount,
	addresses []btcutil.Address, minconf int32) (*chainhash.Hash, error) {
	// TODO(yy): implement
	return nil, nil
}

// SweepAccount sweeps all funds in an account to a single address.
func (w *Wallet) SweepAccount(scope waddrmgr.KeyScope,
	accountName string, satPerKb btcutil.Amount,
	address btcutil.Address, minconf int32) (*chainhash.Hash, error) {
	// TODO(yy): implement
	return nil, nil
}

// LockUnspent locks an unspent output.
func (w *Wallet) LockUnspent(scope waddrmgr.KeyScope,
	accountName string, output *wire.OutPoint) error {
	// TODO(yy): implement
	return nil
}

// UnlockUnspent unlocks an unspent output.
func (w *Wallet) UnlockUnspent(scope waddrmgr.KeyScope,
	accountName string, output *wire.OutPoint) error {
	// TODO(yy): implement
	return nil
}

// LockedUnspents returns all locked unspent outputs for an account.
func (w *Wallet) LockedUnspents(scope waddrmgr.KeyScope,
	accountName string) ([]*wire.OutPoint, error) {
	// TODO(yy): implement
	return nil, nil
}

// GetTransaction returns a transaction.
func (w *Wallet) GetTransaction(hash chainhash.Hash) (*Transaction, error) {
	// TODO(yy): implement
	return nil, nil
}

// Transaction is a struct that holds information about a transaction.
type Transaction struct {
	Hash        chainhash.Hash
	Tx          *wire.MsgTx
	BlockHeight int32
	BlockHash   chainhash.Hash
	Timestamp   time.Time
}

// UnspentOutput is a struct that holds information about an unspent output.
type UnspentOutput struct {
	OutPoint      wire.OutPoint
	Amount        btcutil.Amount
	ScriptPubKey  []byte
	Confirmations int64
}

// GetTransactionsByAddress returns all transactions for an address.
func (w *Wallet) GetTransactionsByAddress(address btcutil.Address) ([]*Transaction, error) {
	// TODO(yy): implement
	return nil, nil
}

// GetTransactionsByAccount returns all transactions for an account.
func (w *Wallet) GetTransactionsByAccount(scope waddrmgr.KeyScope,
	accountName string) ([]*Transaction, error) {
	// TODO(yy): implement
	return nil, nil
}