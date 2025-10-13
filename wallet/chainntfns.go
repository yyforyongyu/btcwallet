// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// birthdayBlockDelta is the maximum time delta allowed between our
	// birthday timestamp and our birthday block's timestamp when searching
	// for a better birthday block candidate (if possible).
	birthdayBlockDelta = 2 * time.Hour
)

func (w *Wallet) handleChainNotifications() {
	defer w.wg.Done()

	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		return
	}

	catchUpHashes := func(w *Wallet, client chain.Interface,
		height int32) error {
		// TODO(aakselrod): There's a race condition here, which
		// happens when a reorg occurs between the
		// rescanProgress notification and the last GetBlockHash
		// call. The solution when using btcd is to make btcd
		// send blockconnected notifications with each block
		// the way Neutrino does, and get rid of the loop. The
		// other alternative is to check the final hash and,
		// if it doesn't match the original hash returned by
		// the notification, to roll back and restart the
		// rescan.
		log.Infof("Catching up block hashes to height %d, this"+
			" might take a while", height)
		err := w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
			WalletID: w.ID(),
			SyncState: db.SyncState{
				Height: height,
			},
		})
		if err != nil {
			log.Errorf("Failed to update address manager "+
				"sync state for height %d: %v", height, err)
		}

		log.Info("Done catching up block hashes")
		return err
	}

	waitForSync := func(birthdayBlock *waddrmgr.BlockStamp) error {
		// We start with a retry delay of 0 to execute the first attempt
		// immediately.
		var retryDelay time.Duration
		for {
			select {
			case <-time.After(retryDelay):
				// Set the delay to the configured value in case
				// we actually need to re-try.
				retryDelay = w.syncRetryInterval

				// Sync may be interrupted by actions such as
				// locking the wallet. Try again after waiting a
				// bit.
				err = w.syncWithChain(birthdayBlock)
				if err != nil {
					if w.ShuttingDown() {
						return ErrWalletShuttingDown
					}

					log.Errorf("Unable to synchronize "+
						"wallet to chain, trying "+
						"again in %s: %v",
						w.syncRetryInterval, err)

					continue
				}

				return nil

			case <-w.quitChan():
				return ErrWalletShuttingDown
			}
		}
	}

	for {
		select {
		case n, ok := <-chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				// Before attempting to sync with our backend,
				// we'll make sure that our birthday block has
				// been set correctly to potentially prevent
				// missing relevant events.
				birthdayStore := &walletBirthdayStore{
					store: w.store,
				}
				birthdayBlock, err := birthdaySanityCheck(
					context.Background(), chainClient,
					birthdayStore,
				)
				if err != nil && !waddrmgr.IsError(
					err, waddrmgr.ErrBirthdayBlockNotSet,
				) {

					log.Errorf("Unable to sanity check "+
						"wallet birthday block: %v",
						err)
				}

				err = waitForSync(birthdayBlock)
				if err != nil {
					log.Infof("Stopped waiting for wallet "+
						"sync due to error: %v", err)

					return
				}

			case chain.BlockConnected:
				err = w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
					WalletID: w.ID(),
					SyncState: db.SyncState{
						SyncedTo: n.Hash,
						Height:   n.Height,
					},
				})
				notificationName = "block connected"
			case chain.BlockDisconnected:
				err = w.store.UpdateSyncState(context.Background(), db.UpdateSyncStateParams{
					WalletID: w.ID(),
					SyncState: db.SyncState{
						SyncedTo: n.Hash,
						Height:   n.Height,
					},
				})
				notificationName = "block disconnected"
			case chain.RelevantTx:
				err = w.store.UpdateTx(context.Background(), db.UpdateTxParams{
					WalletID: w.ID(),
					TxHash:   n.TxRecord.Hash,
					Data: db.TxUpdateData{
						BlockMeta: db.BlockMeta{
							Hash:   n.Block.Hash,
							Height: n.Block.Height,
							Time:   n.Block.Time,
						},
					},
				})
				notificationName = "relevant transaction"
			case chain.FilteredBlockConnected:
				// Atomically update for the whole block.
				if len(n.RelevantTxs) > 0 {
					err = walletdb.Update(w.db, func(
						tx walletdb.ReadWriteTx) error {
						var err error
						for _, rec := range n.RelevantTxs {
							err = w.addRelevantTx(context.Background(), tx, rec,
								n.Block)
							if err != nil {
								return err
							}
						}
						return nil
					})
				}
				notificationName = "filtered block connected"

			// The following require some database maintenance, but also
			// need to be reported to the wallet's rescan goroutine.
			case *chain.RescanProgress:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescan progress"
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			case *chain.RescanFinished:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescan finished"
				w.SetChainSynced(true)
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			}
			if err != nil {
				// If we received a block connected notification
				// while rescanning, then we can ignore logging
				// the error as we'll properly catch up once we
				// process the RescanFinished notification.
				if notificationName == "block connected" &&
					waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) &&
					!w.ChainSynced() {

					log.Debugf("Received block connected "+
						"notification for height %v "+
						"while rescanning",
						n.(chain.BlockConnected).Height)
					continue
				}

				log.Errorf("Unable to process chain backend "+
					"%v notification: %v", notificationName,
					err)
			}
		case <-w.quit:
			return
		}
	}
}

// addRelevantTx adds a relevant transaction to the wallet's transaction store.
func (w *Wallet) addRelevantTx(ctx context.Context, dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) error {

	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	_, err := w.store.GetTx(ctx, db.GetTxQuery{
		WalletID: w.ID(),
		TxHash:   rec.Hash,
	})
	if err == nil {
		return nil
	}

	// If the transaction has already been recorded, we can return early.
	// Note: Returning here is safe as we're within the context of an atomic
	// database transaction, so we don't need to worry about the MarkUsed
	// calls below.
	if !errors.Is(err, db.ErrNotFound) {
		return err
	}

		var credits []db.CreditData

		for i, output := range rec.MsgTx.TxOut {

			_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,

				w.chainParams)

			if err != nil {

				// Non-standard outputs are skipped.

				log.Warnf("Cannot extract non-std pkScript=%x",

					output.PkScript)

	

				continue

			}

	

			for _, addr := range addrs {

				addrInfo, err := w.store.GetAddress(ctx, db.GetAddressQuery{

					WalletID: w.ID(),

					Address:  addr,

				})

	

				switch {

				// Missing addresses are skipped.

				case errors.Is(err, db.ErrNotFound):

					continue

	

				// Other errors should be propagated.

				case err != nil:

					return err

				}

	

				// Prevent addresses from non-default scopes to be

				// detected here. We don't watch funds sent to

				// non-default scopes in other places either, so

				// detecting them here would mean we'd also not properly

				// detect them as spent later.

				keyScope := waddrmgr.KeyScope{

					Purpose: addrInfo.DerivationInfo.KeyScope.Purpose,

					Coin:    addrInfo.DerivationInfo.KeyScope.Coin,

				}

				if !waddrmgr.IsDefaultScope(keyScope) {

					log.Debugf("Skipping non-default scope "+

						"address %v", addr)

	

					continue

				}

	

				credits = append(credits, db.CreditData{

					Index:   uint32(i),

					Address: addr,

				})

				err = w.store.MarkAddressAsUsed(ctx, db.MarkAddressAsUsedParams{

					WalletID: w.ID(),

					Address:  addr,

				})

				if err != nil {

					return err

				}

				log.Debugf("Marked address %v used", addr)

			}

		}

	

		if len(credits) > 0 {

			err = w.store.CreateTx(ctx, db.CreateTxParams{

				WalletID: w.ID(),

				Tx:       &rec.MsgTx,

				Credits:  credits,

			})

			if err != nil {

				return err

			}

		}

	

		// Send notification of mined or unmined transaction to any interested

		// clients.

		//

		// TODO: Avoid the extra db hits.

		if block == nil {

			w.NtfnServer.notifyUnminedTransaction(dbtx, txmgrNs, rec.Hash)

		} else {

			w.NtfnServer.notifyMinedTransaction(

				dbtx, txmgrNs, rec.Hash, block,

			)

		}

	

	return nil
}

// chainConn is an interface that abstracts the chain connection logic required
// to perform a wallet's birthday block sanity check.
type chainConn interface {
	// GetBestBlock returns the hash and height of the best block known to
	// the backend.
	GetBestBlock() (*chainhash.Hash, int32, error)

	// GetBlockHash returns the hash of the block with the given height.
	GetBlockHash(int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header for the block with the given hash.
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
}

// birthdayStore is an interface that abstracts the wallet's sync-related
// information required to perform a birthday block sanity check.
type birthdayStore interface {
	// Birthday returns the birthday timestamp of the wallet.
	Birthday(ctx context.Context) time.Time

	// BirthdayBlock returns the birthday block of the wallet. The boolean
	// returned should signal whether the wallet has already verified the
	// correctness of its birthday block.
	BirthdayBlock(ctx context.Context) (waddrmgr.BlockStamp, bool, error)

	// SetBirthdayBlock updates the birthday block of the wallet to the
	// given block. The boolean can be used to signal whether this block
	// should be sanity checked the next time the wallet starts.
	//
	// NOTE: This should also set the wallet's synced tip to reflect the new
	// birthday block. This will allow the wallet to rescan from this point
	// to detect any potentially missed events.
	SetBirthdayBlock(ctx context.Context, block waddrmgr.BlockStamp) error
}

// walletBirthdayStore is a wrapper around the wallet's database and address
// manager that satisfies the birthdayStore interface.
type walletBirthdayStore struct {
	store db.Store
}

var _ birthdayStore = (*walletBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *walletBirthdayStore) Birthday(ctx context.Context) time.Time {
	info, err := s.store.GetWallet(ctx, "")
	if err != nil {
		return time.Time{}
	}
	return info.SyncState.Timestamp
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *walletBirthdayStore) BirthdayBlock(ctx context.Context) (waddrmgr.BlockStamp, bool, error) {
	info, err := s.store.GetWallet(ctx, "")
	if err != nil {
		return waddrmgr.BlockStamp{}, false, err
	}
	return waddrmgr.BlockStamp{
		Hash:      info.SyncState.SyncedTo,
		Height:    info.SyncState.Height,
		Timestamp: info.SyncState.Timestamp,
	}, true, nil
}

// SetBirthdayBlock updates the birthday block of the wallet to the
// given block. The boolean can be used to signal whether this block
// should be sanity checked the next time the wallet starts.
//
// NOTE: This should also set the wallet's synced tip to reflect the new
// birthday block. This will allow the wallet to rescan from this point
// to detect any potentially missed events.
func (s *walletBirthdayStore) SetBirthdayBlock(ctx context.Context, block waddrmgr.BlockStamp) error {
	return s.store.UpdateSyncState(ctx, db.UpdateSyncStateParams{
		WalletID: 0, // TODO(yy): get wallet ID
		SyncState: db.SyncState{
			SyncedTo:  block.Hash,
			Height:    block.Height,
			Timestamp: block.Timestamp,
		},
	})
}

// birthdaySanityCheck is a helper function that ensures a birthday block
// correctly reflects the birthday timestamp within a reasonable timestamp
// delta. It's intended to be run after the wallet establishes its connection
// with the backend, but before it begins syncing. This is done as the second
// part to the wallet's address manager migration where we populate the birthday
// block to ensure we do not miss any relevant events throughout rescans.
// waddrmgr.ErrBirthdayBlockNotSet is returned if the birthday block has not
// been set yet.
func birthdaySanityCheck(ctx context.Context, chainConn chainConn,
	birthdayStore birthdayStore) (*waddrmgr.BlockStamp, error) {

	// We'll start by fetching our wallet's birthday timestamp and block.
	birthdayTimestamp := birthdayStore.Birthday(ctx)
	birthdayBlock, birthdayBlockVerified, err := birthdayStore.BirthdayBlock(ctx)
	if err != nil {
		return nil, err
	}

	// If the birthday block has already been verified to be correct, we can
	// exit our sanity check to prevent potentially fetching a better
	// candidate.
	if birthdayBlockVerified {
		log.Debugf("Birthday block has already been verified: "+
			"height=%d, hash=%v", birthdayBlock.Height,
			birthdayBlock.Hash)

		return &birthdayBlock, nil
	}

	// Otherwise, we'll attempt to locate a better one now that we have
	// access to the chain.
	newBirthdayBlock, err := locateBirthdayBlock(chainConn, birthdayTimestamp)
	if err != nil {
		return nil, err
	}

	if err := birthdayStore.SetBirthdayBlock(ctx, *newBirthdayBlock); err != nil {
		return nil, err
	}

	return newBirthdayBlock, nil
}