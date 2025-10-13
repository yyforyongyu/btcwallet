// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/davecgh/go-spew/spew"
)

// TxPublisher provides an interface for publishing transactions.
type TxPublisher interface {
	// CheckMempoolAcceptance checks if a transaction would be accepted by
	// the mempool without broadcasting.
	CheckMempoolAcceptance(ctx context.Context, tx *wire.MsgTx) error

	// Broadcast broadcasts a transaction to the network.
	Broadcast(ctx context.Context, tx *wire.MsgTx, label string) error
}

// A compile time check to ensure that Wallet implements the interface.
var _ TxPublisher = (*Wallet)(nil)

// CheckMempoolAcceptance checks if a transaction would be accepted by the
// mempool without broadcasting.
func (w *Wallet) CheckMempoolAcceptance(ctx context.Context,
	tx *wire.MsgTx) error {

	// TODO(yy): thread context through.
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// The TestMempoolAccept rpc expects a slice of transactions.
	txns := []*wire.MsgTx{tx}

	// Use a max feerate of 0 means the default value will be used when
	// testing mempool acceptance. The default max feerate is 0.10 BTC/kvb,
	// or 10,000 sat/vb.
	maxFeeRate := float64(0)

	results, err := chainClient.TestMempoolAccept(txns, maxFeeRate)
	if err != nil {
		return err
	}

	// Sanity check that the expected single result is returned.
	if len(results) != 1 {
		return fmt.Errorf("expected 1 result from TestMempoolAccept, " +
			"instead got %v", len(results))
	}

	result := results[0]

	// If the transaction is allowed, we can return early.
	if result.Allowed {
		return nil
	}

	// Otherwise, we'll map the reason to a concrete error type and return
	// it.
	err = errors.New(result.RejectReason)
	return chainClient.MapRPCErr(err)
}

// Broadcast broadcasts a tx to the network. It is the main implementation of
// the TxPublisher interface.
func (w *Wallet) Broadcast(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.checkMempool(ctx, tx)
	if errors.Is(err, errAlreadyBroadcasted) {
		return nil
	}
	if err != nil {
		return err
	}

	// First, we'll attempt to add the tx to our wallet's DB. This will
	// allow us to track the tx's confirmation status, and also
	// re-broadcast it upon startup. If any of the subsequent steps fail,
	// this tx must be removed.
	ourAddrs, err := w.addTxToWallet(ctx, tx, label)
	if err != nil {
		return err
	}

	// Now, we'll attempt to publish the tx.
	err = w.publishTx(tx, ourAddrs)
	if err == nil {
		return nil
	}

	txid := tx.TxHash()
	log.Errorf("%v: broadcast failed: %v", txid, err)

	// If the tx was rejected for any other reason, then we'll remove it
	// from the tx store, as otherwise, we'll attempt to continually
	// re-broadcast it, and the UTXO state of the wallet won't be accurate.
	removeErr := w.removeUnminedTx(ctx, tx)
	if removeErr != nil {
		log.Warnf("Unable to remove tx %v after broadcast failed: %v",
			txid, removeErr)

		// Return a wrapped error to give the caller full context.
		return fmt.Errorf("broadcast failed: %w; and failed to " +
			"remove from wallet: %v", err, removeErr)
	}

	return err
}

var (
	// errAlreadyBroadcasted is a sentinel error used to indicate that a tx
	// has already been broadcasted.
	errAlreadyBroadcasted = errors.New("tx already broadcasted")
)

// checkMempool is a helper function that checks if a tx is acceptable to the
// mempool before broadcasting.
func (w *Wallet) checkMempool(ctx context.Context,
	tx *wire.MsgTx) error {

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.CheckMempoolAcceptance(ctx, tx)

	switch {
	// If the tx is already in the mempool or confirmed, we can return
	// early.
	case errors.Is(err, chain.ErrTxAlreadyInMempool),
		errors.Is(err, chain.ErrTxAlreadyKnown),
		errors.Is(err, chain.ErrTxAlreadyConfirmed):

		log.Infof("Tx %v already broadcasted", tx.TxHash())

		// TODO(yy): Add a new method UpdateTxLabel to allow updating
		// the label of a tx. With this change, the label passed in
		// will be ignored if the tx is already known.
		return errAlreadyBroadcasted

	// If the backend does not support the mempool acceptance test, we'll
	// just attempt to publish the tx.
	case errors.Is(err, rpcclient.ErrBackendVersion),
		errors.Is(err, chain.ErrUnimplemented):

		log.Warnf("Backend does not support mempool acceptance test, " +
			"broadcasting directly: %v", err)

		return nil

	// If the tx was rejected for any other reason, we'll return the error
	// directly.
	case err != nil:
		return fmt.Errorf("tx rejected by mempool: %w", err)

	// Otherwise, the tx is valid and we can publish it.
	default:
		return nil
	}
}

// addTxToWallet adds a tx to the wallet's database.
func (w *Wallet) addTxToWallet(ctx context.Context, tx *wire.MsgTx,
	label string) ([]btcutil.Address, error) {

	// Stage 1: Extract potential addresses from all transaction outputs.
	txOutAddrs := w.extractTxAddrs(tx)

	// Stage 2: Filter the extracted addresses to find which ones are owned
	// by the wallet.
	ownedAddrs, err := w.filterOwnedAddresses(ctx, txOutAddrs)
	if err != nil {
		return nil, err
	}

	// If the transaction has no outputs relevant to us, we can exit early.
	if len(ownedAddrs) == 0 {
		return nil, nil
	}

	// Stage 3: Prepare a definitive "write plan".
	var creditsToWrite []db.CreditData
	var ourAddrs []btcutil.Address

	for index, addrs := range txOutAddrs {
		for _, addr := range addrs {
			if _, ok := ownedAddrs[addr]; !ok {
				continue
			}

			creditsToWrite = append(creditsToWrite, db.CreditData{
				Index:   uint32(index),
				Address: addr,
			})
			ourAddrs = append(ourAddrs, addr)
		}
	}

	// Stage 4: Atomically execute the write plan.
	params := db.CreateTxParams{
		WalletID: w.ID(),
		Tx:       tx,
		Label:    label,
		Credits:  creditsToWrite,
	}
	err = w.store.CreateTx(ctx, params)
	if err != nil {
		return nil, err
	}

	return ourAddrs, nil
}

// extractTxAddrs extracts all potential addresses from a transaction's outputs.
func (w *Wallet) extractTxAddrs(tx *wire.MsgTx) map[uint32][]btcutil.Address {
	txOutAddrs := make(map[uint32][]btcutil.Address)
	for i, output := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		// Ignore non-standard scripts.
		if err != nil {
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)
			continue
		}

		txOutAddrs[uint32(i)] = addrs
	}

	return txOutAddrs
}

// filterOwnedAddresses takes a map of output indexes to addresses and returns a
// new map containing only the addresses that are owned by the wallet.
func (w *Wallet) filterOwnedAddresses(ctx context.Context,
	txOutAddrs map[uint32][]btcutil.Address) (
	map[btcutil.Address]struct{}, error) {

	ownedAddrs := make(map[btcutil.Address]struct{})
	for _, addrs := range txOutAddrs {
		for _, addr := range addrs {
			if _, ok := ownedAddrs[addr]; ok {
				continue
			}

			_, err := w.store.GetAddress(ctx, db.GetAddressQuery{
				WalletID: w.ID(),
				Address:  addr,
			})
			if waddrmgr.IsError(
				err, waddrmgr.ErrAddressNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}

			ownedAddrs[addr] = struct{}{}
		}
	}

	return ownedAddrs, nil
}

// publishTx is a helper function that handles the process of broadcasting a
// transaction to the network.
func (w *Wallet) publishTx(tx *wire.MsgTx, ourAddrs []btcutil.Address) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	if err := chainClient.NotifyReceived(ourAddrs); err != nil {
		return err
	}

	txid := tx.TxHash()
	_, rpcErr := chainClient.SendRawTransaction(tx, false)
	if rpcErr == nil {
		return nil
	}

	if errors.Is(rpcErr, chain.ErrTxAlreadyInMempool) {
		log.Infof("%v: tx already in mempool", txid)
		return nil
	}

	return rpcErr
}

// removeUnminedTx removes a tx from the unconfirmed store.
func (w *Wallet) removeUnminedTx(ctx context.Context, tx *wire.MsgTx) error {
	params := db.DeleteTxParams{
		WalletID: w.ID(),
		Tx:       tx,
	}
	err := w.store.DeleteTx(ctx, params)
	if err != nil {
		log.Warnf("Unable to remove invalid tx %v: %v", tx.TxHash(), err)
		return err
	}

	log.Infof("Removed invalid tx: %v", tx.TxHash())

	var txRaw bytes.Buffer
	_ = tx.Serialize(&txRaw)

	const maxTxSizeForLog = 1_000_000
	if txRaw.Len() < maxTxSizeForLog {
		log.Debugf("Removed invalid tx: %v \n hex=%x",
			newLogClosure(func() string {
				return spew.Sdump(tx)
			}), txRaw.Bytes())
	} else {
		log.Debugf("Removed invalid tx %v due to its size " +
			"being too large", tx.TxHash())
	}

	return nil
}
