// Copyright (c) 2015-2020 The btcsuite developers
// Use of this source code is governed by an ISC
package wallet

import ()

var (
	// bucketTxLabels is the name of the label sub bucket of the wtxmgr
	// top level bucket that stores the mapping between a txid and a
	// user-defined transaction label.
	bucketTxLabels = []byte("l")
)

// DropTransactionHistory completely removes and re-creates the transaction
// manager namespace from the given wallet database. This can be used to force
// a full chain rescan of all wallet transaction and UTXO data. User-defined
// transaction labels can optionally be kept by setting keepLabels to true.
func (w *Wallet) DropTransactionHistory(keepLabels bool) error {
	log.Infof("Dropping btcwallet transaction history")
	// TODO(yy): implement this
	return nil
}