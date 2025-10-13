// Copyright (c) 2016 The Decred developers
// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type unstableAPI struct {
	w *Wallet
}

// UnstableAPI exposes additional unstable public APIs for a Wallet.  These APIs
// may be changed or removed at any time.  Currently this type exists to ease
// the transition (particularly for the legacy JSON-RPC server) from using
// exported manager packages to a unified wallet package that exposes all
// functionality by itself.  New code should not be written using this API.
func UnstableAPI(w *Wallet) unstableAPI { return unstableAPI{w} } // nolint:golint

func (u unstableAPI) TxDetails(hash *chainhash.Hash) (*wtxmgr.TxDetails, error) {
	return u.w.fetchTxDetails(context.Background(), hash)
}

func (u unstableAPI) RangeTransactions(begin, end int32, f func([]wtxmgr.TxDetails) (bool, error)) error {
	txns, err := u.w.ListTxns(context.Background(), begin, end)
	if err != nil {
		return err
	}

	details := make([]wtxmgr.TxDetails, len(txns))
	for i, tx := range txns {
		// This is not ideal, but the Unstable API requires
		// wtxmgr.TxDetails, so we need to fetch them one by one.
		detail, err := u.w.fetchTxDetails(context.Background(), &tx.Hash)
		if err != nil {
			return err
		}
		details[i] = *detail
	}

	_, err = f(details)
	return err
}