// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ImportScript imports a redeem script for a P2SH output.
func (w *Wallet) ImportScript(script []byte) (*btcutil.AddressScriptHash, error) {
	addrInfo, err := w.store.ImportAddress(context.Background(), db.ImportAddressData{
		WalletID: w.ID(),
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0044.Purpose,
			Coin:    w.chainParams.HDCoinType,
		},
		Script: script,
		Rescan: true,
	})
	if err != nil {
		// Don't care if it's already there, but still have to
		// set the p2shAddr since the address manager didn't
		// return anything useful.
		if waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress) {
			// This function will never error as it always
			// hashes the script to the correct length.
			p2shAddr, _ := btcutil.NewAddressScriptHash(
				script, w.chainParams,
			)
			return p2shAddr, nil
		}
		return nil, err
	}

	return addrInfo.Address.(*btcutil.AddressScriptHash), nil
}
