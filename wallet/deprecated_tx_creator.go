// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/walletdb"
)

// addrMgrWithChangeSource returns the address manager bucket and a legacy
// change source for deprecated transaction creation callers.
func (w *Wallet) addrMgrWithChangeSource(dbtx walletdb.ReadWriteTx,
	changeKeyScope *waddrmgr.KeyScope, account uint32) (
	walletdb.ReadWriteBucket, *txauthor.ChangeSource, error) {

	// Determine the address type for change addresses of the given
	// account.
	if changeKeyScope == nil {
		changeKeyScope = &waddrmgr.KeyScopeBIP0086
	}

	addrType := waddrmgr.ScopeAddrMap[*changeKeyScope].InternalAddrType

	// It's possible for the account to have an address schema override, so
	// prefer that if it exists.
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	scopeMgr, err := w.addrStore.FetchScopedKeyManager(*changeKeyScope)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch scoped key manager: %w", err)
	}

	accountInfo, err := scopeMgr.AccountProperties(addrmgrNs, account)
	if err != nil {
		return nil, nil, fmt.Errorf("account properties: %w", err)
	}

	if accountInfo.AddrSchema != nil {
		addrType = accountInfo.AddrSchema.InternalAddrType
	}

	// Compute the expected size of the script for the change address type.
	scriptSize, err := addrType.ScriptPubKeySize()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			addrType)
	}

	newChangeScript := func() ([]byte, error) {
		// Derive the change output script. As a hack to allow spending
		// from the imported account, change addresses are created from
		// account 0.
		var (
			changeAddr btcutil.Address
			err        error
		)
		if account == waddrmgr.ImportedAddrAccount {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, 0, *changeKeyScope,
			)
		} else {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, account, *changeKeyScope,
			)
		}

		if err != nil {
			return nil, err
		}

		return txscript.PayToAddrScript(changeAddr)
	}

	return addrmgrNs, &txauthor.ChangeSource{
		ScriptSize: scriptSize,
		NewScript:  newChangeScript,
	}, nil
}
