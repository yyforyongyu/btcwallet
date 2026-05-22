// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// errUnsupportedTestDoubleMethod is returned if a test unexpectedly exercises
// unsupported managed pubkey methods.
var errUnsupportedTestDoubleMethod = errors.New(
	"unsupported test double method",
)

// TestAddressStoreNewDerivedAddress verifies that kvdb.Store creates derived
// addresses through the legacy address manager.
func TestAddressStoreNewDerivedAddress(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	props := createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "addr",
	)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: "addr",
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), info.ID)
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.Equal(t, db.WitnessPubKey, info.AddrType)
	require.Equal(t, "addr", info.AccountName)
	require.Equal(t, props.AccountNumber, info.AccountID)
	require.NotEmpty(t, info.ScriptPubKey)
	require.NotEmpty(t, info.PubKey)
}

// TestManagedAddressIsWatchOnlyUnsupportedPubKey verifies that unsupported
// managed public-key address implementations are reported explicitly.
func TestManagedAddressIsWatchOnlyUnsupportedPubKey(t *testing.T) {
	t.Parallel()

	isWatchOnly, err := managedAddressIsWatchOnly(
		false, unsupportedManagedPubKeyAddress{},
	)
	require.ErrorContains(t, err, "unsupported managed pubkey address")
	require.False(t, isWatchOnly)
}

type unsupportedManagedPubKeyAddress struct {
	waddrmgr.ManagedAddress
}

// Imported reports that the unsupported test double is imported.
func (unsupportedManagedPubKeyAddress) Imported() bool {
	return true
}

// PubKey returns no public key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) PubKey() *btcec.PublicKey {
	return nil
}

// ExportPubKey returns no public key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) ExportPubKey() string {
	return ""
}

// PrivKey returns no private key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) PrivKey() (*btcec.PrivateKey, error) {
	return nil, errUnsupportedTestDoubleMethod
}

// ExportPrivKey returns no private key for the unsupported test double.
func (unsupportedManagedPubKeyAddress) ExportPrivKey() (*btcutil.WIF, error) {
	return nil, errUnsupportedTestDoubleMethod
}

// DerivationInfo returns no derivation path for the unsupported test double.
func (unsupportedManagedPubKeyAddress) DerivationInfo() (waddrmgr.KeyScope,
	waddrmgr.DerivationPath, bool) {

	return waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false
}
