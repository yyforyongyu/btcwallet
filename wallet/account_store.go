// Copyright (c) 2023 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// accountStore is an implementation of the waddrmgr.AccountStore interface
// that uses the wallet's internal database.
type accountStore struct {
	store    db.Store
	walletID uint64
	scope    waddrmgr.KeyScope
}

// newAccountStore creates a new accountStore.
func newAccountStore(store db.Store, walletID uint64,
	scope waddrmgr.KeyScope) *accountStore {
	return &accountStore{
		store:    store,
		walletID: walletID,
		scope:    scope,
	}
}

// Scope returns the key scope of the account store.
func (s *accountStore) Scope() waddrmgr.KeyScope {
	return s.scope
}

// AddrSchema returns the address schema of the account store.
func (s *accountStore) AddrSchema() waddrmgr.ScopeAddrSchema {
	// TODO(yy): implement
	return waddrmgr.ScopeAddrSchema{}
}

// CanAddAccount returns an error if a new account cannot be added to the
// account store.
func (s *accountStore) CanAddAccount() error {
	// TODO(yy): implement
	return nil
}

// LastAccount returns the last account number of the account store.
func (s *accountStore) LastAccount(ns walletdb.ReadBucket) (uint32, error) {
	// TODO(yy): implement
	return 0, nil
}

// ForEachAccount calls a function for each account in the account store.
func (s *accountStore) ForEachAccount(ns walletdb.ReadBucket,
	fn func(account uint32) error) error {
	// TODO(yy): implement
	return nil
}

// ForEachAccountAddress calls a function for each address of an account.
func (s *accountStore) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr waddrmgr.ManagedAddress) error) error {
	// TODO(yy): implement
	return nil
}

// LastAddress returns the last address of an account.
func (s *accountStore) LastAddress(ns walletdb.ReadBucket, account uint32,
	branch uint32) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// ContainsAddress returns true if the account store contains the given
// address.
func (s *accountStore) ContainsAddress(ns walletdb.ReadBucket,
	account uint32, address btcutil.Address) bool {
	// TODO(yy): implement
	return false
}

// IsWatchOnlyAccount returns true if the account is a watch-only account.
func (s *accountStore) IsWatchOnlyAccount(ns walletdb.ReadBucket,
	account uint32) (bool, error) {
	// TODO(yy): implement
	return false, nil
}

// ExtendExternalAddresses extends the external addresses of an account.
func (s *accountStore) ExtendExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) error {

	dbScope := db.KeyScope{
		Purpose: s.scope.Purpose,
		Coin:    s.scope.Coin,
	}
	info, err := s.store.GetAccount(
		context.Background(), db.GetAccountQuery{
			WalletID:      s.walletID,
			Scope:         dbScope,
			AccountNumber: &account,
		},
	)
	if err != nil {
		return err
	}

	for i := uint32(0); i < count; i++ {
		_, err := s.store.CreateAddress(
			context.Background(), db.CreateAddressParams{
				WalletID:    s.walletID,
				AccountName: info.AccountName,
				Scope:       dbScope,
				Change:      false,
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExtendInternalAddresses extends the internal addresses of an account.
func (s *accountStore) ExtendInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) error {

	dbScope := db.KeyScope{
		Purpose: s.scope.Purpose,
		Coin:    s.scope.Coin,
	}
	info, err := s.store.GetAccount(
		context.Background(), db.GetAccountQuery{
			WalletID:      s.walletID,
			Scope:         dbScope,
			AccountNumber: &account,
		},
	)
	if err != nil {
		return err
	}

	for i := uint32(0); i < count; i++ {
		_, err := s.store.CreateAddress(
			context.Background(), db.CreateAddressParams{
				WalletID:    s.walletID,
				AccountName: info.AccountName,
				Scope:       dbScope,
				Change:      true,
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewAccount creates a new account.
func (s *accountStore) NewAccount(ns walletdb.ReadWriteBucket,
	name string) (uint32, error) {
	// TODO(yy): implement
	return 0, nil
}

// RenameAccount renames an account.
func (s *accountStore) RenameAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {
	// TODO(yy): implement
	return nil
}

// AccountName returns the name of an account.
func (s *accountStore) AccountName(ns walletdb.ReadBucket,
	account uint32) (string, error) {
	// TODO(yy): implement
	return "", nil
}

// AccountProperties returns the properties of an account.
func (s *accountStore) AccountProperties(ns walletdb.ReadBucket,
	account uint32) (*waddrmgr.AccountProperties, error) {
	// TODO(yy): implement
	return nil, nil
}

// LookupAccount returns the account number for a given account name.
func (s *accountStore) LookupAccount(ns walletdb.ReadBucket,
	name string) (uint32, error) {
	// TODO(yy): implement
	return 0, nil
}

// NewAddress creates a new address.
func (s *accountStore) NewAddress(ns walletdb.ReadWriteBucket,
	account string, internal bool) (btcutil.Address, error) {
	// TODO(yy): implement
	return nil, nil
}

// NewExternalAddress creates a new external address.
func (s *accountStore) NewExternalAddress(ns walletdb.ReadWriteBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// NewInternalAddress creates a new internal address.
func (s *accountStore) NewInternalAddress(ns walletdb.ReadWriteBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// ImportPublicKey imports a public key.
func (s *accountStore) ImportPublicKey(ns walletdb.ReadWriteBucket,
	pubKey *btcec.PublicKey,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// ImportScript imports a script.
func (s *accountStore) ImportScript(ns walletdb.ReadWriteBucket,
	script []byte,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedScriptAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// Address returns the managed address for a given address.
func (s *accountStore) Address(ns walletdb.ReadBucket,
	address btcutil.Address) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// AddrAccount returns the account for a given address.
func (s *accountStore) AddrAccount(ns walletdb.ReadBucket,
	address btcutil.Address) (uint32, error) {
	// TODO(yy): implement
	return 0, nil
}

// MarkUsed marks an address as used.
func (s *accountStore) MarkUsed(ns walletdb.ReadWriteBucket,
	address btcutil.Address) error {
	// TODO(yy): implement
	return nil
}

// ForEachActiveAddress calls a function for each active address.
func (s *accountStore) ForEachActiveAddress(ns walletdb.ReadBucket,
	fn func(address btcutil.Address) error) error {
	// TODO(yy): implement
	return nil
}

// ForEachInternalActiveAddress calls a function for each internal active
// address.
func (s *accountStore) ForEachInternalActiveAddress(ns walletdb.ReadBucket,
	fn func(address btcutil.Address) error) error {
	// TODO(yy): implement
	return nil
}

// DeriveFromKeyPath derives a managed address from a BIP-32 derivation path.
func (s *accountStore) DeriveFromKeyPath(ns walletdb.ReadBucket,
	path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error) {
	dbScope := db.KeyScope{
		Purpose: s.scope.Purpose,
		Coin:    s.scope.Coin,
	}
	return s.store.DeriveFromKeyPath(context.Background(), dbScope, path)
}

// DeriveFromKeyPathCache derives a managed address from a BIP-32 derivation
// path, caching the result.
func (s *accountStore) DeriveFromKeyPathCache(
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {
	// TODO(yy): implement
	return nil, nil
}

// ImportPrivateKey imports a private key.
func (s *accountStore) ImportPrivateKey(ns walletdb.ReadWriteBucket,
	wif *btcutil.WIF, bs *waddrmgr.BlockStamp) (waddrmgr.ManagedPubKeyAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// ImportTaprootScript imports a taproot script.
func (s *accountStore) ImportTaprootScript(ns walletdb.ReadWriteBucket,
	script *waddrmgr.Tapscript, bs *waddrmgr.BlockStamp, privKeyType byte,
	isInternal bool) (waddrmgr.ManagedTaprootScriptAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// InvalidateAccountCache invalidates the account cache.
func (s *accountStore) InvalidateAccountCache(account uint32) {
	// TODO(yy): implement
}

// LastExternalAddress returns the last external address of an account.
func (s *accountStore) LastExternalAddress(ns walletdb.ReadBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// LastInternalAddress returns the last internal address of an account.
func (s *accountStore) LastInternalAddress(ns walletdb.ReadBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// NewAccountWatchingOnly creates a new watching-only account.
func (s *accountStore) NewAccountWatchingOnly(ns walletdb.ReadWriteBucket,
	name string, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) (uint32, error) {
	// TODO(yy): implement
	return 0, nil
}

// NewRawAccount creates a new account with a raw account number.
func (s *accountStore) NewRawAccount(ns walletdb.ReadWriteBucket,
	account uint32) error {
	// TODO(yy): implement
	return nil
}

// NextExternalAddresses returns the next external addresses for an account.
func (s *accountStore) NextExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) ([]waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}

// NextInternalAddresses returns the next internal addresses for an account.
func (s *accountStore) NextInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) ([]waddrmgr.ManagedAddress, error) {
	// TODO(yy): implement
	return nil, nil
}
