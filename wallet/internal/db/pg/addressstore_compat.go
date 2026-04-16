package pg

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// FindUnusedAddress is not yet implemented for the PostgreSQL store.
func (s *Store) FindUnusedAddress(_ context.Context,
	_ db.FindUnusedAddressQuery) (btcutil.Address, error) {

	return nil, db.AddressManagerCompatNotImplemented("FindUnusedAddress")
}

// GetManagedAddress is not yet implemented for the PostgreSQL store.
func (s *Store) GetManagedAddress(_ context.Context,
	_ db.GetManagedAddressQuery) (waddrmgr.ManagedAddress, error) {

	return nil, db.AddressManagerCompatNotImplemented("GetManagedAddress")
}

// GetManagedPubKeyAddressByPath is not yet implemented for the PostgreSQL
// store.
func (s *Store) GetManagedPubKeyAddressByPath(_ context.Context,
	_ db.SignerPathQuery) (waddrmgr.ManagedPubKeyAddress, error) {

	return nil, db.SignerCompatNotImplemented("GetManagedPubKeyAddressByPath")
}

// GetManagedPubKeyAddress is not yet implemented for the PostgreSQL store.
func (s *Store) GetManagedPubKeyAddress(_ context.Context,
	_ db.SignerAddressQuery) (waddrmgr.ManagedPubKeyAddress, error) {

	return nil, db.SignerCompatNotImplemented("GetManagedPubKeyAddress")
}

// GetPrivKeyByPath is not yet implemented for the PostgreSQL store.
func (s *Store) GetPrivKeyByPath(_ context.Context,
	_ db.SignerPathQuery) (*btcec.PrivateKey, error) {

	return nil, db.SignerCompatNotImplemented("GetPrivKeyByPath")
}

// GetPrivKeyForAddress is not yet implemented for the PostgreSQL store.
func (s *Store) GetPrivKeyForAddress(_ context.Context,
	_ db.SignerAddressQuery) (*btcec.PrivateKey, error) {

	return nil, db.SignerCompatNotImplemented("GetPrivKeyForAddress")
}

// ImportPublicKey is not yet implemented for the PostgreSQL store.
func (s *Store) ImportPublicKey(_ context.Context,
	_ db.ImportPublicKeyParams) (btcutil.Address, error) {

	return nil, db.AddressManagerCompatNotImplemented("ImportPublicKey")
}

// ImportTaprootScript is not yet implemented for the PostgreSQL store.
func (s *Store) ImportTaprootScript(_ context.Context,
	_ db.ImportTaprootScriptParams) (btcutil.Address, error) {

	return nil, db.AddressManagerCompatNotImplemented("ImportTaprootScript")
}

// ImportAccount is not yet implemented for the PostgreSQL store.
func (s *Store) ImportAccount(_ context.Context,
	_ db.ImportAccountParams) (*db.AccountProperties, error) {

	return nil, db.AccountManagerCompatNotImplemented("ImportAccount")
}
