package sqlite

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// FindUnusedAddress is not yet implemented for the SQLite store.
func (s *Store) FindUnusedAddress(_ context.Context,
	_ db.FindUnusedAddressQuery) (btcutil.Address, error) {

	return nil, db.AddressManagerCompatNotImplemented("FindUnusedAddress")
}

// GetManagedAddress is not yet implemented for the SQLite store.
func (s *Store) GetManagedAddress(_ context.Context,
	_ db.GetManagedAddressQuery) (waddrmgr.ManagedAddress, error) {

	return nil, db.AddressManagerCompatNotImplemented("GetManagedAddress")
}

// ImportPublicKey is not yet implemented for the SQLite store.
func (s *Store) ImportPublicKey(_ context.Context,
	_ db.ImportPublicKeyParams) (btcutil.Address, error) {

	return nil, db.AddressManagerCompatNotImplemented("ImportPublicKey")
}

// ImportTaprootScript is not yet implemented for the SQLite store.
func (s *Store) ImportTaprootScript(_ context.Context,
	_ db.ImportTaprootScriptParams) (btcutil.Address, error) {

	return nil, db.AddressManagerCompatNotImplemented("ImportTaprootScript")
}

// ImportAccount is not yet implemented for the SQLite store.
func (s *Store) ImportAccount(_ context.Context,
	_ db.ImportAccountParams) (*db.AccountProperties, error) {

	return nil, db.AccountManagerCompatNotImplemented("ImportAccount")
}
