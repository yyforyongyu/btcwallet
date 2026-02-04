// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db address store interfaces.
package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")
)

// Store is the kvdb (walletdb) implementation of the db.AddressStore interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// managers migrate to the new db interfaces.
type Store struct {
	db        walletdb.DB
	addrStore waddrmgr.AddrStore
}

var _ db.AddressStore = (*Store)(nil)

// NewStore creates a new kvdb-backed address store.
func NewStore(dbConn walletdb.DB, addrStore waddrmgr.AddrStore) *Store {
	return &Store{
		db:        dbConn,
		addrStore: addrStore,
	}
}

func notImplemented(ctx context.Context, method string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}

	return fmt.Errorf("kvdb.Store.%s: %w", method, errNotImplemented)
}

// NewAddress is not yet implemented for kvdb.
func (s *Store) NewAddress(ctx context.Context,
	_ db.NewAddressParams) (btcutil.Address, error) {

	return nil, notImplemented(ctx, "NewAddress")
}

// ImportAddress is not yet implemented for kvdb.
func (s *Store) ImportAddress(ctx context.Context,
	_ db.ImportAddressParams) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "ImportAddress")
}

// GetAddress is not yet implemented for kvdb.
func (s *Store) GetAddress(ctx context.Context,
	_ db.GetAddressQuery) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "GetAddress")
}

// ListAddresses is not yet implemented for kvdb.
func (s *Store) ListAddresses(ctx context.Context,
	_ db.ListAddressesQuery) ([]db.AddressInfo, error) {

	return nil, notImplemented(ctx, "ListAddresses")
}

// MarkAddressAsUsed is not yet implemented for kvdb.
func (s *Store) MarkAddressAsUsed(ctx context.Context,
	_ db.MarkAddressAsUsedParams) error {

	return notImplemented(ctx, "MarkAddressAsUsed")
}

// GetPrivateKey is not yet implemented for kvdb.
func (s *Store) GetPrivateKey(ctx context.Context,
	_ db.GetPrivateKeyParams) (*btcec.PrivateKey, error) {

	return nil, notImplemented(ctx, "GetPrivateKey")
}

// ListAddressTypes is not yet implemented for kvdb.
func (s *Store) ListAddressTypes(ctx context.Context) ([]db.AddressTypeInfo,
	error) {

	return nil, notImplemented(ctx, "ListAddressTypes")
}

// GetAddressType is not yet implemented for kvdb.
func (s *Store) GetAddressType(ctx context.Context,
	_ db.AddressType) (db.AddressTypeInfo, error) {

	return db.AddressTypeInfo{}, notImplemented(ctx, "GetAddressType")
}
