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

	errMissingWaddrmgrNamespace = errors.New("missing waddrmgr namespace")

	// waddrmgrNamespaceKey is the walletdb top-level bucket key used by the
	// address manager.
	//
	// NOTE: This must match the namespace used by the wallet package.
	waddrmgrNamespaceKey = []byte("waddrmgr")
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

// NewAddress creates and persists a new derived address for an account.
func (s *Store) NewAddress(ctx context.Context,
	params db.NewAddressParams) (btcutil.Address, error) {

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	keyScope := waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}

	manager, err := s.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.NewAddress: fetch scoped manager: %w", err,
		)
	}

	var addr btcutil.Address

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return ctxErr
		}

		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingWaddrmgrNamespace
		}

		var addrErr error

		addr, addrErr = manager.NewAddress(
			ns, params.AccountName, params.Change,
		)
		if addrErr != nil {
			return fmt.Errorf("new address: %w", addrErr)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.NewAddress: %w", err)
	}

	return addr, nil
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
