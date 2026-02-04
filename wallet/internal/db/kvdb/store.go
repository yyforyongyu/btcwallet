// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db store interfaces.
package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")
)

// Store is the kvdb (walletdb) implementation of the db.Store interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// managers migrate to the new db.Store interface.
type Store struct {
	db        walletdb.DB
	addrStore waddrmgr.AddrStore
}

var _ db.Store = (*Store)(nil)

// NewStore creates a new kvdb-backed wallet store.
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

// CreateWallet is not yet implemented for kvdb.
func (s *Store) CreateWallet(ctx context.Context,
	_ db.CreateWalletParams) (*db.WalletInfo, error) {

	return nil, notImplemented(ctx, "CreateWallet")
}

// GetWallet is not yet implemented for kvdb.
func (s *Store) GetWallet(ctx context.Context, _ string) (*db.WalletInfo,
	error) {

	return nil, notImplemented(ctx, "GetWallet")
}

// ListWallets is not yet implemented for kvdb.
func (s *Store) ListWallets(ctx context.Context) ([]db.WalletInfo, error) {
	return nil, notImplemented(ctx, "ListWallets")
}

// UpdateWallet is not yet implemented for kvdb.
func (s *Store) UpdateWallet(ctx context.Context,
	_ db.UpdateWalletParams) error {

	return notImplemented(ctx, "UpdateWallet")
}

// GetEncryptedHDSeed is not yet implemented for kvdb.
func (s *Store) GetEncryptedHDSeed(ctx context.Context,
	_ uint32) ([]byte, error) {

	return nil, notImplemented(ctx, "GetEncryptedHDSeed")
}

// UpdateWalletSecrets is not yet implemented for kvdb.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	_ db.UpdateWalletSecretsParams) error {

	return notImplemented(ctx, "UpdateWalletSecrets")
}

// CreateDerivedAccount is not yet implemented for kvdb.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	_ db.CreateDerivedAccountParams) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "CreateDerivedAccount")
}

// CreateImportedAccount is not yet implemented for kvdb.
func (s *Store) CreateImportedAccount(ctx context.Context,
	_ db.CreateImportedAccountParams) (*db.AccountProperties, error) {

	return nil, notImplemented(ctx, "CreateImportedAccount")
}

// GetAccount is not yet implemented for kvdb.
func (s *Store) GetAccount(ctx context.Context,
	_ db.GetAccountQuery) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "GetAccount")
}

// ListAccounts is not yet implemented for kvdb.
func (s *Store) ListAccounts(ctx context.Context,
	_ db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return nil, notImplemented(ctx, "ListAccounts")
}

// RenameAccount is not yet implemented for kvdb.
func (s *Store) RenameAccount(ctx context.Context,
	_ db.RenameAccountParams) error {

	return notImplemented(ctx, "RenameAccount")
}
