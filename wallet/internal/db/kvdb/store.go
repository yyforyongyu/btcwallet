// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db store interfaces.
package kvdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")

	// ErrUnsupportedAddressType is returned when an address type cannot be
	// translated to a waddrmgr.AddressType.
	ErrUnsupportedAddressType = errors.New("unsupported address type")

	// ErrUnknownAddressType is returned when an address type is not recognized.
	ErrUnknownAddressType = errors.New("unknown address type")

	// errMissingAddrMgrNamespace is returned when the waddrmgr top-level bucket
	// is missing.
	errMissingAddrMgrNamespace = errors.New("missing address manager namespace")

	// waddrmgrNamespaceKey is the top-level bucket key for the address manager.
	//
	// NOTE: This MUST match wallet.waddrmgrNamespaceKey.
	waddrmgrNamespaceKey = []byte("waddrmgr")
)

// WalletDB is the kvdb (walletdb) implementation of the db.Store interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// managers migrate to the new db.Store interface.
type WalletDB struct {
	db        walletdb.DB
	addrStore waddrmgr.AddrStore
}

var _ db.Store = (*WalletDB)(nil)

// NewWalletDB creates a new kvdb-backed wallet store.
func NewWalletDB(dbConn walletdb.DB, addrStore waddrmgr.AddrStore) *WalletDB {
	return &WalletDB{
		db:        dbConn,
		addrStore: addrStore,
	}
}

// CreateDerivedAccount creates a new derived account for the given wallet.
//
// This is the kvdb backend implementation of
// db.AccountStore.CreateDerivedAccount.
// The logic is copied from the legacy implementation in
// wallet/account_manager.go.
func (w *WalletDB) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams) (*db.AccountInfo, error) {

	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	if params.WalletID != 0 {
		return nil, fmt.Errorf("wallet %d: %w", params.WalletID,
			db.ErrWalletNotFound)
	}

	if params.Name == "" {
		return nil, db.ErrMissingAccountName
	}

	scope := waddrmgr.KeyScope{
		Purpose: params.Scope.Purpose,
		Coin:    params.Scope.Coin,
	}

	accountNum, watchOnly, err := w.createDerivedAccountTx(
		scope, params.Scope, params.Name,
	)
	if err != nil {
		return nil, err
	}

	return &db.AccountInfo{
		AccountNumber:      accountNum,
		AccountName:        params.Name,
		Origin:             db.DerivedAccount,
		ExternalKeyCount:   0,
		InternalKeyCount:   0,
		ImportedKeyCount:   0,
		ConfirmedBalance:   0,
		UnconfirmedBalance: 0,
		IsWatchOnly:        watchOnly,
		CreatedAt:          time.Now().UTC(),
		KeyScope:           params.Scope,
	}, nil
}

// CreateWallet is not yet implemented for kvdb.
func (w *WalletDB) CreateWallet(context.Context,
	db.CreateWalletParams) (*db.WalletInfo, error) {

	return nil, errNotImplemented
}

// GetWallet is not yet implemented for kvdb.
func (w *WalletDB) GetWallet(context.Context, string) (*db.WalletInfo, error) {
	return nil, errNotImplemented
}

// ListWallets is not yet implemented for kvdb.
func (w *WalletDB) ListWallets(context.Context) ([]db.WalletInfo, error) {
	return nil, errNotImplemented
}

// UpdateWallet is not yet implemented for kvdb.
func (w *WalletDB) UpdateWallet(context.Context, db.UpdateWalletParams) error {
	return errNotImplemented
}

// GetEncryptedHDSeed is not yet implemented for kvdb.
func (w *WalletDB) GetEncryptedHDSeed(context.Context, uint32) ([]byte, error) {
	return nil, errNotImplemented
}

// UpdateWalletSecrets is not yet implemented for kvdb.
func (w *WalletDB) UpdateWalletSecrets(context.Context,
	db.UpdateWalletSecretsParams) error {

	return errNotImplemented
}

// CreateImportedAccount is not yet implemented for kvdb.
func (w *WalletDB) CreateImportedAccount(context.Context,
	db.CreateImportedAccountParams) (*db.AccountProperties, error) {

	return nil, errNotImplemented
}

// GetAccount is not yet implemented for kvdb.
func (w *WalletDB) GetAccount(context.Context,
	db.GetAccountQuery) (*db.AccountInfo, error) {

	return nil, errNotImplemented
}

// ListAccounts is not yet implemented for kvdb.
func (w *WalletDB) ListAccounts(context.Context,
	db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return nil, errNotImplemented
}

// RenameAccount is not yet implemented for kvdb.
func (w *WalletDB) RenameAccount(context.Context,
	db.RenameAccountParams) error {

	return errNotImplemented
}

func (w *WalletDB) createDerivedAccountTx(scope waddrmgr.KeyScope,
	keyScope db.KeyScope, name string) (uint32, bool, error) {

	var (
		accountNum uint32
		watchOnly  bool
	)

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrMgrNamespace
		}

		scopedMgr, err := w.fetchOrCreateScopedMgr(ns, scope, keyScope)
		if err != nil {
			return err
		}

		err = scopedMgr.CanAddAccount()
		if err != nil {
			return fmt.Errorf("can add account: %w", err)
		}

		accountNum, err = scopedMgr.NewAccount(ns, name)
		if err != nil {
			return fmt.Errorf("new account: %w", err)
		}

		props, err := scopedMgr.AccountProperties(ns, accountNum)
		if err != nil {
			return fmt.Errorf("account properties: %w", err)
		}

		watchOnly = props.IsWatchOnly

		return nil
	})
	if err != nil {
		return 0, false, fmt.Errorf("create derived account: %w", err)
	}

	return accountNum, watchOnly, nil
}

func (w *WalletDB) fetchOrCreateScopedMgr(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope, keyScope db.KeyScope) (waddrmgr.AccountStore,
	error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err == nil {
		return scopedMgr, nil
	}

	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return nil, fmt.Errorf("fetch scoped key manager: %w", err)
	}

	addrSchema, err := addrSchemaForScope(keyScope)
	if err != nil {
		return nil, err
	}

	scopedMgr, err = w.addrStore.NewScopedKeyManager(ns, scope, addrSchema)
	if err != nil {
		return nil, fmt.Errorf("new scoped key manager: %w", err)
	}

	return scopedMgr, nil
}

func addrSchemaForScope(scope db.KeyScope) (waddrmgr.ScopeAddrSchema, error) {
	addrSchema, exists := db.ScopeAddrMap[scope]
	if !exists {
		return waddrmgr.ScopeAddrSchema{}, fmt.Errorf("%w: scope %d/%d",
			db.ErrUnknownKeyScope, scope.Purpose, scope.Coin)
	}

	externalAddrType, err := toWaddrmgrAddrType(addrSchema.ExternalAddrType)
	if err != nil {
		return waddrmgr.ScopeAddrSchema{}, fmt.Errorf("external addr type: %w",
			err)
	}

	internalAddrType, err := toWaddrmgrAddrType(addrSchema.InternalAddrType)
	if err != nil {
		return waddrmgr.ScopeAddrSchema{}, fmt.Errorf("internal addr type: %w",
			err)
	}

	return waddrmgr.ScopeAddrSchema{
		ExternalAddrType: externalAddrType,
		InternalAddrType: internalAddrType,
	}, nil
}

func toWaddrmgrAddrType(t db.AddressType) (waddrmgr.AddressType, error) {
	switch t {
	case db.RawPubKey:
		return waddrmgr.RawPubKey, nil
	case db.PubKeyHash:
		return waddrmgr.PubKeyHash, nil
	case db.ScriptHash:
		return waddrmgr.Script, nil
	case db.NestedWitnessPubKey:
		return waddrmgr.NestedWitnessPubKey, nil
	case db.WitnessPubKey:
		return waddrmgr.WitnessPubKey, nil
	case db.WitnessScript:
		return waddrmgr.WitnessScript, nil
	case db.TaprootPubKey:
		return waddrmgr.TaprootPubKey, nil
	case db.Anchor:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedAddressType, t)
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnknownAddressType, t)
	}
}
