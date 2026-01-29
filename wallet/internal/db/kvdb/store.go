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

// NewWalletDB creates a new kvdb-backed wallet store.
func NewWalletDB(dbConn walletdb.DB, addrStore waddrmgr.AddrStore) *WalletDB {
	return &WalletDB{
		db:        dbConn,
		addrStore: addrStore,
	}
}

// CreateDerivedAccount creates a new derived account for the given wallet.
//
// This is the kvdb backend implementation of db.AccountStore.CreateDerivedAccount.
// The logic is copied from the legacy implementation in wallet/account_manager.go.
func (w *WalletDB) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams) (*db.AccountInfo, error) {

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

	var (
		accountNum uint32
		watchOnly  bool
	)

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errors.New("missing address manager namespace")
		}

		// Fetch the scoped manager for this scope, creating it if missing.
		scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
		if err != nil {
			if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
				return err
			}

			addrSchema, err := addrSchemaForScope(params.Scope)
			if err != nil {
				return err
			}

			scopedMgr, err = w.addrStore.NewScopedKeyManager(
				ns, scope, addrSchema,
			)
			if err != nil {
				return err
			}
		}

		// Validate that the scope manager can add a new derived account.
		err = scopedMgr.CanAddAccount()
		if err != nil {
			return err
		}

		accountNum, err = scopedMgr.NewAccount(ns, params.Name)
		if err != nil {
			return err
		}

		props, err := scopedMgr.AccountProperties(ns, accountNum)
		if err != nil {
			return err
		}

		watchOnly = props.IsWatchOnly

		return nil
	})
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
		return 0, fmt.Errorf("unsupported address type %d", t)
	default:
		return 0, fmt.Errorf("unknown address type %d", t)
	}
}
