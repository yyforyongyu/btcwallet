package kvdb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// GetAccount retrieves one account through the legacy address-manager path.
func (s *Store) GetAccount(_ context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetAccount: %w", errMissingLegacyAddrStore,
		)
	}

	err := kvdbValidateGetAccountQuery(query)
	if err != nil {
		return nil, err
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(query.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetAccount: fetch scoped manager: %w", err,
		)
	}

	var info *db.AccountInfo

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		accountNum, err := kvdbLookupAccount(ns, manager, query)
		if err != nil {
			return err
		}

		props, err := manager.AccountProperties(ns, accountNum)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
				return db.ErrAccountNotFound
			}

			return fmt.Errorf("account properties: %w", err)
		}

		info = kvdbAccountInfoFromProps(props)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetAccount: %w", err)
	}

	return info, nil
}

// CreateDerivedAccount creates one derived account through the legacy address-
// manager path.
func (s *Store) CreateDerivedAccount(_ context.Context,
	params db.CreateDerivedAccountParams) (*db.AccountInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.CreateDerivedAccount: %w",
			errMissingLegacyAddrStore,
		)
	}

	err := params.Validate()
	if err != nil {
		return nil, fmt.Errorf("validate params: %w", err)
	}

	var info *db.AccountInfo

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		manager, err := kvdbScopedManager(
			ns, s.addrStore, params.Scope,
		)
		if err != nil {
			return err
		}

		accountNum, err := manager.NewAccount(ns, params.Name)
		if err != nil {
			return fmt.Errorf("new account: %w", err)
		}

		props, err := manager.AccountProperties(ns, accountNum)
		if err != nil {
			return fmt.Errorf("account properties: %w", err)
		}

		info = kvdbAccountInfoFromProps(props)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.CreateDerivedAccount: %w", err)
	}

	return info, nil
}

// ImportAccount imports one account through the legacy account-manager path.
func (s *Store) ImportAccount(_ context.Context,
	params db.ImportAccountParams) (*db.AccountProperties, error) {

	err := kvdbValidateImportAccountParams(s.addrStore, params)
	if err != nil {
		return nil, err
	}

	var props *db.AccountProperties

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		var txErr error

		props, txErr = kvdbImportAccountProperties(
			ns, s.addrStore, params,
		)
		if txErr != nil {
			return txErr
		}

		if params.DryRun {
			return walletdb.ErrDryRunRollBack
		}

		return nil
	})
	if err != nil &&
		(!params.DryRun || !errors.Is(err, walletdb.ErrDryRunRollBack)) {

		return nil, fmt.Errorf("kvdb.Store.ImportAccount: %w", err)
	}

	return props, nil
}

func kvdbValidateImportAccountParams(addrStore legacyAddrStore,
	params db.ImportAccountParams) error {

	if addrStore == nil {
		return fmt.Errorf(
			"kvdb.Store.ImportAccount: %w", errMissingLegacyAddrStore,
		)
	}

	if params.AccountKey == nil {
		return db.ErrMissingAccountPublicKey
	}

	return nil
}

func kvdbImportAccountProperties(ns walletdb.ReadWriteBucket,
	addrStore legacyAddrStore,
	params db.ImportAccountParams) (*db.AccountProperties, error) {

	scopedMgr, err := kvdbImportAccountManager(
		ns, addrStore, params.Scope, params.AddrSchema,
	)
	if err != nil {
		return nil, err
	}

	accountNum, err := scopedMgr.NewAccountWatchingOnly(
		ns,
		params.Name,
		params.AccountKey,
		params.MasterFingerprint,
		kvdbImportedAddrSchema(params.AddrSchema),
	)
	if err != nil {
		return nil, fmt.Errorf("new account watching-only: %w", err)
	}

	legacyProps, err := scopedMgr.AccountProperties(ns, accountNum)
	if err != nil {
		return nil, fmt.Errorf("account properties: %w", err)
	}

	if params.DryRun {
		legacyProps, err = kvdbImportAccountDryRun(ns, legacyProps, scopedMgr)
		if err != nil {
			return nil, err
		}
	}

	return kvdbAccountPropertiesFromProps(legacyProps), nil
}

func kvdbImportedAddrSchema(
	addrSchema *db.ScopeAddrSchema,
) *waddrmgr.ScopeAddrSchema {

	if addrSchema == nil {
		return nil
	}

	return kvdbWaddrmgrScopeAddrSchema(*addrSchema)
}

// ListAccounts lists accounts through the legacy address-manager path.
func (s *Store) ListAccounts(_ context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ListAccounts: %w", errMissingLegacyAddrStore,
		)
	}

	if query.Scope != nil && query.Name != nil {
		return nil, db.ErrInvalidAccountQuery
	}

	var infos []db.AccountInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		scopes, err := kvdbAccountManagers(s.addrStore, query.Scope)
		if err != nil {
			return err
		}

		for _, manager := range scopes {
			scopeInfos, err := kvdbListScopeAccounts(ns, manager, query.Name)
			if err != nil {
				return err
			}

			infos = append(infos, scopeInfos...)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListAccounts: %w", err)
	}

	kvdbSortAccountInfos(infos)

	return infos, nil
}

// RenameAccount renames one account through the legacy address-manager path.
func (s *Store) RenameAccount(_ context.Context,
	params db.RenameAccountParams) error {

	if s.addrStore == nil {
		return fmt.Errorf(
			"kvdb.Store.RenameAccount: %w", errMissingLegacyAddrStore,
		)
	}

	err := kvdbValidateRenameAccountParams(params)
	if err != nil {
		return err
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(params.Scope),
	)
	if err != nil {
		return fmt.Errorf(
			"kvdb.Store.RenameAccount: fetch scoped manager: %w", err,
		)
	}

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		accountNum, err := kvdbRenameAccountNumber(ns, manager, params)
		if err != nil {
			return err
		}

		err = manager.RenameAccount(ns, accountNum, params.NewName)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
				return db.ErrAccountNotFound
			}

			return fmt.Errorf("rename account: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.RenameAccount: %w", err)
	}

	return nil
}

// kvdbValidateGetAccountQuery checks that exactly one account selector was set.
func kvdbValidateGetAccountQuery(query db.GetAccountQuery) error {
	if query.Name == nil && query.AccountNumber == nil {
		return db.ErrInvalidAccountQuery
	}

	if query.Name != nil && query.AccountNumber != nil {
		return db.ErrInvalidAccountQuery
	}

	return nil
}

// kvdbValidateRenameAccountParams checks that the rename query is well formed.
func kvdbValidateRenameAccountParams(params db.RenameAccountParams) error {
	if params.NewName == "" {
		return db.ErrMissingAccountName
	}

	if params.OldName == "" && params.AccountNumber == nil {
		return db.ErrInvalidAccountQuery
	}

	if params.OldName != "" && params.AccountNumber != nil {
		return db.ErrInvalidAccountQuery
	}

	return nil
}

// kvdbAccountManagers returns the relevant scoped managers for one account
// query.
func kvdbAccountManagers(addrStore legacyAddrStore,
	scope *db.KeyScope) ([]waddrmgr.AccountStore, error) {

	if scope != nil {
		manager, err := addrStore.FetchScopedKeyManager(
			waddrmgr.KeyScope(*scope),
		)
		if err != nil {
			return nil, fmt.Errorf("fetch scoped manager: %w", err)
		}

		return []waddrmgr.AccountStore{manager}, nil
	}

	return addrStore.ActiveScopedKeyManagers(), nil
}

// kvdbLookupAccount resolves one account number from a GetAccount query.
func kvdbLookupAccount(ns walletdb.ReadBucket, manager waddrmgr.AccountStore,
	query db.GetAccountQuery) (uint32, error) {

	if query.AccountNumber != nil {
		return *query.AccountNumber, nil
	}

	accountNum, err := manager.LookupAccount(ns, *query.Name)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return 0, db.ErrAccountNotFound
		}

		return 0, fmt.Errorf("lookup account: %w", err)
	}

	return accountNum, nil
}

// kvdbRenameAccountNumber resolves the target account number for a rename.
func kvdbRenameAccountNumber(ns walletdb.ReadBucket,
	manager waddrmgr.AccountStore,
	params db.RenameAccountParams) (uint32, error) {

	if params.AccountNumber != nil {
		return *params.AccountNumber, nil
	}

	accountNum, err := manager.LookupAccount(ns, params.OldName)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return 0, db.ErrAccountNotFound
		}

		return 0, fmt.Errorf("lookup account: %w", err)
	}

	return accountNum, nil
}

// kvdbListScopeAccounts lists all matching accounts from one scoped manager.
func kvdbListScopeAccounts(ns walletdb.ReadBucket,
	manager waddrmgr.AccountStore,
	name *string) ([]db.AccountInfo, error) {

	if name != nil {
		accountNum, err := manager.LookupAccount(ns, *name)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
				return nil, nil
			}

			return nil, fmt.Errorf("lookup account: %w", err)
		}

		props, err := manager.AccountProperties(ns, accountNum)
		if err != nil {
			return nil, fmt.Errorf("account properties: %w", err)
		}

		return []db.AccountInfo{*kvdbAccountInfoFromProps(props)}, nil
	}

	var infos []db.AccountInfo

	err := manager.ForEachAccount(ns, func(accountNum uint32) error {
		props, err := manager.AccountProperties(ns, accountNum)
		if err != nil {
			return fmt.Errorf("account properties: %w", err)
		}

		infos = append(infos, *kvdbAccountInfoFromProps(props))

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list accounts in scope: %w", err)
	}

	return infos, nil
}

// kvdbAccountInfoFromProps adapts one legacy account properties record into the
// db account view used by store callers.
func kvdbAccountInfoFromProps(
	props *waddrmgr.AccountProperties,
) *db.AccountInfo {

	origin := db.DerivedAccount
	accountNum := props.AccountNumber

	if props.AccountPubKey == nil ||
		props.AccountNumber == waddrmgr.ImportedAddrAccount {

		origin = db.ImportedAccount
		accountNum = 0
	}

	return db.BuildAccountInfo(
		accountNum,
		props.AccountName,
		origin,
		props.ExternalKeyCount,
		props.InternalKeyCount,
		props.ImportedKeyCount,
		props.IsWatchOnly,
		time.Time{},
		db.KeyScope(props.KeyScope),
	)
}

// kvdbAccountPropertiesFromProps adapts one legacy account properties record
// into the db account-properties view used by store callers.
func kvdbAccountPropertiesFromProps(
	props *waddrmgr.AccountProperties,
) *db.AccountProperties {

	origin := db.DerivedAccount

	accountNum := props.AccountNumber
	if props.AccountPubKey == nil ||
		accountNum == waddrmgr.ImportedAddrAccount {

		accountNum = 0
		origin = db.ImportedAccount
	}

	var addrSchema *db.ScopeAddrSchema
	if props.AddrSchema != nil {
		addrSchema = &db.ScopeAddrSchema{
			InternalAddrType: db.AddressType(
				props.AddrSchema.InternalAddrType,
			),
			ExternalAddrType: db.AddressType(
				props.AddrSchema.ExternalAddrType,
			),
		}
	}

	return &db.AccountProperties{
		AccountNumber:        accountNum,
		AccountName:          props.AccountName,
		Origin:               origin,
		ExternalKeyCount:     props.ExternalKeyCount,
		InternalKeyCount:     props.InternalKeyCount,
		ImportedKeyCount:     props.ImportedKeyCount,
		MasterKeyFingerprint: props.MasterKeyFingerprint,
		KeyScope:             db.KeyScope(props.KeyScope),
		IsWatchOnly:          props.IsWatchOnly,
		AddrSchema:           addrSchema,
	}
}

// kvdbScopedManager returns one scoped manager, creating the default scope on
// demand when the legacy root manager does not have it yet.
func kvdbScopedManager(ns walletdb.ReadWriteBucket, addrStore legacyAddrStore,
	scope db.KeyScope) (waddrmgr.AccountStore, error) {

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
	if err == nil {
		return manager, nil
	}

	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return nil, fmt.Errorf("fetch scoped manager: %w", err)
	}

	schema, ok := db.ScopeAddrMap[scope]
	if !ok {
		return nil, fmt.Errorf("scope %d/%d: %w", scope.Purpose, scope.Coin,
			db.ErrUnknownKeyScope)
	}

	manager, err = addrStore.NewScopedKeyManager(ns, waddrmgr.KeyScope(scope),
		waddrmgr.ScopeAddrSchema{
			InternalAddrType: waddrmgr.AddressType(schema.InternalAddrType),
			ExternalAddrType: waddrmgr.AddressType(schema.ExternalAddrType),
		})
	if err != nil {
		return nil, fmt.Errorf("create scoped manager: %w", err)
	}

	return manager, nil
}

// kvdbImportAccountManager returns one scoped manager for account import,
// creating the scope with the requested address schema when necessary.
func kvdbImportAccountManager(ns walletdb.ReadWriteBucket,
	addrStore legacyAddrStore, scope db.KeyScope,
	addrSchema *db.ScopeAddrSchema) (waddrmgr.AccountStore, error) {

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
	if err == nil {
		return manager, nil
	}

	if !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound) {
		return nil, fmt.Errorf("fetch scoped manager: %w", err)
	}

	var schema db.ScopeAddrSchema
	if addrSchema != nil {
		schema = *addrSchema
	} else {
		var ok bool

		schema, ok = db.ScopeAddrMap[scope]
		if !ok {
			return nil, fmt.Errorf("scope %d/%d: %w", scope.Purpose,
				scope.Coin, db.ErrUnknownKeyScope)
		}
	}

	manager, err = addrStore.NewScopedKeyManager(
		ns, waddrmgr.KeyScope(scope),
		*kvdbWaddrmgrScopeAddrSchema(schema),
	)
	if err != nil {
		return nil, fmt.Errorf("create scoped manager: %w", err)
	}

	return manager, nil
}

// kvdbWaddrmgrScopeAddrSchema converts one db scope schema to the legacy
// waddrmgr schema type.
func kvdbWaddrmgrScopeAddrSchema(
	schema db.ScopeAddrSchema,
) *waddrmgr.ScopeAddrSchema {

	return &waddrmgr.ScopeAddrSchema{
		InternalAddrType: waddrmgr.AddressType(schema.InternalAddrType),
		ExternalAddrType: waddrmgr.AddressType(schema.ExternalAddrType),
	}
}

// kvdbImportAccountDryRun validates one imported account by deriving one
// external and one internal address before rolling back the transaction.
func kvdbImportAccountDryRun(ns walletdb.ReadWriteBucket,
	props *waddrmgr.AccountProperties,
	scopedMgr waddrmgr.AccountStore) (*waddrmgr.AccountProperties, error) {

	defer scopedMgr.InvalidateAccountCache(props.AccountNumber)

	_, err := scopedMgr.NextExternalAddresses(ns, props.AccountNumber, 1)
	if err != nil {
		return nil, fmt.Errorf("next external addresses: %w", err)
	}

	_, err = scopedMgr.NextInternalAddresses(ns, props.AccountNumber, 1)
	if err != nil {
		return nil, fmt.Errorf("next internal addresses: %w", err)
	}

	props, err = scopedMgr.AccountProperties(ns, props.AccountNumber)
	if err != nil {
		return nil, fmt.Errorf("account properties: %w", err)
	}

	return props, nil
}

// kvdbSortAccountInfos keeps account listings stable and mirrors SQL ordering:
// scope first, then derived accounts by account number, with imported accounts
// last.
func kvdbSortAccountInfos(infos []db.AccountInfo) {
	sort.Slice(infos, func(i, j int) bool {
		left := infos[i]
		right := infos[j]

		if left.KeyScope.Purpose != right.KeyScope.Purpose {
			return left.KeyScope.Purpose < right.KeyScope.Purpose
		}

		if left.KeyScope.Coin != right.KeyScope.Coin {
			return left.KeyScope.Coin < right.KeyScope.Coin
		}

		if left.Origin != right.Origin {
			return left.Origin == db.DerivedAccount
		}

		if left.AccountNumber != right.AccountNumber {
			return left.AccountNumber < right.AccountNumber
		}

		return left.AccountName < right.AccountName
	})
}
