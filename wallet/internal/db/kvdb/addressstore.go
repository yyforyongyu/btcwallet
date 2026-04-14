package kvdb

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
)

const legacyUnknownAccountName = "unknown"

var (
	errMissingAddrmgrNamespace = errors.New("missing waddrmgr namespace")
	errMissingLegacyAddrStore  = errors.New("missing addr store")
	errNoAddressInPkScript     = errors.New("pkScript has no address")
	errMissingAddressQuery     = errors.New(
		"managed address query missing address",
	)
	errStopUnusedAddrScan  = errors.New("stop unused address scan")
	errUnsupportedAddrType = errors.New("unsupported legacy address type")
)

var waddrmgrNamespaceKey = []byte("waddrmgr")

// NewDerivedAddress creates one new derived address through the legacy
// address-manager path and adapts it to db.AddressInfo.
func (s *Store) NewDerivedAddress(_ context.Context,
	params db.NewDerivedAddressParams,
	_ db.AddressDerivationFunc) (*db.AddressInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.NewDerivedAddress: %w", errMissingLegacyAddrStore,
		)
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(params.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.NewDerivedAddress: fetch scoped manager: %w", err,
		)
	}

	var info *db.AddressInfo

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		addr, err := manager.NewAddress(ns, params.AccountName, params.Change)
		if err != nil {
			return fmt.Errorf("new address: %w", err)
		}

		managedAddr, err := s.addrStore.Address(ns, addr)
		if err != nil {
			return fmt.Errorf("lookup managed address: %w", err)
		}

		info, err = kvdbAddressInfo(managedAddr)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.NewDerivedAddress: %w", err)
	}

	return info, nil
}

// NewImportedAddress is not yet implemented for kvdb.
func (s *Store) NewImportedAddress(ctx context.Context,
	_ db.NewImportedAddressParams) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "NewImportedAddress")
}

// ImportPublicKey imports one public key through the legacy address-manager
// path and returns the imported address.
func (s *Store) ImportPublicKey(_ context.Context,
	params db.ImportPublicKeyParams) (btcutil.Address, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ImportPublicKey: %w", errMissingLegacyAddrStore,
		)
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(params.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ImportPublicKey: fetch scoped manager: %w", err,
		)
	}

	pubKey, err := btcec.ParsePubKey(params.SerializedPubKey)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ImportPublicKey: parse public key: %w", err,
		)
	}

	var addr btcutil.Address

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err := manager.ImportPublicKey(ns, pubKey, nil)
		if err != nil {
			return fmt.Errorf("import public key: %w", err)
		}

		addr = managedAddr.Address()

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ImportPublicKey: %w", err)
	}

	return addr, nil
}

// ImportTaprootScript imports one taproot script through the legacy
// address-manager path and returns the imported address.
func (s *Store) ImportTaprootScript(_ context.Context,
	params db.ImportTaprootScriptParams) (btcutil.Address, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ImportTaprootScript: %w", errMissingLegacyAddrStore,
		)
	}

	manager, err := s.addrStore.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0086)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ImportTaprootScript: fetch scoped manager: %w", err,
		)
	}

	var addr btcutil.Address

	err = walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err := manager.ImportTaprootScript(
			ns, &params.Tapscript, &params.SyncedTo,
			params.WitnessVersion, params.IsSecretScript,
		)
		if err != nil {
			return fmt.Errorf("import taproot script: %w", err)
		}

		addr = managedAddr.Address()

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ImportTaprootScript: %w", err,
		)
	}

	return addr, nil
}

// GetAddress is not yet implemented for kvdb.
func (s *Store) GetAddress(ctx context.Context,
	_ db.GetAddressQuery) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "GetAddress")
}

// FindUnusedAddress scans one account and returns its first unused address.
func (s *Store) FindUnusedAddress(_ context.Context,
	query db.FindUnusedAddressQuery) (btcutil.Address, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.FindUnusedAddress: %w", errMissingLegacyAddrStore,
		)
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(query.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.FindUnusedAddress: fetch scoped manager: %w", err,
		)
	}

	var addr btcutil.Address

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		account, err := manager.LookupAccount(ns, query.AccountName)
		if err != nil {
			return fmt.Errorf("lookup account: %w", err)
		}

		return manager.ForEachAccountAddress(ns, account,
			func(managedAddr waddrmgr.ManagedAddress) error {
				if managedAddr.Internal() != query.Change {
					return nil
				}

				if managedAddr.Used(ns) {
					return nil
				}

				addr = managedAddr.Address()

				return errStopUnusedAddrScan
			},
		)
	})
	if err != nil && !errors.Is(err, errStopUnusedAddrScan) {
		return nil, fmt.Errorf("kvdb.Store.FindUnusedAddress: %w", err)
	}

	return addr, nil
}

// GetManagedAddress returns the legacy managed-address view for one wallet
// address.
func (s *Store) GetManagedAddress(_ context.Context,
	query db.GetManagedAddressQuery) (waddrmgr.ManagedAddress, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetManagedAddress: %w", errMissingLegacyAddrStore,
		)
	}

	if query.Address == "" {
		return nil, fmt.Errorf(
			"kvdb.Store.GetManagedAddress: %w", errMissingAddressQuery,
		)
	}

	addr, err := btcutil.DecodeAddress(query.Address, s.addrStore.ChainParams())
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetManagedAddress: decode address: %w", err,
		)
	}

	var managedAddr waddrmgr.ManagedAddress

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err = s.addrStore.Address(ns, addr)
		if err != nil {
			return fmt.Errorf("lookup managed address: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetManagedAddress: %w", err)
	}

	return managedAddr, nil
}

// GetAddressDetails returns the wallet-facing address metadata for one script
// pubkey through the legacy waddrmgr path.
func (s *Store) GetAddressDetails(_ context.Context,
	query db.GetAddressDetailsQuery) (bool, string, db.AddressType, error) {

	if s.addrStore == nil {
		return false, "", 0, fmt.Errorf(
			"kvdb.Store.GetAddressDetails: %w", errMissingLegacyAddrStore,
		)
	}

	addr, err := kvdbAddressFromPkScript(
		query.ScriptPubKey, s.addrStore.ChainParams(),
	)
	if err != nil {
		return false, "", 0, fmt.Errorf(
			"kvdb.Store.GetAddressDetails: %w", err,
		)
	}

	var (
		spendable bool
		account   string
		addrType  db.AddressType
	)

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		var legacyType waddrmgr.AddressType

		spendable, account, legacyType = s.addrStore.AddressDetails(ns, addr)

		mappedType, err := kvdbAddressType(legacyType)
		if err != nil {
			return err
		}

		addrType = mappedType

		if account == "" {
			account = legacyUnknownAccountName
		}

		return nil
	})
	if err != nil {
		return false, "", 0, fmt.Errorf(
			"kvdb.Store.GetAddressDetails: %w", err,
		)
	}

	return spendable, account, addrType, nil
}

// ListAddresses returns one page of addresses for the requested account and
// scope through the legacy address-manager path.
func (s *Store) ListAddresses(_ context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	if s.addrStore == nil {
		return page.Result[db.AddressInfo, uint32]{}, fmt.Errorf(
			"kvdb.Store.ListAddresses: %w", errMissingLegacyAddrStore,
		)
	}

	if query.Page.Limit() == 0 {
		return page.Result[db.AddressInfo, uint32]{}, db.ErrInvalidPageLimit
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(query.Scope),
	)
	if err != nil {
		return page.Result[db.AddressInfo, uint32]{}, fmt.Errorf(
			"kvdb.Store.ListAddresses: fetch scoped manager: %w", err,
		)
	}

	addresses := make([]db.AddressInfo, 0)

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		account, err := manager.LookupAccount(ns, query.AccountName)
		if err != nil {
			return fmt.Errorf("lookup account: %w", err)
		}

		return manager.ForEachAccountAddress(ns, account,
			func(managedAddr waddrmgr.ManagedAddress) error {
				info, err := kvdbAddressInfo(managedAddr)
				if err != nil {
					return err
				}

				addresses = append(addresses, *info)

				return nil
			},
		)
	})
	if err != nil {
		return page.Result[db.AddressInfo, uint32]{}, fmt.Errorf(
			"kvdb.Store.ListAddresses: %w", err,
		)
	}

	result := page.BuildResult(
		query.Page, addresses,
		func(item db.AddressInfo) uint32 {
			return item.ID
		},
	)

	return result, nil
}

// IterAddresses returns an iterator over paginated address results.
func (s *Store) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses,
		func(q db.ListAddressesQuery, after uint32) db.ListAddressesQuery {
			q.Page.After = &after
			return q
		},
	)
}

// GetAddressSecret is not yet implemented for kvdb.
func (s *Store) GetAddressSecret(ctx context.Context,
	_ uint32) (*db.AddressSecret, error) {

	return nil, notImplemented(ctx, "GetAddressSecret")
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

// CreateImportedAccount is not yet implemented for kvdb.
func (s *Store) CreateImportedAccount(ctx context.Context,
	_ db.CreateImportedAccountParams) (*db.AccountProperties, error) {

	return nil, notImplemented(ctx, "CreateImportedAccount")
}

// ImportAccount is not yet implemented for kvdb.
func (s *Store) ImportAccount(ctx context.Context,
	_ db.ImportAccountParams) (*db.AccountProperties, error) {

	return nil, notImplemented(ctx, "ImportAccount")
}

// kvdbAddressFromPkScript extracts the first standard address from one script.
//
// This lets the legacy address manager resolve wallet metadata from a
// script-pubkey-only store lookup.
func kvdbAddressFromPkScript(pkScript []byte,
	chainParams *chaincfg.Params) (btcutil.Address, error) {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, chainParams)
	if err != nil {
		return nil, fmt.Errorf("extract address from pkScript: %w", err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf(
			"extract address from pkScript: %w", errNoAddressInPkScript,
		)
	}

	return addrs[0], nil
}

// kvdbAddressType maps the legacy waddrmgr enum into the db-native address
// type enum used by store interfaces.
func kvdbAddressType(addrType waddrmgr.AddressType) (db.AddressType, error) {
	switch addrType {
	case waddrmgr.RawPubKey:
		return db.RawPubKey, nil
	case waddrmgr.PubKeyHash:
		return db.PubKeyHash, nil
	case waddrmgr.Script:
		return db.ScriptHash, nil
	case waddrmgr.NestedWitnessPubKey:
		return db.NestedWitnessPubKey, nil
	case waddrmgr.WitnessPubKey:
		return db.WitnessPubKey, nil
	case waddrmgr.WitnessScript:
		return db.WitnessScript, nil
	case waddrmgr.TaprootPubKey:
		return db.TaprootPubKey, nil
	case waddrmgr.TaprootScript:
		return 0, fmt.Errorf("%w: %v", errUnsupportedAddrType, addrType)
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedAddrType, addrType)
	}
}

// kvdbAddressInfo converts one legacy managed address into the db-native
// address metadata shape used by transitional store callers.
func kvdbAddressInfo(managedAddr waddrmgr.ManagedAddress) (*db.AddressInfo,
	error) {

	addrType, err := kvdbAddressType(managedAddr.AddrType())
	if err != nil {
		return nil, err
	}

	scriptPubKey, err := txscript.PayToAddrScript(managedAddr.Address())
	if err != nil {
		return nil, fmt.Errorf("address script pubkey: %w", err)
	}

	info := &db.AddressInfo{
		AccountID:    managedAddr.InternalAccount(),
		AddrType:     addrType,
		Origin:       db.DerivedAccount,
		ScriptPubKey: scriptPubKey,
		IsWatchOnly:  false,
	}

	if managedAddr.Imported() {
		info.Origin = db.ImportedAccount
	}

	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return info, nil
	}

	pubKey := pubKeyAddr.PubKey()
	if pubKey != nil {
		if managedAddr.Compressed() {
			info.PubKey = pubKey.SerializeCompressed()
		} else {
			info.PubKey = pubKey.SerializeUncompressed()
		}
	}

	_, derivation, ok := pubKeyAddr.DerivationInfo()
	if ok {
		info.Branch = derivation.Branch
		info.Index = derivation.Index
	}

	return info, nil
}
