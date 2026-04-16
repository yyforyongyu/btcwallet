package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

var errSignerDerivationInfoUnavailable = errors.New(
	"signer derivation info unavailable",
)

// GetManagedPubKeyAddressByPath resolves one BIP32 derivation path through the
// legacy address-manager path and returns the managed pubkey address view.
func (s *Store) GetManagedPubKeyAddressByPath(_ context.Context,
	query db.SignerPathQuery) (waddrmgr.ManagedPubKeyAddress, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetManagedPubKeyAddressByPath: %w",
			errMissingLegacyAddrStore,
		)
	}

	manager, err := s.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(query.Scope),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetManagedPubKeyAddressByPath: "+
				"fetch scoped manager: %w",
			err,
		)
	}

	var managedAddr waddrmgr.ManagedAddress

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err = manager.DeriveFromKeyPath(
			ns, query.DerivationPath,
		)
		if err != nil {
			return fmt.Errorf("derive from key path: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetManagedPubKeyAddressByPath: %w", err,
		)
	}

	return kvdbManagedPubKeyAddress(managedAddr)
}

// GetManagedPubKeyAddress resolves one wallet address through the legacy
// address-manager path and returns the managed pubkey address view.
func (s *Store) GetManagedPubKeyAddress(ctx context.Context,
	query db.SignerAddressQuery) (waddrmgr.ManagedPubKeyAddress, error) {

	managedAddr, err := s.GetManagedAddress(
		ctx, db.GetManagedAddressQuery(query),
	)
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetManagedPubKeyAddress: %w", err)
	}

	return kvdbManagedPubKeyAddress(managedAddr)
}

// GetPrivKeyByPath resolves one derived private key through the legacy
// address-manager path.
func (s *Store) GetPrivKeyByPath(ctx context.Context,
	query db.SignerPathQuery) (*btcec.PrivateKey, error) {

	pubKeyAddr, err := s.GetManagedPubKeyAddressByPath(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetPrivKeyByPath: %w", err)
	}

	privKey, err := pubKeyAddr.PrivKey()
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetPrivKeyByPath: fetch private key: %w", err,
		)
	}

	return privKey, nil
}

// GetPrivKeyForAddress resolves one private key by wallet address through the
// legacy address-manager path.
func (s *Store) GetPrivKeyForAddress(ctx context.Context,
	query db.SignerAddressQuery) (*btcec.PrivateKey, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetPrivKeyForAddress: %w", errMissingLegacyAddrStore,
		)
	}

	pubKeyAddr, err := s.GetManagedPubKeyAddress(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetPrivKeyForAddress: %w", err)
	}

	if pubKeyAddr.Imported() {
		privKey, err := pubKeyAddr.PrivKey()
		if err != nil {
			return nil, fmt.Errorf(
				"kvdb.Store.GetPrivKeyForAddress: "+
					"fetch imported private key: %w",
				err,
			)
		}

		return privKey, nil
	}

	keyScope, derivationPath, ok := pubKeyAddr.DerivationInfo()
	if !ok {
		return nil, fmt.Errorf(
			"kvdb.Store.GetPrivKeyForAddress: %w: addr %s",
			errSignerDerivationInfoUnavailable,
			pubKeyAddr.Address(),
		)
	}

	manager, err := s.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, fmt.Errorf(
			"kvdb.Store.GetPrivKeyForAddress: fetch scoped manager: %w", err,
		)
	}

	privKey, err := manager.DeriveFromKeyPathCache(derivationPath)
	if err != nil {
		if !waddrmgr.IsError(err, waddrmgr.ErrAccountNotCached) {
			return nil, fmt.Errorf(
				"kvdb.Store.GetPrivKeyForAddress: "+
					"derive private key from cache: %w",
				err,
			)
		}

		privKey, err = s.derivePrivKeyByPath(manager, derivationPath)
		if err != nil {
			return nil, err
		}
	}

	return privKey, nil
}

// derivePrivKeyByPath resolves one derived private key through the normal
// database-backed derivation path after an account-cache miss.
func (s *Store) derivePrivKeyByPath(manager waddrmgr.AccountStore,
	derivationPath waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	var privKey *btcec.PrivateKey

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		managedAddr, err := manager.DeriveFromKeyPath(ns, derivationPath)
		if err != nil {
			return fmt.Errorf("derive private key from db: %w", err)
		}

		pubKeyAddr, err := kvdbManagedPubKeyAddress(managedAddr)
		if err != nil {
			return err
		}

		privKey, err = pubKeyAddr.PrivKey()
		if err != nil {
			return fmt.Errorf("fetch derived private key: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetPrivKeyForAddress: %w", err)
	}

	return privKey, nil
}

// kvdbManagedPubKeyAddress converts one managed address into the managed pubkey
// address view required by transitional signer callers.
func kvdbManagedPubKeyAddress(managedAddr waddrmgr.ManagedAddress) (
	waddrmgr.ManagedPubKeyAddress, error) {

	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, fmt.Errorf(
			"%w: addr %s", db.ErrNotManagedPubKeyAddress, managedAddr.Address(),
		)
	}

	return pubKeyAddr, nil
}
