package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
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

	_ = ctx
	_ = query

	return nil, db.SignerCompatNotImplemented("GetPrivKeyByPath")
}

// GetPrivKeyForAddress resolves one private key by wallet address through the
// legacy address-manager path.
func (s *Store) GetPrivKeyForAddress(ctx context.Context,
	query db.SignerAddressQuery) (*btcec.PrivateKey, error) {

	_ = ctx
	_ = query

	return nil, db.SignerCompatNotImplemented("GetPrivKeyForAddress")
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
