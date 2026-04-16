package kvdb

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// GetManagedPubKeyAddressByPath resolves one BIP32 derivation path through the
// legacy address-manager path and returns the managed pubkey address view.
func (s *Store) GetManagedPubKeyAddressByPath(_ context.Context,
	query db.SignerPathQuery) (waddrmgr.ManagedPubKeyAddress, error) {

	return nil, db.SignerCompatNotImplemented("GetManagedPubKeyAddressByPath")
}

// GetManagedPubKeyAddress resolves one wallet address through the legacy
// address-manager path and returns the managed pubkey address view.
func (s *Store) GetManagedPubKeyAddress(ctx context.Context,
	query db.SignerAddressQuery) (waddrmgr.ManagedPubKeyAddress, error) {

	_ = ctx
	_ = query

	return nil, db.SignerCompatNotImplemented("GetManagedPubKeyAddress")
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
