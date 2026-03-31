package kvdb

import (
	"context"
	"errors"
	"fmt"
	"iter"

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
	errUnsupportedAddrType     = errors.New("unsupported legacy address type")
)

var waddrmgrNamespaceKey = []byte("waddrmgr")

// NewDerivedAddress is not yet implemented for kvdb.
func (s *Store) NewDerivedAddress(ctx context.Context,
	_ db.NewDerivedAddressParams,
	_ db.AddressDerivationFunc) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "NewDerivedAddress")
}

// NewImportedAddress is not yet implemented for kvdb.
func (s *Store) NewImportedAddress(ctx context.Context,
	_ db.NewImportedAddressParams) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "NewImportedAddress")
}

// GetAddress is not yet implemented for kvdb.
func (s *Store) GetAddress(ctx context.Context,
	_ db.GetAddressQuery) (*db.AddressInfo, error) {

	return nil, notImplemented(ctx, "GetAddress")
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

// ListAddresses is not yet implemented for kvdb.
func (s *Store) ListAddresses(ctx context.Context,
	_ db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	return page.Result[db.AddressInfo, uint32]{},
		notImplemented(ctx, "ListAddresses")
}

// IterAddresses is not yet implemented for kvdb.
func (s *Store) IterAddresses(ctx context.Context,
	_ db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return func(yield func(db.AddressInfo, error) bool) {
		var zero db.AddressInfo

		yield(zero, notImplemented(ctx, "IterAddresses"))
	}
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
