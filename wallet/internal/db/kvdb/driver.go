package kvdb

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// legacyAddrStore is the narrow subset of the legacy address manager that the
// kvdb adapter needs while wallet managers migrate behind db.Store.
type legacyAddrStore interface {
	ChainParams() *chaincfg.Params
	SyncedTo() waddrmgr.BlockStamp
	ActiveScopedKeyManagers() []waddrmgr.AccountStore
	NewScopedKeyManager(ns walletdb.ReadWriteBucket,
		scope waddrmgr.KeyScope,
		addrSchema waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error)
	FetchScopedKeyManager(scope waddrmgr.KeyScope) (waddrmgr.AccountStore,
		error)
	Address(ns walletdb.ReadBucket,
		addr btcutil.Address) (waddrmgr.ManagedAddress, error)
	AddressDetails(ns walletdb.ReadBucket,
		addr btcutil.Address) (bool, string, waddrmgr.AddressType)
	AddrAccount(ns walletdb.ReadBucket,
		addr btcutil.Address) (waddrmgr.AccountStore, uint32, error)
}

// Store is the kvdb (walletdb) implementation of the db.Store interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// UTXO manager migrates to the new db interfaces.
type Store struct {
	db        walletdb.DB
	txStore   wtxmgr.TxStore
	addrStore legacyAddrStore
}

// A compile-time assertion to ensure that Store implements the db.Store
// interface.
var _ db.Store = (*Store)(nil)

// NewStore creates a new kvdb-backed wallet store adapter.
func NewStore(dbConn walletdb.DB, txStore wtxmgr.TxStore,
	addrStore legacyAddrStore) *Store {

	return &Store{
		db:        dbConn,
		txStore:   txStore,
		addrStore: addrStore,
	}
}
