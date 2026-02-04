package kvdb

import (
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Store is the kvdb (walletdb) implementation of the db.UTXOStore interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// UTXO manager migrates to the new db interfaces.
type Store struct {
	db      walletdb.DB
	txStore wtxmgr.TxStore
}

// A compile-time assertion to ensure that Store implements the db.UTXOStore
// interface.
var _ db.UTXOStore = (*Store)(nil)

// NewStore creates a new kvdb-backed UTXO store.
func NewStore(dbConn walletdb.DB, txStore wtxmgr.TxStore) *Store {
	return &Store{
		db:      dbConn,
		txStore: txStore,
	}
}
