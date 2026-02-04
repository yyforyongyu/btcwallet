// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db UTXO store interface.
package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")
)

// UTXOStore is the kvdb (walletdb) implementation of the db.UTXOStore
// interface.
//
// NOTE: This is a partial implementation that will be expanded as the wallet
// UTXO manager migrates to the new db interfaces.
type UTXOStore struct {
	db      walletdb.DB
	txStore wtxmgr.TxStore
}

// A compile-time assertion to ensure that UTXOStore implements the
// db.UTXOStore interface.
var _ db.UTXOStore = (*UTXOStore)(nil)

// NewUTXOStore creates a new kvdb-backed UTXO store.
func NewUTXOStore(dbConn walletdb.DB, txStore wtxmgr.TxStore) *UTXOStore {
	return &UTXOStore{
		db:      dbConn,
		txStore: txStore,
	}
}

func notImplemented(ctx context.Context, method string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}

	return fmt.Errorf("kvdb.UTXOStore.%s: %w", method, errNotImplemented)
}

// GetUtxo is not yet implemented for kvdb.
func (s *UTXOStore) GetUtxo(ctx context.Context,
	_ db.GetUtxoQuery) (*db.UtxoInfo, error) {

	return nil, notImplemented(ctx, "GetUtxo")
}

// ListUTXOs is not yet implemented for kvdb.
func (s *UTXOStore) ListUTXOs(ctx context.Context,
	_ db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	return nil, notImplemented(ctx, "ListUTXOs")
}

// LeaseOutput is not yet implemented for kvdb.
func (s *UTXOStore) LeaseOutput(ctx context.Context,
	_ db.LeaseOutputParams) (*db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "LeaseOutput")
}

// ReleaseOutput is not yet implemented for kvdb.
func (s *UTXOStore) ReleaseOutput(ctx context.Context,
	_ db.ReleaseOutputParams) error {

	return notImplemented(ctx, "ReleaseOutput")
}

// ListLeasedOutputs is not yet implemented for kvdb.
func (s *UTXOStore) ListLeasedOutputs(ctx context.Context,
	_ uint32) ([]db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "ListLeasedOutputs")
}

// Balance is not yet implemented for kvdb.
func (s *UTXOStore) Balance(ctx context.Context,
	_ db.BalanceParams) (btcutil.Amount, error) {

	return 0, notImplemented(ctx, "Balance")
}
