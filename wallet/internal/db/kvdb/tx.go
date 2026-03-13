package kvdb

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// CreateTx is not yet implemented for kvdb.
func (s *Store) CreateTx(ctx context.Context,
	_ db.CreateTxParams) error {

	return notImplemented(ctx, "CreateTx")
}

// UpdateTxLabel is not yet implemented for kvdb.
func (s *Store) UpdateTxLabel(ctx context.Context,
	_ db.UpdateTxLabelParams) error {

	return notImplemented(ctx, "UpdateTxLabel")
}

// GetTx is not yet implemented for kvdb.
func (s *Store) GetTx(ctx context.Context,
	_ db.GetTxQuery) (*db.TxInfo, error) {

	return nil, notImplemented(ctx, "GetTx")
}

// ListTxns is not yet implemented for kvdb.
func (s *Store) ListTxns(ctx context.Context,
	_ db.ListTxnsQuery) ([]db.TxInfo, error) {

	return nil, notImplemented(ctx, "ListTxns")
}

// DeleteTx is not yet implemented for kvdb.
func (s *Store) DeleteTx(ctx context.Context,
	_ db.DeleteTxParams) error {

	return notImplemented(ctx, "DeleteTx")
}

// RollbackToBlock is not yet implemented for kvdb.
func (s *Store) RollbackToBlock(ctx context.Context, _ uint32) error {
	return notImplemented(ctx, "RollbackToBlock")
}
