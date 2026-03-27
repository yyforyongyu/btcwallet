package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// UpdateTx patches the mutable metadata for one wallet-scoped transaction.
//
// UpdateTx may edit the user-visible label, the block/status view, or both in
// one SQL transaction. Immutable transaction facts such as raw_tx, credits, and
// spent-input edges stay owned by CreateTx and the internal rollback/delete
// flows.
func (s *SqliteStore) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return updateTxWithOps(ctx, params, &sqliteUpdateTxOps{qtx: qtx})
	})
}

// sqliteUpdateTxOps adapts sqlite sqlc queries to the shared UpdateTx flow.
type sqliteUpdateTxOps struct {
	qtx *sqlcsqlite.Queries

	blockHeight sql.NullInt64
	status      int64
}

var _ updateTxOps = (*sqliteUpdateTxOps)(nil)

// loadIsCoinbase loads the existing row metadata UpdateTx needs before it can
// validate one patch.
func (o *sqliteUpdateTxOps) loadIsCoinbase(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (bool, error) {

	return loadUpdateTxIsCoinbase(ctx, txHash,
		func(ctx context.Context) (bool, error) {
			meta, err := o.qtx.GetTransactionMetaByHash(
				ctx,
				sqlcsqlite.GetTransactionMetaByHashParams{
					WalletID: int64(walletID),
					TxHash:   txHash[:],
				},
			)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return false, errUpdateTxTargetNotFound
				}

				return false, fmt.Errorf("get transaction metadata: %w", err)
			}

			return meta.IsCoinbase, nil
		},
	)
}

// prepareState validates any referenced confirming block and captures the
// sqlite-specific state params for the later row update.
func (o *sqliteUpdateTxOps) prepareState(ctx context.Context,
	state UpdateTxState) error {

	blockHeight, status, err := prepareUpdateTxStateParams(
		ctx,
		state,
		func(status TxStatus) int64 {
			return int64(status)
		},
		func(ctx context.Context, block *Block) (int64, error) {
			return requireBlockMatchesSqlite(ctx, o.qtx, block)
		},
		func(height int64) sql.NullInt64 {
			return sql.NullInt64{Int64: height, Valid: true}
		},
	)
	if err != nil {
		return err
	}

	o.blockHeight = blockHeight
	o.status = status

	return nil
}

// updateLabel writes one user-visible label change.
func (o *sqliteUpdateTxOps) updateLabel(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, label string) error {

	return applyUpdateTxRows(ctx, txHash, "update transaction label",
		func(ctx context.Context) (int64, error) {
			rows, err := o.qtx.UpdateTransactionLabelByHash(
				ctx,
				sqlcsqlite.UpdateTransactionLabelByHashParams{
					Label:    label,
					WalletID: int64(walletID),
					TxHash:   txHash[:],
				},
			)
			if err != nil {
				return 0, fmt.Errorf("update transaction label query: %w", err)
			}

			return rows, nil
		},
	)
}

// updateState writes one block/status patch after prepareState has validated
// any referenced block metadata.
func (o *sqliteUpdateTxOps) updateState(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, _ UpdateTxState) error {

	return applyUpdateTxRows(ctx, txHash, "update transaction state",
		func(ctx context.Context) (int64, error) {
			rows, err := o.qtx.UpdateTransactionStateByHash(
				ctx,
				sqlcsqlite.UpdateTransactionStateByHashParams{
					BlockHeight: o.blockHeight,
					Status:      o.status,
					WalletID:    int64(walletID),
					TxHash:      txHash[:],
				},
			)
			if err != nil {
				return 0, fmt.Errorf("update transaction state query: %w", err)
			}

			return rows, nil
		},
	)
}
