package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// InvalidateUnminedTx atomically invalidates one wallet-owned unmined
// transaction branch and marks the root plus descendants failed.
func (s *PostgresStore) InvalidateUnminedTx(ctx context.Context,
	params InvalidateUnminedTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return invalidateUnminedTxWithOps(ctx, params,
			pgInvalidateUnminedTxOps{qtx: qtx})
	})
}

// pgInvalidateUnminedTxOps adapts postgres sqlc queries to the shared
// InvalidateUnminedTx workflow.
type pgInvalidateUnminedTxOps struct {
	qtx *sqlcpg.Queries
}

var _ invalidateUnminedTxOps = (*pgInvalidateUnminedTxOps)(nil)

// loadTarget loads the root transaction metadata used by the shared
// invalidation workflow.
func (o pgInvalidateUnminedTxOps) loadTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (invalidateUnminedTxTarget, error) {

	row, err := o.qtx.GetTransactionMetaByHash(
		ctx, sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return invalidateUnminedTxTarget{}, fmt.Errorf("transaction %s: %w",
				txHash, ErrTxNotFound)
		}

		return invalidateUnminedTxTarget{},
			fmt.Errorf("get transaction metadata: %w", err)
	}

	status, err := parseTxStatus(int64(row.TxStatus))
	if err != nil {
		return invalidateUnminedTxTarget{}, err
	}

	return invalidateUnminedTxTarget{
		id:         row.ID,
		txHash:     txHash,
		status:     status,
		hasBlock:   row.BlockHeight.Valid,
		isCoinbase: row.IsCoinbase,
	}, nil
}

// listUnminedTxRecords loads and decodes the wallet's active unmined
// transaction rows.
func (o pgInvalidateUnminedTxOps) listUnminedTxRecords(
	ctx context.Context, walletID int64) ([]unminedTxRecord, error) {

	rows, err := o.qtx.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined transactions: %w", err)
	}

	return buildUnminedTxRecords(rows,
		func(row sqlcpg.ListUnminedTransactionsRow) (int64, []byte, []byte) {
			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// clearSpentUtxos restores any wallet-owned parent outputs spent by the given
// transaction row.
func (o pgInvalidateUnminedTxOps) clearSpentUtxos(ctx context.Context,
	walletID int64, txID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx, sqlcpg.ClearUtxosSpentByTxIDParams{
			WalletID: walletID,
			SpentByTxID: sql.NullInt64{
				Int64: txID,
				Valid: true,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("clear spent utxos: %w", err)
	}

	return nil
}

// markTransactionsFailed marks the provided transaction rows failed in one
// batch update.
func (o pgInvalidateUnminedTxOps) markTransactionsFailed(
	ctx context.Context, walletID int64, txIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcpg.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int16(TxStatusFailed),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark transactions failed: %w", err)
	}

	return nil
}
