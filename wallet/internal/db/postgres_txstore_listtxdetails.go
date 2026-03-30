package db

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ListTxDetails lists detailed wallet-scoped transaction views using wallet
// tx-reader range semantics.
func (s *PostgresStore) ListTxDetails(ctx context.Context,
	query ListTxDetailsQuery) ([]TxDetailInfo, error) {

	return listTxDetailsWithOps(
		ctx, query, s.listUnminedTxDetailsBasesPg,
		s.listConfirmedTxDetailsBasesPg,
		s.loadOwnedInputsForTxIDsPg,
		s.loadOwnedOutputsForTxIDsPg,
		txDetailFromPgBase,
		func(base pgTxDetailBase) int64 {
			return base.ID
		},
	)
}

// listUnminedTxDetailsBasesPg loads the base Postgres rows for unmined
// wallet-scoped transactions.
func (s *PostgresStore) listUnminedTxDetailsBasesPg(ctx context.Context,
	walletID uint32) ([]pgTxDetailBase, error) {

	rows, err := s.queries.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list unmined transaction details: %w", err)
	}

	bases := make([]pgTxDetailBase, len(rows))
	for i, row := range rows {
		bases[i] = pgTxDetailBase{
			ID:             row.ID,
			TxHash:         row.TxHash,
			RawTx:          row.RawTx,
			ReceivedTime:   row.ReceivedTime,
			BlockHeight:    row.BlockHeight,
			BlockHash:      row.BlockHash,
			BlockTimestamp: row.BlockTimestamp,
			TxStatus:       int64(row.TxStatus),
			TxLabel:        row.TxLabel,
		}
	}

	return bases, nil
}

// listConfirmedTxDetailsBasesPg loads the base Postgres rows for confirmed
// wallet-scoped transactions in the normalized height range.
func (s *PostgresStore) listConfirmedTxDetailsBasesPg(ctx context.Context,
	walletID uint32, startHeight, endHeight int32,
	reverse bool) ([]pgTxDetailBase, error) {

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(walletID),
			StartHeight: startHeight,
			EndHeight:   endHeight,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list confirmed transaction details: %w", err)
	}

	bases := make([]pgTxDetailBase, len(rows))
	for i, row := range rows {
		bases[i] = pgTxDetailBase{
			ID:           row.ID,
			TxHash:       row.TxHash,
			RawTx:        row.RawTx,
			ReceivedTime: row.ReceivedTime,
			BlockHeight:  row.BlockHeight,
			BlockHash:    row.BlockHash,
			BlockTimestamp: sql.NullInt64{
				Int64: row.BlockTimestamp,
				Valid: true,
			},
			TxStatus: int64(row.TxStatus),
			TxLabel:  row.TxLabel,
		}
	}

	if reverse {
		slices.Reverse(bases)
	}

	return bases, nil
}
