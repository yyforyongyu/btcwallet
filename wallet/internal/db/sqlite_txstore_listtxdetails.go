package db

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListTxDetails lists detailed wallet-scoped transaction views using wallet
// tx-reader range semantics.
func (s *SqliteStore) ListTxDetails(ctx context.Context,
	query ListTxDetailsQuery) ([]TxDetailInfo, error) {

	return listTxDetailsWithOps(
		ctx, query, s.listUnminedTxDetailsBasesSqlite,
		s.listConfirmedTxDetailsBasesSqlite,
		s.loadOwnedInputsForTxIDsSqlite,
		s.loadOwnedOutputsForTxIDsSqlite,
		txDetailFromSqliteBase,
		func(base sqliteTxDetailBase) int64 {
			return base.ID
		},
	)
}

// listUnminedTxDetailsBasesSqlite loads the base SQLite rows for unmined
// wallet-scoped transactions.
func (s *SqliteStore) listUnminedTxDetailsBasesSqlite(ctx context.Context,
	walletID uint32) ([]sqliteTxDetailBase, error) {

	rows, err := s.queries.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list unmined transaction details: %w", err)
	}

	bases := make([]sqliteTxDetailBase, len(rows))
	for i, row := range rows {
		bases[i] = sqliteTxDetailBase{
			ID:             row.ID,
			TxHash:         row.TxHash,
			RawTx:          row.RawTx,
			ReceivedTime:   row.ReceivedTime,
			BlockHeight:    row.BlockHeight,
			BlockHash:      row.BlockHash,
			BlockTimestamp: row.BlockTimestamp,
			TxStatus:       row.TxStatus,
			TxLabel:        row.TxLabel,
		}
	}

	return bases, nil
}

// listConfirmedTxDetailsBasesSqlite loads the base SQLite rows for confirmed
// wallet-scoped transactions in the normalized height range.
func (s *SqliteStore) listConfirmedTxDetailsBasesSqlite(ctx context.Context,
	walletID uint32, startHeight, endHeight int32,
	reverse bool) ([]sqliteTxDetailBase, error) {

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(walletID),
			StartHeight: int64(startHeight),
			EndHeight:   int64(endHeight),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list confirmed transaction details: %w", err)
	}

	bases := make([]sqliteTxDetailBase, len(rows))
	for i, row := range rows {
		bases[i] = sqliteTxDetailBase{
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
			TxStatus: row.TxStatus,
			TxLabel:  row.TxLabel,
		}
	}

	if reverse {
		slices.Reverse(bases)
	}

	return bases, nil
}
