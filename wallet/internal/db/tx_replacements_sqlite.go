package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// ApplyTxReplacement records directed replacement edges, marks each direct
// victim as replaced, recursively fails descendants, and reclaims the winner's
// spent-input edges inside one SQL transaction.
func (s *SqliteStore) ApplyTxReplacement(ctx context.Context,
	params ApplyTxReplacementParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return applyTxReplacementCommon(
			ctx, params,
			func(ctx context.Context,
				txid chainhash.Hash) (txChainMeta, error) {

				return loadTxChainMetaSqlite(
					ctx, qtx, params.WalletID, txid,
				)
			},
			func(ctx context.Context,
				txids []chainhash.Hash) ([]txChainMeta, error) {

				return loadTxChainMetasSqlite(
					ctx, qtx, params.WalletID, txids,
				)
			},
			buildTxChainHooksSqlite(qtx, params.WalletID),
		)
	})
}

// ApplyTxFailure marks each direct loser as failed, recursively fails
// descendants, and reclaims the winner's spent-input edges inside one SQL
// transaction.
func (s *SqliteStore) ApplyTxFailure(ctx context.Context,
	params ApplyTxFailureParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return applyTxFailureCommon(
			ctx, params,
			func(ctx context.Context,
				txid chainhash.Hash) (txChainMeta, error) {

				return loadTxChainMetaSqlite(
					ctx, qtx, params.WalletID, txid,
				)
			},
			func(ctx context.Context,
				txids []chainhash.Hash) ([]txChainMeta, error) {

				return loadTxChainMetasSqlite(
					ctx, qtx, params.WalletID, txids,
				)
			},
			buildTxChainHooksSqlite(qtx, params.WalletID),
		)
	})
}

// OrphanTxChain recursively fails every descendant of the provided orphaned
// coinbase roots while keeping the roots themselves in the orphaned state.
func (s *SqliteStore) OrphanTxChain(ctx context.Context,
	params OrphanTxChainParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		roots, err := loadTxChainMetasSqlite(
			ctx, qtx, params.WalletID, params.Txids,
		)
		if err != nil {
			return err
		}

		err = validateOrphanPlan(roots)
		if err != nil {
			return err
		}

		return applyTxChainInvalidation(
			ctx, txIDsFromMetas(roots), TxStatusOrphaned,
			buildTxChainHooksSqlite(qtx, params.WalletID),
		)
	})
}

// ReconfirmOrphanedCoinbase restores one orphaned coinbase transaction to a new
// confirming block inside one SQL transaction.
func (s *SqliteStore) ReconfirmOrphanedCoinbase(ctx context.Context,
	params ReconfirmOrphanedCoinbaseParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		meta, err := loadTxChainMetaSqlite(
			ctx, qtx, params.WalletID, params.Txid,
		)
		if err != nil {
			return err
		}

		err = validateCoinbaseReconfirmation(meta)
		if err != nil {
			return err
		}

		err = ensureBlockExistsSqlite(ctx, qtx, &params.Block)
		if err != nil {
			return fmt.Errorf("ensure block exists: %w", err)
		}

		rows, err := qtx.ReconfirmOrphanedCoinbaseByHash(
			ctx, sqlcsqlite.ReconfirmOrphanedCoinbaseByHashParams{
				BlockHeight: sql.NullInt64{
					Int64: int64(params.Block.Height),
					Valid: true,
				},
				WalletID: int64(params.WalletID),
				TxHash:   params.Txid[:],
			},
		)
		if err != nil {
			return fmt.Errorf("reconfirm orphaned coinbase: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("transaction %s: %w", params.Txid,
				errCoinbaseReconfirmationStateChanged)
		}

		return nil
	})
}

// buildTxChainHooksSqlite binds the shared replacement helpers to the sqlite
// query set active for the surrounding SQL transaction.
func buildTxChainHooksSqlite(qtx *sqlcsqlite.Queries,
	walletID uint32) txChainHooks {

	return buildTxChainHooks(
		func(ctx context.Context, parentID int64) ([]int64, error) {
			return listChildTxIDsSqlite(ctx, qtx, walletID, parentID)
		},
		func(ctx context.Context, txID int64) error {
			return clearSpentByTxIDSqlite(ctx, qtx, walletID, txID)
		},
		func(ctx context.Context, status TxStatus,
			txIDs []int64) error {

			return updateTxStatusSqlite(ctx, qtx, walletID, status, txIDs)
		},
		func(ctx context.Context, txid chainhash.Hash,
			txID int64) error {

			return reclaimInputsByTxidSqlite(ctx, qtx, walletID, txid, txID)
		},
		func(ctx context.Context, replacedTxID int64,
			replacementTxID int64) error {

			return recordReplacementEdgeSqlite(
				ctx, qtx, walletID, replacedTxID, replacementTxID,
			)
		},
	)
}

func loadTxChainMetasSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txids []chainhash.Hash) ([]txChainMeta, error) {

	metas := make([]txChainMeta, len(txids))
	for i, txid := range txids {
		meta, err := loadTxChainMetaSqlite(ctx, qtx, walletID, txid)
		if err != nil {
			return nil, err
		}

		metas[i] = meta
	}

	return metas, nil
}

func loadTxChainMetaSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txid chainhash.Hash) (txChainMeta, error) {

	row, err := qtx.GetTransactionMetaByHash(
		ctx, sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return txChainMeta{}, fmt.Errorf("transaction %s: %w", txid,
				ErrTxNotFound)
		}

		return txChainMeta{}, fmt.Errorf("get transaction metadata: %w", err)
	}

	status, err := parseTxStatus(row.Status)
	if err != nil {
		return txChainMeta{}, err
	}

	return txChainMeta{
		ID:         row.ID,
		Txid:       txid,
		Status:     status,
		HasBlock:   row.BlockHeight.Valid,
		IsCoinbase: row.IsCoinbase,
	}, nil
}

func listChildTxIDsSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, parentID int64) ([]int64, error) {

	rows, err := qtx.ListSpendingTxIDsByParentTxID(
		ctx, sqlcsqlite.ListSpendingTxIDsByParentTxIDParams{
			WalletID: int64(walletID),
			TxID:     parentID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list spending transactions for %d: %w",
			parentID, err)
	}

	childIDs := make([]int64, 0, len(rows))
	for _, row := range rows {
		if !row.Valid {
			continue
		}

		childIDs = append(childIDs, row.Int64)
	}

	return childIDs, nil
}

func clearSpentByTxIDSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txID int64) error {

	_, err := qtx.ClearUtxosSpentByTxID(
		ctx, sqlcsqlite.ClearUtxosSpentByTxIDParams{
			WalletID:    int64(walletID),
			SpentByTxID: sql.NullInt64{Int64: txID, Valid: true},
		},
	)
	if err != nil {
		return fmt.Errorf("clear spent edges for transaction %d: %w", txID,
			err)
	}

	return nil
}

func updateTxStatusSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, status TxStatus, txIDs []int64) error {

	if len(txIDs) == 0 {
		return nil
	}

	_, err := qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcsqlite.UpdateTransactionStatusByIDsParams{
			Status:   string(status),
			WalletID: int64(walletID),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("update transaction status to %s: %w", status, err)
	}

	return nil
}

func recordReplacementEdgeSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, replacedTxID int64, replacementTxID int64) error {

	_, err := qtx.InsertTxReplacementEdge(
		ctx, sqlcsqlite.InsertTxReplacementEdgeParams{
			WalletID:        int64(walletID),
			ReplacedTxID:    replacedTxID,
			ReplacementTxID: replacementTxID,
		},
	)
	if err != nil {
		return fmt.Errorf("record replacement edge %d -> %d: %w",
			replacedTxID, replacementTxID, err)
	}

	return nil
}

func reclaimInputsByTxidSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, txid chainhash.Hash, txID int64) error {

	row, err := qtx.GetTransactionByHash(
		ctx, sqlcsqlite.GetTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("transaction %s: %w", txid, ErrTxNotFound)
		}

		return fmt.Errorf("get transaction for input reclaim: %w", err)
	}

	tx, err := deserializeMsgTx(row.RawTx)
	if err != nil {
		return err
	}

	err = markInputsSpentSqlite(ctx, qtx, CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
	}, txID)
	if err != nil {
		return fmt.Errorf("reclaim inputs for transaction %s: %w", txid, err)
	}

	err = ensureWalletOwnedInputsReclaimedSqlite(ctx, qtx, walletID, tx, txID)
	if err != nil {
		return fmt.Errorf("verify reclaimed inputs for transaction %s: %w",
			txid, err)
	}

	return nil
}

func ensureWalletOwnedInputsReclaimedSqlite(ctx context.Context,
	qtx *sqlcsqlite.Queries, walletID uint32, tx *wire.MsgTx,
	txID int64) error {

	for inputIndex, txIn := range tx.TxIn {
		spenderID, err := qtx.GetUtxoSpenderByOutpoint(
			ctx, sqlcsqlite.GetUtxoSpenderByOutpointParams{
				WalletID:    int64(walletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: int64(txIn.PreviousOutPoint.Index),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}

			return fmt.Errorf("get input claim %d: %w", inputIndex, err)
		}

		if !spenderID.Valid || spenderID.Int64 != txID {
			return fmt.Errorf("input %d: %w", inputIndex,
				errWinnerInputNotReclaimed)
		}
	}

	return nil
}
