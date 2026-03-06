package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// ApplyTxReplacement records directed replacement edges, marks each direct
// victim as replaced, recursively fails descendants, and reclaims the winner's
// spent-input edges inside one SQL transaction.
func (s *PostgresStore) ApplyTxReplacement(ctx context.Context,
	params ApplyTxReplacementParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		winner, err := loadTxChainMetaPg(
			ctx, qtx, params.WalletID, params.ReplacementTxid,
		)
		if err != nil {
			return err
		}

		victims, err := loadTxChainMetasPg(
			ctx, qtx, params.WalletID, params.ReplacedTxids,
		)
		if err != nil {
			return err
		}

		err = validateReplacementPlan(winner, victims)
		if err != nil {
			return err
		}

		for _, victim := range victims {
			err := recordReplacementEdgePg(
				ctx, qtx, params.WalletID, victim.ID, winner.ID,
			)
			if err != nil {
				return err
			}
		}

		err = applyTxChainInvalidation(
			ctx, txIDsFromMetas(victims), TxStatusReplaced,
			buildTxChainHooksPg(qtx, params.WalletID),
		)
		if err != nil {
			return err
		}

		return reclaimInputsByTxidPg(
			ctx, qtx, params.WalletID, params.ReplacementTxid, winner.ID,
		)
	})
}

// ApplyTxFailure marks each direct loser as failed, recursively fails
// descendants, and reclaims the winner's spent-input edges inside one SQL
// transaction.
func (s *PostgresStore) ApplyTxFailure(ctx context.Context,
	params ApplyTxFailureParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		winner, err := loadTxChainMetaPg(
			ctx, qtx, params.WalletID, params.ConflictingTxid,
		)
		if err != nil {
			return err
		}

		roots, err := loadTxChainMetasPg(
			ctx, qtx, params.WalletID, params.FailedTxids,
		)
		if err != nil {
			return err
		}

		err = validateFailurePlan(winner, roots)
		if err != nil {
			return err
		}

		err = applyTxChainInvalidation(
			ctx, txIDsFromMetas(roots), TxStatusFailed,
			buildTxChainHooksPg(qtx, params.WalletID),
		)
		if err != nil {
			return err
		}

		return reclaimInputsByTxidPg(
			ctx, qtx, params.WalletID, params.ConflictingTxid, winner.ID,
		)
	})
}

// OrphanTxChain recursively fails every descendant of the provided orphaned
// coinbase roots while keeping the roots themselves in the orphaned state.
func (s *PostgresStore) OrphanTxChain(ctx context.Context,
	params OrphanTxChainParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		roots, err := loadTxChainMetasPg(ctx, qtx, params.WalletID, params.Txids)
		if err != nil {
			return err
		}

		err = validateOrphanPlan(roots)
		if err != nil {
			return err
		}

		return applyTxChainInvalidation(
			ctx, txIDsFromMetas(roots), TxStatusOrphaned,
			buildTxChainHooksPg(qtx, params.WalletID),
		)
	})
}

// ReconfirmOrphanedCoinbase restores one orphaned coinbase transaction to a new
// confirming block inside one SQL transaction.
func (s *PostgresStore) ReconfirmOrphanedCoinbase(ctx context.Context,
	params ReconfirmOrphanedCoinbaseParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		meta, err := loadTxChainMetaPg(ctx, qtx, params.WalletID, params.Txid)
		if err != nil {
			return err
		}

		err = validateCoinbaseReconfirmation(meta)
		if err != nil {
			return err
		}

		err = ensureBlockExistsPg(ctx, qtx, &params.Block)
		if err != nil {
			return fmt.Errorf("ensure block exists: %w", err)
		}

		blockHeight, err := uint32ToInt32(params.Block.Height)
		if err != nil {
			return fmt.Errorf("convert block height: %w", err)
		}

		rows, err := qtx.ReconfirmOrphanedCoinbaseByHash(
			ctx, sqlcpg.ReconfirmOrphanedCoinbaseByHashParams{
				BlockHeight: sql.NullInt32{Int32: blockHeight, Valid: true},
				WalletID:    int64(params.WalletID),
				TxHash:      params.Txid[:],
			},
		)
		if err != nil {
			return fmt.Errorf("reconfirm orphaned coinbase: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("transaction %s: orphaned coinbase state changed",
				params.Txid)
		}

		return nil
	})
}

func buildTxChainHooksPg(qtx *sqlcpg.Queries, walletID uint32) txChainHooks {
	return txChainHooks{
		ListChildren: func(ctx context.Context, parentID int64) ([]int64, error) {
			return listChildTxIDsPg(ctx, qtx, walletID, parentID)
		},
		ClearSpentByTx: func(ctx context.Context, txID int64) error {
			return clearSpentByTxIDPg(ctx, qtx, walletID, txID)
		},
		UpdateStatus: func(ctx context.Context, status TxStatus,
			txIDs []int64) error {

			return updateTxStatusPg(ctx, qtx, walletID, status, txIDs)
		},
	}
}

func loadTxChainMetasPg(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	txids []chainhash.Hash) ([]txChainMeta, error) {

	metas := make([]txChainMeta, len(txids))
	for i, txid := range txids {
		meta, err := loadTxChainMetaPg(ctx, qtx, walletID, txid)
		if err != nil {
			return nil, err
		}

		metas[i] = meta
	}

	return metas, nil
}

func loadTxChainMetaPg(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	txid chainhash.Hash) (txChainMeta, error) {

	row, err := qtx.GetTransactionMetaByHash(
		ctx, sqlcpg.GetTransactionMetaByHashParams{
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

func listChildTxIDsPg(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	parentID int64) ([]int64, error) {

	rows, err := qtx.ListSpendingTxIDsByParentTxID(
		ctx, sqlcpg.ListSpendingTxIDsByParentTxIDParams{
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

func clearSpentByTxIDPg(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	txID int64) error {

	_, err := qtx.ClearUtxosSpentByTxID(
		ctx, sqlcpg.ClearUtxosSpentByTxIDParams{
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

func updateTxStatusPg(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	status TxStatus, txIDs []int64) error {

	if len(txIDs) == 0 {
		return nil
	}

	_, err := qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcpg.UpdateTransactionStatusByIDsParams{
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

func recordReplacementEdgePg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, replacedTxID int64, replacementTxID int64) error {

	_, err := qtx.InsertTxReplacementEdge(
		ctx, sqlcpg.InsertTxReplacementEdgeParams{
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

func reclaimInputsByTxidPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txid chainhash.Hash, txID int64) error {

	row, err := qtx.GetTransactionByHash(
		ctx, sqlcpg.GetTransactionByHashParams{
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

	err = markInputsSpentPg(ctx, qtx, CreateTxParams{
		WalletID: walletID,
		Tx:       tx,
	}, txID)
	if err != nil {
		return fmt.Errorf("reclaim inputs for transaction %s: %w", txid, err)
	}

	return nil
}
