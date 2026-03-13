package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

var _ TxReplacementStore = (*PostgresStore)(nil)

// ApplyTxReplacement records directed replacement edges for one live
// unconfirmed winner, marks each direct victim as replaced, recursively fails
// descendants, and reclaims the winner's spent-input edges inside one SQL
// transaction. Every supplied victim must directly conflict with the winner
// on a wallet-owned input.
func (s *PostgresStore) ApplyTxReplacement(ctx context.Context,
	params ApplyTxReplacementParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return applyTxReplacementCommon(
			ctx, params,
			func(ctx context.Context,
				txid chainhash.Hash) (txChainMeta, error) {

				return loadTxChainMetaPg(ctx, qtx, params.WalletID, txid)
			},
			func(ctx context.Context,
				txids []chainhash.Hash) ([]txChainMeta, error) {

				return loadTxChainMetasPg(ctx, qtx, params.WalletID, txids)
			},
			buildTxChainHooksPg(qtx, params.WalletID),
		)
	})
}

// ApplyTxFailure marks each direct loser as failed, recursively fails
// descendants, and reclaims the winner's spent-input edges inside one SQL
// transaction. This is the direct-conflict path for winners that are confirmed
// or otherwise not eligible for mempool replacement semantics. Every supplied
// loser must directly conflict with the winner on a wallet-owned input.
func (s *PostgresStore) ApplyTxFailure(ctx context.Context,
	params ApplyTxFailureParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return applyTxFailureCommon(
			ctx, params,
			func(ctx context.Context,
				txid chainhash.Hash) (txChainMeta, error) {

				return loadTxChainMetaPg(ctx, qtx, params.WalletID, txid)
			},
			func(ctx context.Context,
				txids []chainhash.Hash) ([]txChainMeta, error) {

				return loadTxChainMetasPg(ctx, qtx, params.WalletID, txids)
			},
			buildTxChainHooksPg(qtx, params.WalletID),
		)
	})
}

// OrphanTxChain recursively fails every descendant of the provided orphaned
// coinbase roots while keeping the roots themselves in the orphaned state.
func (s *PostgresStore) OrphanTxChain(ctx context.Context,
	params OrphanTxChainParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		roots, err := loadTxChainMetasPg(
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
			buildTxChainHooksPg(qtx, params.WalletID),
		)
	})
}

// ReconfirmOrphanedCoinbase restores one orphaned coinbase transaction to a new
// confirming block inside one SQL transaction. This is intentionally a
// root-only transition: coinbase spends require maturity, so the supported
// reconfirmation path assumes no descendant branch needs replay.
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
				BlockHeight: blockHeight,
				WalletID:    int64(params.WalletID),
				TxHash:      params.Txid[:],
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

// buildTxChainHooksPg binds the shared replacement helpers to the postgres
// query set active for the surrounding SQL transaction.
//
//nolint:dupl // Backend-specific sqlc hooks differ only in generated types.
func buildTxChainHooksPg(qtx *sqlcpg.Queries, walletID uint32) txChainHooks {
	return buildTxChainHooks(
		func(ctx context.Context, parentID int64) ([]int64, error) {
			return listChildTxIDsPg(ctx, qtx, walletID, parentID)
		},
		func(ctx context.Context, txID int64) error {
			return clearSpentByTxIDPg(ctx, qtx, walletID, txID)
		},
		func(ctx context.Context, status TxStatus,
			txIDs []int64) error {

			return updateTxStatusPg(ctx, qtx, walletID, status, txIDs)
		},
		func(ctx context.Context, txid chainhash.Hash,
			txID int64) error {

			return reclaimInputsByTxidPg(ctx, qtx, walletID, txid, txID)
		},
		func(ctx context.Context, replacedTxID int64,
			replacementTxID int64) error {

			return recordReplacementEdgePg(
				ctx, qtx, walletID, replacedTxID, replacementTxID,
			)
		},
		func(ctx context.Context, txid chainhash.Hash) ([]txChainMeta, error) {
			return listDirectConflictRootsByTxidPg(
				ctx, qtx, walletID, txid,
			)
		},
	)
}

// loadTxChainMetasPg resolves one metadata row per requested transaction hash
// for the shared invalidation flows.
func loadTxChainMetasPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32,
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

// loadTxChainMetaPg loads the wallet-scoped metadata needed to validate one
// transaction's replacement or orphaning state.
func loadTxChainMetaPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32,
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

	status, err := parseTxStatus(int64(row.TxStatus))
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

// listChildTxIDsPg returns the direct spender transaction IDs for outputs
// created by the provided parent row.
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

// clearSpentByTxIDPg releases every wallet-owned spent-input edge currently
// claimed by the provided transaction row.
func clearSpentByTxIDPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32,
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

// updateTxStatusPg applies one wallet-scoped status update batch for the shared
// invalidation flows.
func updateTxStatusPg(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	status TxStatus, txIDs []int64) error {

	if len(txIDs) == 0 {
		return nil
	}

	_, err := qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcpg.UpdateTransactionStatusByIDsParams{
			Status:   int16(status),
			WalletID: int64(walletID),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("update transaction status to %s: %w", status, err)
	}

	return nil
}

// recordReplacementEdgePg inserts one victim-to-winner audit edge for a direct
// replacement relationship.
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

// reclaimInputsByTxidPg replays the winner's wallet-owned spent-input edges and
// verifies that reclamation completed before commit.
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

	err = ensureWalletOwnedInputsReclaimedPg(ctx, qtx, walletID, tx, txID)
	if err != nil {
		return fmt.Errorf("verify reclaimed inputs for transaction %s: %w",
			txid, err)
	}

	return nil
}

// listDirectConflictRootsByTxidPg loads the winner transaction and derives the
// complete live direct loser set for its wallet-owned inputs.
func listDirectConflictRootsByTxidPg(ctx context.Context,
	qtx *sqlcpg.Queries, walletID uint32,
	txid chainhash.Hash) ([]txChainMeta, error) {

	row, err := qtx.GetTransactionByHash(
		ctx, sqlcpg.GetTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("transaction %s: %w", txid, ErrTxNotFound)
		}

		return nil, fmt.Errorf("get transaction for root validation: %w", err)
	}

	tx, err := deserializeMsgTx(row.RawTx)
	if err != nil {
		return nil, err
	}

	return listDirectConflictRootsPg(ctx, qtx, walletID, row.ID, tx)
}

// listDirectConflictRootsPg scans live unconfirmed wallet transactions and
// returns those that directly conflict with the winner on wallet-owned inputs.
//

func listDirectConflictRootsPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, winnerID int64,
	tx *wire.MsgTx) ([]txChainMeta, error) {

	walletOwnedInputs, err := listWalletOwnedInputsPg(ctx, qtx, walletID, tx)
	if err != nil {
		return nil, err
	}

	if len(walletOwnedInputs) == 0 {
		return nil, nil
	}

	rows, err := qtx.ListLiveUnminedConflictCandidates(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf(
			"list live conflict candidates for root validation: %w", err,
		)
	}

	roots := make([]txChainMeta, 0, len(rows))

	for _, row := range rows {
		if row.ID == winnerID {
			continue
		}

		meta, ok, err := buildDirectConflictMeta(
			row.ID, row.TxHash, int64(row.TxStatus), false, row.IsCoinbase,
		)
		if err != nil {
			return nil, err
		}

		if !ok {
			continue
		}

		candidateTx, err := deserializeMsgTx(row.RawTx)
		if err != nil {
			return nil, err
		}

		if !txSpendsAnyOutpoint(candidateTx, walletOwnedInputs) {
			continue
		}

		roots = append(roots, meta)
	}

	return roots, nil
}

// listWalletOwnedInputsPg filters the winner's inputs down to wallet-owned
// outpoints, which define the eligible direct-conflict surface.
func listWalletOwnedInputsPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, tx *wire.MsgTx) (map[wire.OutPoint]struct{}, error) {

	walletOwnedInputs := make(map[wire.OutPoint]struct{}, len(tx.TxIn))

	for inputIndex, txIn := range tx.TxIn {
		outputIndex, err := uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return nil, fmt.Errorf("convert input outpoint index %d: %w",
				inputIndex, err)
		}

		_, err = qtx.GetUtxoSpendByOutpoint(
			ctx, sqlcpg.GetUtxoSpendByOutpointParams{
				WalletID:    int64(walletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: outputIndex,
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}

			return nil, fmt.Errorf("check wallet-owned input %d: %w",
				inputIndex, err)
		}

		walletOwnedInputs[txIn.PreviousOutPoint] = struct{}{}
	}

	return walletOwnedInputs, nil
}

// ensureWalletOwnedInputsReclaimedPg verifies that every wallet-owned input of
// the winner now points back to the winner row before commit.
func ensureWalletOwnedInputsReclaimedPg(ctx context.Context,
	qtx *sqlcpg.Queries,
	walletID uint32, tx *wire.MsgTx, txID int64) error {

	for inputIndex, txIn := range tx.TxIn {
		outputIndex, err := uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return fmt.Errorf("convert input outpoint index %d: %w",
				inputIndex, err)
		}

		spenderID, err := qtx.GetUtxoSpendByOutpoint(
			ctx, sqlcpg.GetUtxoSpendByOutpointParams{
				WalletID:    int64(walletID),
				TxHash:      txIn.PreviousOutPoint.Hash[:],
				OutputIndex: outputIndex,
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
