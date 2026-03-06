package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Ensure PostgresStore satisfies the TxStore interface.
var _ TxStore = (*PostgresStore)(nil)

// CreateTx atomically records a transaction row, its wallet-owned credits, and
// any spend edges created by its inputs.
func (s *PostgresStore) CreateTx(ctx context.Context,
	params CreateTxParams) error {

	err := validateCreateTxParams(params)
	if err != nil {
		return fmt.Errorf("validate create tx params: %w", err)
	}

	rawTx, err := serializeMsgTx(params.Tx)
	if err != nil {
		return err
	}

	txHash := params.Tx.TxHash()
	isCoinbase := blockchain.IsCoinBaseTx(params.Tx)
	received := params.Received.UTC()

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		blockHeight := sql.NullInt32{}
		if params.Block != nil {
			err := ensureBlockExistsPg(ctx, qtx, params.Block)
			if err != nil {
				return fmt.Errorf("ensure block exists: %w", err)
			}

			height, err := uint32ToInt32(params.Block.Height)
			if err != nil {
				return fmt.Errorf("convert block height: %w", err)
			}

			blockHeight = sql.NullInt32{Int32: height, Valid: true}
		}

		txID, err := qtx.InsertTransaction(ctx, sqlcpg.InsertTransactionParams{
			WalletID:     int64(params.WalletID),
			TxHash:       txHash[:],
			RawTx:        rawTx,
			BlockHeight:  blockHeight,
			Status:       string(params.Status),
			ReceivedTime: received,
			IsCoinbase:   isCoinbase,
			Label:        params.Label,
		})
		if err != nil {
			return fmt.Errorf("insert transaction: %w", err)
		}

		err = insertCreditsPg(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		err = markInputsSpentPg(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		return nil
	})
}

// UpdateTx updates the user-visible transaction label for one wallet-scoped
// transaction.
func (s *PostgresStore) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	rows, err := s.queries.UpdateTransactionLabelByHash(
		ctx, sqlcpg.UpdateTransactionLabelByHashParams{
			Label:    params.Label,
			WalletID: int64(params.WalletID),
			TxHash:   params.Txid[:],
		},
	)
	if err != nil {
		return fmt.Errorf("update transaction label: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("transaction %s: %w", params.Txid, ErrTxNotFound)
	}

	return nil
}

// GetTx retrieves a wallet-scoped transaction by hash.
func (s *PostgresStore) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlcpg.GetTransactionByHashParams{
			WalletID: int64(query.WalletID),
			TxHash:   query.Txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("transaction %s: %w", query.Txid,
				ErrTxNotFound)
		}

		return nil, fmt.Errorf("get transaction: %w", err)
	}

	return txInfoFromPgRow(
		row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
		row.BlockHash, row.BlockTimestamp, row.Status, row.Label,
	)
}

// ListTxns lists wallet-scoped transactions using either the confirmed-range or
// unmined-only read path.
func (s *PostgresStore) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	if query.UnminedOnly {
		return s.listUnminedTxns(ctx, query.WalletID)
	}

	return s.listConfirmedTxns(ctx, query)
}

func (s *PostgresStore) listUnminedTxns(ctx context.Context,
	walletID uint32) ([]TxInfo, error) {

	rows, err := s.queries.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list unmined transactions: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		info, err := txInfoFromPgRow(
			row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
			row.BlockHash, row.BlockTimestamp, row.Status, row.Label,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

func (s *PostgresStore) listConfirmedTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	startHeight, err := uint32ToInt32(query.StartHeight)
	if err != nil {
		return nil, fmt.Errorf("convert start height: %w", err)
	}

	endHeight, err := uint32ToInt32(query.EndHeight)
	if err != nil {
		return nil, fmt.Errorf("convert end height: %w", err)
	}

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlcpg.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: sql.NullInt32{Int32: startHeight, Valid: true},
			EndHeight:   sql.NullInt32{Int32: endHeight, Valid: true},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions by height: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		block, err := buildPgConfirmedBlock(row.BlockHeight, row.BlockHash,
			row.BlockTimestamp)
		if err != nil {
			return nil, err
		}

		info, err := buildTxInfo(
			row.TxHash, row.RawTx, row.ReceivedTime, block, row.Status,
			row.Label,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// DeleteTx removes one live unconfirmed transaction and restores any wallet
// UTXO rows that it had spent.
func (s *PostgresStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return deleteTxCommon(
			ctx, params.Txid, buildTxDeleteHooksPg(qtx, params),
		)
	})
}

// buildTxDeleteHooksPg binds the shared delete flow to the postgres query set
// active for the surrounding SQL transaction.
func buildTxDeleteHooksPg(qtx *sqlcpg.Queries,
	params DeleteTxParams) txDeleteHooks {

	return buildTxDeleteHooks(
		func(ctx context.Context) (txChainMeta, error) {
			return loadTxChainMetaPg(ctx, qtx, params.WalletID, params.Txid)
		},
		func(ctx context.Context, txID int64) ([]int64, error) {
			return listChildTxIDsPg(ctx, qtx, params.WalletID, txID)
		},
		func(ctx context.Context, txID int64) error {
			return clearSpentByTxIDPg(ctx, qtx, params.WalletID, txID)
		},
		func(ctx context.Context, txID int64) error {
			return deleteUtxosByTxIDPg(ctx, qtx, params.WalletID, txID)
		},
		func(ctx context.Context) (int64, error) {
			return deleteUnminedTxByHashPg(
				ctx, qtx, params.WalletID, params.Txid,
			)
		},
	)
}

// deleteUtxosByTxIDPg removes the wallet-owned outputs created by one
// transaction before its row is pruned from the live graph.
func deleteUtxosByTxIDPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txID int64) error {

	_, err := qtx.DeleteUtxosByTxID(
		ctx, sqlcpg.DeleteUtxosByTxIDParams{
			WalletID: int64(walletID),
			TxID:     txID,
		},
	)
	if err != nil {
		return fmt.Errorf("delete created utxos: %w", err)
	}

	return nil
}

// deleteUnminedTxByHashPg removes the unconfirmed transaction row after its
// dependent UTXO edges have already been cleared.
func deleteUnminedTxByHashPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txid [32]byte) (int64, error) {

	rows, err := qtx.DeleteUnminedTransactionByHash(
		ctx, sqlcpg.DeleteUnminedTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txid[:],
		},
	)
	if err != nil {
		return 0, fmt.Errorf("delete unmined transaction: %w", err)
	}

	return rows, nil
}

// RollbackToBlock removes every block at or above the provided
// height and rewrites wallet sync-state references so the block
// delete can succeed.
func (s *PostgresStore) RollbackToBlock(ctx context.Context,
	height uint32) error {

	rollbackHeight, err := uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("convert rollback height: %w", err)
	}

	rollbackArg := sql.NullInt32{Int32: rollbackHeight, Valid: true}

	newHeight := sql.NullInt32{}
	if height > 0 {
		clampedHeight, err := uint32ToInt32(height - 1)
		if err != nil {
			return fmt.Errorf("convert new height: %w", err)
		}

		newHeight = sql.NullInt32{Int32: clampedHeight, Valid: true}
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		_, err := qtx.ClampWalletSyncStateHeightsForRollback(
			ctx, sqlcpg.ClampWalletSyncStateHeightsForRollbackParams{
				RollbackHeight: rollbackArg,
				NewHeight:      newHeight,
			},
		)
		if err != nil {
			return fmt.Errorf("clamp wallet sync state heights: %w", err)
		}

		_, err = qtx.DeleteBlocksAtOrAboveHeight(ctx, rollbackHeight)
		if err != nil {
			return fmt.Errorf("delete blocks at or above height: %w", err)
		}

		return nil
	})
}

func insertCreditsPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	for _, credit := range params.Credits {
		pkScript := params.Tx.TxOut[credit.Index].PkScript

		addrRow, err := qtx.GetAddressByScriptPubKey(
			ctx, sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: pkScript,
				WalletID:     int64(params.WalletID),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("credit output %d: %w", credit.Index,
					ErrAddressNotFound)
			}

			return fmt.Errorf("resolve credit address %d: %w", credit.Index,
				err)
		}

		outputIndex, err := uint32ToInt32(credit.Index)
		if err != nil {
			return fmt.Errorf("convert credit index %d: %w", credit.Index,
				err)
		}

		_, err = qtx.InsertUtxo(ctx, sqlcpg.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: outputIndex,
			Amount:      params.Tx.TxOut[credit.Index].Value,
			AddressID:   addrRow.ID,
		})
		if err != nil {
			return fmt.Errorf("insert credit output %d: %w", credit.Index,
				err)
		}
	}

	return nil
}

func markInputsSpentPg(ctx context.Context, qtx *sqlcpg.Queries,
	params CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		outputIndex, err := uint32ToInt32(txIn.PreviousOutPoint.Index)
		if err != nil {
			return fmt.Errorf("convert input outpoint index %d: %w",
				inputIndex, err)
		}

		spentInputIndex, err := intToInt32(inputIndex)
		if err != nil {
			return fmt.Errorf("convert input index %d: %w", inputIndex, err)
		}

		_, err = qtx.MarkUtxoSpent(ctx, sqlcpg.MarkUtxoSpentParams{
			WalletID:        int64(params.WalletID),
			TxHash:          txIn.PreviousOutPoint.Hash[:],
			OutputIndex:     outputIndex,
			SpentByTxID:     sql.NullInt64{Int64: txID, Valid: true},
			SpentInputIndex: sql.NullInt32{Int32: spentInputIndex, Valid: true},
		})
		if err != nil {
			return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
		}
	}

	return nil
}

func txInfoFromPgRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt32, blockHash []byte, blockTimestamp sql.NullInt64,
	status string, label string) (*TxInfo, error) {

	block, _, err := buildPgOptionalBlock(
		blockHeight, blockHash, blockTimestamp,
	)
	if err != nil {
		return nil, err
	}

	return buildTxInfo(
		hash, rawTx, received, block, status, label,
	)
}

func buildPgOptionalBlock(height sql.NullInt32, hash []byte,
	timestamp sql.NullInt64) (*Block, bool, error) {

	if !height.Valid {
		return nil, false, nil
	}

	block, err := buildPgBlock(height, hash, timestamp)
	if err != nil {
		return nil, false, err
	}

	return block, true, nil
}

func buildPgConfirmedBlock(height sql.NullInt32, hash []byte,
	timestamp int64) (*Block, error) {

	return buildPgBlock(
		height, hash, sql.NullInt64{Int64: timestamp, Valid: true},
	)
}
