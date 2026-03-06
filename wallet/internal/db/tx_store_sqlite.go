package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SqliteStore satisfies the TxStore interface.
var _ TxStore = (*SqliteStore)(nil)

// CreateTx atomically records a transaction row, its wallet-owned credits, and
// any spend edges created by its inputs.
func (s *SqliteStore) CreateTx(ctx context.Context,
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

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		blockHeight := sql.NullInt64{}
		if params.Block != nil {
			err := ensureBlockExistsSqlite(ctx, qtx, params.Block)
			if err != nil {
				return fmt.Errorf("ensure block exists: %w", err)
			}

			blockHeight = sql.NullInt64{Int64: int64(params.Block.Height), Valid: true}
		}

		txID, err := qtx.InsertTransaction(ctx, sqlcsqlite.InsertTransactionParams{
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

		err = insertCreditsSqlite(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		err = markInputsSpentSqlite(ctx, qtx, params, txID)
		if err != nil {
			return err
		}

		return nil
	})
}

// UpdateTx updates the user-visible transaction label for one wallet-scoped
// transaction.
func (s *SqliteStore) UpdateTx(ctx context.Context,
	params UpdateTxParams) error {

	rows, err := s.queries.UpdateTransactionLabelByHash(
		ctx, sqlcsqlite.UpdateTransactionLabelByHashParams{
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
func (s *SqliteStore) GetTx(ctx context.Context,
	query GetTxQuery) (*TxInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlcsqlite.GetTransactionByHashParams{
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

	return txInfoFromSqliteRow(
		row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
		row.BlockHash, row.BlockTimestamp, row.Status, row.Label,
	)
}

// ListTxns lists wallet-scoped transactions using either the confirmed-range or
// unmined-only read path.
func (s *SqliteStore) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	if query.UnminedOnly {
		rows, err := s.queries.ListUnminedTransactions(
			ctx, int64(query.WalletID),
		)
		if err != nil {
			return nil, fmt.Errorf("list unmined transactions: %w", err)
		}

		infos := make([]TxInfo, len(rows))
		for i, row := range rows {
			info, err := txInfoFromSqliteRow(
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

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlcsqlite.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: sql.NullInt64{Int64: int64(query.StartHeight), Valid: true},
			EndHeight:   sql.NullInt64{Int64: int64(query.EndHeight), Valid: true},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list transactions by height: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		block, err := buildSqliteConfirmedBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
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
func (s *SqliteStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		meta, err := qtx.GetTransactionMetaByHash(
			ctx, sqlcsqlite.GetTransactionMetaByHashParams{
				WalletID: int64(params.WalletID),
				TxHash:   params.Txid[:],
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("transaction %s: %w", params.Txid,
					ErrTxNotFound)
			}

			return fmt.Errorf("get transaction metadata: %w", err)
		}

		status, err := parseTxStatus(meta.Status)
		if err != nil {
			return err
		}

		if meta.BlockHeight.Valid || !isLiveUnconfirmedStatus(status) {
			return fmt.Errorf(
				"delete transaction %s: live unconfirmed transaction required",
				params.Txid,
			)
		}

		_, err = qtx.ClearUtxosSpentByTxID(
			ctx, sqlcsqlite.ClearUtxosSpentByTxIDParams{
				WalletID:    int64(params.WalletID),
				SpentByTxID: sql.NullInt64{Int64: meta.ID, Valid: true},
			},
		)
		if err != nil {
			return fmt.Errorf("clear spent utxos: %w", err)
		}

		_, err = qtx.DeleteUtxosByTxID(
			ctx, sqlcsqlite.DeleteUtxosByTxIDParams{
				WalletID: int64(params.WalletID),
				TxID:     meta.ID,
			},
		)
		if err != nil {
			return fmt.Errorf("delete created utxos: %w", err)
		}

		rows, err := qtx.DeleteUnminedTransactionByHash(
			ctx, sqlcsqlite.DeleteUnminedTransactionByHashParams{
				WalletID: int64(params.WalletID),
				TxHash:   params.Txid[:],
			},
		)
		if err != nil {
			return fmt.Errorf("delete unmined transaction: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("transaction %s: %w", params.Txid,
				ErrTxNotFound)
		}

		return nil
	})
}

// RollbackToBlock removes every block at or above the provided height and
// rewrites wallet sync-state references so the block delete can succeed.
func (s *SqliteStore) RollbackToBlock(ctx context.Context, height uint32) error {

	rollbackArg := sql.NullInt64{Int64: int64(height), Valid: true}
	newHeight := sql.NullInt64{}
	if height > 0 {
		newHeight = sql.NullInt64{Int64: int64(height - 1), Valid: true}
	}

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		_, err := qtx.ClampWalletSyncStateHeightsForRollback(
			ctx, sqlcsqlite.ClampWalletSyncStateHeightsForRollbackParams{
				RollbackHeight: rollbackArg,
				NewHeight:      newHeight,
			},
		)
		if err != nil {
			return fmt.Errorf("clamp wallet sync state heights: %w", err)
		}

		_, err = qtx.DeleteBlocksAtOrAboveHeight(ctx, int64(height))
		if err != nil {
			return fmt.Errorf("delete blocks at or above height: %w", err)
		}

		return nil
	})
}

func insertCreditsSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	params CreateTxParams, txID int64) error {

	for _, credit := range params.Credits {
		pkScript := params.Tx.TxOut[credit.Index].PkScript

		addrRow, err := qtx.GetAddressByScriptPubKey(
			ctx, sqlcsqlite.GetAddressByScriptPubKeyParams{
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

		_, err = qtx.InsertUtxo(ctx, sqlcsqlite.InsertUtxoParams{
			WalletID:    int64(params.WalletID),
			TxID:        txID,
			OutputIndex: int64(credit.Index),
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

func markInputsSpentSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	params CreateTxParams, txID int64) error {

	if blockchain.IsCoinBaseTx(params.Tx) {
		return nil
	}

	for inputIndex, txIn := range params.Tx.TxIn {
		_, err := qtx.MarkUtxoSpent(ctx, sqlcsqlite.MarkUtxoSpentParams{
			WalletID:        int64(params.WalletID),
			TxHash:          txIn.PreviousOutPoint.Hash[:],
			OutputIndex:     int64(txIn.PreviousOutPoint.Index),
			SpentByTxID:     sql.NullInt64{Int64: txID, Valid: true},
			SpentInputIndex: sql.NullInt64{Int64: int64(inputIndex), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("mark spent input %d: %w", inputIndex, err)
		}
	}

	return nil
}

func txInfoFromSqliteRow(hash []byte, rawTx []byte, received time.Time,
	blockHeight sql.NullInt64, blockHash []byte, blockTimestamp sql.NullInt64,
	status string, label string) (*TxInfo, error) {

	block, err := buildSqliteOptionalBlock(blockHeight, blockHash, blockTimestamp)
	if err != nil {
		return nil, err
	}

	return buildTxInfo(
		hash, rawTx, received, block, status, label,
	)
}

func buildSqliteOptionalBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	if !height.Valid {
		return nil, nil
	}

	return buildSqliteBlock(height, hash, timestamp)
}

func buildSqliteConfirmedBlock(height sql.NullInt64, hash []byte,
	timestamp int64) (*Block, error) {

	return buildSqliteBlock(height, hash, sql.NullInt64{Int64: timestamp, Valid: true})
}
