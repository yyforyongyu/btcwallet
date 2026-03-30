package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// pgTxDetailBase captures the base normalized transaction fields needed to
// assemble one Postgres-backed TxDetailInfo.
type pgTxDetailBase struct {
	// ID is the internal transaction row identifier.
	ID int64

	// TxHash is the serialized transaction hash.
	TxHash []byte

	// RawTx is the serialized wire transaction.
	RawTx []byte

	// ReceivedTime is when the wallet observed the transaction.
	ReceivedTime time.Time

	// BlockHeight holds the confirming block height when the tx is mined.
	BlockHeight sql.NullInt32

	// BlockHash holds the confirming block hash when the tx is mined.
	BlockHash []byte

	// BlockTimestamp holds the confirming block timestamp when the tx is mined.
	BlockTimestamp sql.NullInt64

	// TxStatus is the persisted wallet-relative transaction status code.
	TxStatus int64

	// TxLabel is the optional user-supplied transaction label.
	TxLabel string
}

// GetTxDetail retrieves one detailed wallet-scoped transaction view by hash.
func (s *PostgresStore) GetTxDetail(ctx context.Context,
	query GetTxDetailQuery) (*TxDetailInfo, error) {

	row, err := s.queries.GetTransactionByHash(
		ctx, sqlc.GetTransactionByHashParams{
			WalletID: int64(query.WalletID),
			TxHash:   query.Txid[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("transaction %s: %w", query.Txid,
				ErrTxNotFound)
		}

		return nil, fmt.Errorf("get transaction detail: %w", err)
	}

	base := pgTxDetailBase{
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

	ownedOutputs, err := s.loadOwnedOutputsForTxIDsPg(
		ctx, query.WalletID, []int64{row.ID},
	)
	if err != nil {
		return nil, err
	}

	ownedInputs, err := s.loadOwnedInputsForTxIDsPg(
		ctx, query.WalletID, []int64{row.ID},
	)
	if err != nil {
		return nil, err
	}

	return txDetailFromPgBase(base, ownedInputs[row.ID], ownedOutputs[row.ID])
}

// txDetailFromPgBase assembles a TxDetailInfo from one Postgres base row plus
// its owned input and output edge data.
func txDetailFromPgBase(base pgTxDetailBase,
	ownedInputs []TxOwnedInput, ownedOutputs []TxOwnedOutput) (*TxDetailInfo,
	error) {

	var (
		block *Block
		err   error
	)

	if base.BlockHeight.Valid {
		block, err = buildPgBlock(
			base.BlockHeight, base.BlockHash, base.BlockTimestamp,
		)
		if err != nil {
			return nil, err
		}
	}

	msgTx, err := deserializeMsgTx(base.RawTx)
	if err != nil {
		return nil, err
	}

	return buildTxDetailInfo(
		base.TxHash, msgTx, base.RawTx, base.ReceivedTime, block,
		base.TxStatus, base.TxLabel, ownedInputs, ownedOutputs,
	)
}

// loadOwnedOutputsForTxIDsPg loads all wallet-owned outputs created by the
// selected Postgres transaction rows and groups them by tx id.
func (s *PostgresStore) loadOwnedOutputsForTxIDsPg(ctx context.Context,
	walletID uint32, txIDs []int64) (map[int64][]TxOwnedOutput, error) {

	rows, err := s.queries.ListOwnedOutputsByTxIDs(
		ctx, sqlc.ListOwnedOutputsByTxIDsParams{
			WalletID: int64(walletID),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list owned outputs by tx ids: %w", err)
	}

	result := make(map[int64][]TxOwnedOutput)
	for _, row := range rows {
		index, err := int64ToUint32(int64(row.OutputIndex))
		if err != nil {
			return nil, fmt.Errorf("owned output index: %w", err)
		}

		result[row.TxID] = append(
			result[row.TxID],
			buildTxOwnedOutput(index, row.Amount),
		)
	}

	return result, nil
}

// loadOwnedInputsForTxIDsPg loads all wallet-owned inputs spent by the
// selected Postgres transaction rows and groups them by spender tx id.
func (s *PostgresStore) loadOwnedInputsForTxIDsPg(ctx context.Context,
	walletID uint32, txIDs []int64) (map[int64][]TxOwnedInput, error) {

	rows, err := s.queries.ListOwnedInputsBySpendingTxIDs(
		ctx, sqlc.ListOwnedInputsBySpendingTxIDsParams{
			WalletID: int64(walletID),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list owned inputs by spending tx ids: %w", err)
	}

	result := make(map[int64][]TxOwnedInput)
	for _, row := range rows {
		if !row.SpentByTxID.Valid || !row.SpentInputIndex.Valid {
			continue
		}

		index, err := int64ToUint32(int64(row.SpentInputIndex.Int32))
		if err != nil {
			return nil, fmt.Errorf("owned input index: %w", err)
		}

		result[row.SpentByTxID.Int64] = append(
			result[row.SpentByTxID.Int64],
			buildTxOwnedInput(index, row.Amount),
		)
	}

	return result, nil
}
