package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Ensure PostgresStore satisfies the UTXOStore interface.
var _ UTXOStore = (*PostgresStore)(nil)

// GetUtxo retrieves one live wallet-owned UTXO by outpoint.
func (s *PostgresStore) GetUtxo(ctx context.Context,
	query GetUtxoQuery) (*UtxoInfo, error) {

	outputIndex, err := uint32ToInt32(query.OutPoint.Index)
	if err != nil {
		return nil, fmt.Errorf("convert output index: %w", err)
	}

	row, err := s.queries.GetUtxoByOutpoint(
		ctx, sqlcpg.GetUtxoByOutpointParams{
			WalletID:    int64(query.WalletID),
			TxHash:      query.OutPoint.Hash[:],
			OutputIndex: outputIndex,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("utxo %s: %w", query.OutPoint,
				ErrUtxoNotFound)
		}

		return nil, fmt.Errorf("get utxo: %w", err)
	}

	return utxoInfoFromPgRow(
		row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
		row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
	)
}

// ListUTXOs lists all live wallet-owned UTXOs matching the caller filters.
func (s *PostgresStore) ListUTXOs(ctx context.Context,
	query ListUtxosQuery) ([]UtxoInfo, error) {

	params, err := buildListUtxosParamsPg(query)
	if err != nil {
		return nil, err
	}

	rows, err := s.queries.ListUtxos(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	utxos := make([]UtxoInfo, len(rows))
	for i, row := range rows {
		utxo, err := utxoInfoFromPgRow(
			row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
			row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
		)
		if err != nil {
			return nil, err
		}

		utxos[i] = *utxo
	}

	return utxos, nil
}

// LeaseOutput acquires or renews a lease for one live UTXO.
func (s *PostgresStore) LeaseOutput(ctx context.Context,
	params LeaseOutputParams) (*LeasedOutput, error) {

	expiresAt := time.Now().UTC().Add(params.Duration)

	var lease *LeasedOutput
	err := s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		expiration, err := qtx.AcquireUtxoLease(
			ctx, sqlcpg.AcquireUtxoLeaseParams{
				WalletID:    int64(params.WalletID),
				LockID:      params.ID[:],
				ExpiresAt:   expiresAt,
				TxHash:      params.OutPoint.Hash[:],
				OutputIndex: mustUint32ToInt32(params.OutPoint.Index),
			},
		)
		if err == nil {
			lease = &LeasedOutput{
				OutPoint:   params.OutPoint,
				LockID:     LockID(params.ID),
				Expiration: expiration.UTC(),
			}

			return nil
		}

		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("acquire utxo lease: %w", err)
		}

		_, lookupErr := qtx.GetUtxoIDByOutpoint(
			ctx, sqlcpg.GetUtxoIDByOutpointParams{
				WalletID:    int64(params.WalletID),
				TxHash:      params.OutPoint.Hash[:],
				OutputIndex: mustUint32ToInt32(params.OutPoint.Index),
			},
		)
		if lookupErr != nil {
			if errors.Is(lookupErr, sql.ErrNoRows) {
				return fmt.Errorf("utxo %s: %w", params.OutPoint,
					ErrUtxoNotFound)
			}

			return fmt.Errorf("lookup utxo before lease conflict: %w",
				lookupErr)
		}

		return fmt.Errorf("utxo %s: %w", params.OutPoint,
			errOutputAlreadyLeased)
	})
	if err != nil {
		return nil, err
	}

	return lease, nil
}

// ReleaseOutput releases a lease when the caller provides the active lock ID.
func (s *PostgresStore) ReleaseOutput(ctx context.Context,
	params ReleaseOutputParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		utxoID, err := qtx.GetUtxoIDByOutpoint(
			ctx, sqlcpg.GetUtxoIDByOutpointParams{
				WalletID:    int64(params.WalletID),
				TxHash:      params.OutPoint.Hash[:],
				OutputIndex: mustUint32ToInt32(params.OutPoint.Index),
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("utxo %s: %w", params.OutPoint,
					ErrUtxoNotFound)
			}

			return fmt.Errorf("lookup utxo for release: %w", err)
		}

		rows, err := qtx.ReleaseUtxoLease(
			ctx, sqlcpg.ReleaseUtxoLeaseParams{
				WalletID: int64(params.WalletID),
				UtxoID:   utxoID,
				LockID:   params.ID[:],
			},
		)
		if err != nil {
			return fmt.Errorf("release utxo lease: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("utxo %s: %w", params.OutPoint,
				errOutputUnlockNotAllowed)
		}

		return nil
	})
}

// ListLeasedOutputs lists all active leases for live wallet-owned UTXOs.
func (s *PostgresStore) ListLeasedOutputs(ctx context.Context,
	walletID uint32) ([]LeasedOutput, error) {

	rows, err := s.queries.ListActiveUtxoLeases(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list active utxo leases: %w", err)
	}

	leases := make([]LeasedOutput, len(rows))
	for i, row := range rows {
		outputIndex, err := int64ToUint32(int64(row.OutputIndex))
		if err != nil {
			return nil, fmt.Errorf("lease output index: %w", err)
		}

		lease, err := buildLeasedOutput(
			row.TxHash, outputIndex, row.LockID, row.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}

		leases[i] = *lease
	}

	return leases, nil
}

// Balance returns the sum of wallet-owned live UTXOs after optional filters.
func (s *PostgresStore) Balance(ctx context.Context,
	params BalanceParams) (btcutil.Amount, error) {

	balance, err := s.queries.Balance(ctx, sqlcpg.BalanceParams{
		WalletID:         int64(params.WalletID),
		AccountNumber:    nullableUint32Int64(params.Account),
		MinConfirms:      nullableInt32(params.MinConfs),
		MaxConfirms:      nullableInt32(params.MaxConfs),
		ExcludeLeased:    params.ExcludeLeased,
		CoinbaseMaturity: nullableInt32(params.CoinbaseMaturity),
	})
	if err != nil {
		return 0, fmt.Errorf("balance: %w", err)
	}

	return btcutil.Amount(balance), nil
}

func buildListUtxosParamsPg(query ListUtxosQuery) (sqlcpg.ListUtxosParams,
	error) {

	return sqlcpg.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: nullableUint32Int64(query.Account),
		MinConfirms:   sql.NullInt32{Int32: query.MinConfs, Valid: true},
		MaxConfirms:   sql.NullInt32{Int32: query.MaxConfs, Valid: true},
	}, nil
}

func utxoInfoFromPgRow(hash []byte, outputIndex int32, amount int64,
	pkScript []byte, received time.Time, isCoinbase bool,
	blockHeight sql.NullInt32) (*UtxoInfo, error) {

	index, err := int64ToUint32(int64(outputIndex))
	if err != nil {
		return nil, fmt.Errorf("utxo output index: %w", err)
	}

	var height *uint32
	if blockHeight.Valid {
		heightValue, err := nullInt32ToUint32(blockHeight)
		if err != nil {
			return nil, fmt.Errorf("utxo block height: %w", err)
		}

		height = &heightValue
	}

	return buildUtxoInfo(
		hash, index, amount, pkScript, received, isCoinbase, height,
	)
}

func mustUint32ToInt32(value uint32) int32 {
	converted, err := uint32ToInt32(value)
	if err != nil {
		panic(err)
	}

	return converted
}

func optionalUint32Int64(value *uint32) interface{} {
	if value == nil {
		return nil
	}

	return int64(*value)
}

func optionalInt32(value *int32) interface{} {
	if value == nil {
		return nil
	}

	return *value
}

func nullableUint32Int64(value *uint32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

func nullableInt32(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}

	return sql.NullInt32{Int32: *value, Valid: true}
}
