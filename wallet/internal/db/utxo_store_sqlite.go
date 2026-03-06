package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SqliteStore satisfies the UTXOStore interface.
var _ UTXOStore = (*SqliteStore)(nil)

// GetUtxo retrieves one live wallet-owned UTXO by outpoint.
func (s *SqliteStore) GetUtxo(ctx context.Context,
	query GetUtxoQuery) (*UtxoInfo, error) {

	row, err := s.queries.GetUtxoByOutpoint(
		ctx, sqlcsqlite.GetUtxoByOutpointParams{
			WalletID:    int64(query.WalletID),
			TxHash:      query.OutPoint.Hash[:],
			OutputIndex: int64(query.OutPoint.Index),
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("utxo %s: %w", query.OutPoint,
				ErrUtxoNotFound)
		}

		return nil, fmt.Errorf("get utxo: %w", err)
	}

	return utxoInfoFromSqliteRow(
		row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
		row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
	)
}

// ListUTXOs lists all live wallet-owned UTXOs matching the caller filters.
func (s *SqliteStore) ListUTXOs(ctx context.Context,
	query ListUtxosQuery) ([]UtxoInfo, error) {

	rows, err := s.queries.ListUtxos(ctx, sqlcsqlite.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: optionalUint32Int64(query.Account),
		MinConfirms:   sql.NullInt64{Int64: int64(query.MinConfs), Valid: true},
		MaxConfirms:   sql.NullInt64{Int64: int64(query.MaxConfs), Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	utxos := make([]UtxoInfo, len(rows))
	for i, row := range rows {
		utxo, err := utxoInfoFromSqliteRow(
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
func (s *SqliteStore) LeaseOutput(ctx context.Context,
	params LeaseOutputParams) (*LeasedOutput, error) {

	var lease *LeasedOutput

	execErr := s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		acquiredLease, err := acquireLeaseCommon(
			ctx, params.OutPoint, params.ID, utxoLeaseHooks{
				AcquireLease: func(ctx context.Context) (time.Time, error) {
					return qtx.AcquireUtxoLease(
						ctx, sqlcsqlite.AcquireUtxoLeaseParams{
							WalletID:    int64(params.WalletID),
							LockID:      params.ID[:],
							ExpiresAt:   time.Now().UTC().Add(params.Duration),
							TxHash:      params.OutPoint.Hash[:],
							OutputIndex: int64(params.OutPoint.Index),
						},
					)
				},
				LookupUtxoID: func(ctx context.Context) (int64, error) {
					return qtx.GetUtxoIDByOutpoint(
						ctx, sqlcsqlite.GetUtxoIDByOutpointParams{
							WalletID:    int64(params.WalletID),
							TxHash:      params.OutPoint.Hash[:],
							OutputIndex: int64(params.OutPoint.Index),
						},
					)
				},
			},
		)
		if err != nil {
			if errors.Is(err, errOutputAlreadyLeased) ||
				errors.Is(err, ErrUtxoNotFound) {

				return err
			}

			return fmt.Errorf("acquire utxo lease: %w", err)
		}

		lease = acquiredLease

		return nil
	})
	if execErr != nil {
		return nil, execErr
	}

	return lease, nil
}

// ReleaseOutput releases a lease when the caller provides the active lock ID.
func (s *SqliteStore) ReleaseOutput(ctx context.Context,
	params ReleaseOutputParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		err := releaseLeaseCommon(ctx, params.OutPoint, utxoLeaseHooks{
			LookupUtxoID: func(ctx context.Context) (int64, error) {
				return qtx.GetUtxoIDByOutpoint(
					ctx, sqlcsqlite.GetUtxoIDByOutpointParams{
						WalletID:    int64(params.WalletID),
						TxHash:      params.OutPoint.Hash[:],
						OutputIndex: int64(params.OutPoint.Index),
					},
				)
			},
			ReleaseLease: func(ctx context.Context,
				utxoID int64) (int64, error) {

				rows, err := qtx.ReleaseUtxoLease(
					ctx, sqlcsqlite.ReleaseUtxoLeaseParams{
						WalletID: int64(params.WalletID),
						UtxoID:   utxoID,
						LockID:   params.ID[:],
					},
				)
				if err != nil {
					return 0, fmt.Errorf("release utxo lease: %w", err)
				}

				return rows, nil
			},
		})
		if err != nil {
			if errors.Is(err, errOutputUnlockNotAllowed) ||
				errors.Is(err, ErrUtxoNotFound) {

				return err
			}

			return fmt.Errorf("lookup utxo for release: %w", err)
		}

		return nil
	})
}

// ListLeasedOutputs lists all active leases for live wallet-owned UTXOs.
func (s *SqliteStore) ListLeasedOutputs(ctx context.Context,
	walletID uint32) ([]LeasedOutput, error) {

	rows, err := s.queries.ListActiveUtxoLeases(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list active utxo leases: %w", err)
	}

	leases := make([]LeasedOutput, len(rows))
	for i, row := range rows {
		outputIndex, err := int64ToUint32(row.OutputIndex)
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
func (s *SqliteStore) Balance(ctx context.Context,
	params BalanceParams) (btcutil.Amount, error) {

	balance, err := s.queries.Balance(ctx, sqlcsqlite.BalanceParams{
		WalletID:         int64(params.WalletID),
		AccountNumber:    optionalUint32Int64(params.Account),
		MinConfirms:      optionalInt32(params.MinConfs),
		MaxConfirms:      optionalInt32(params.MaxConfs),
		ExcludeLeased:    params.ExcludeLeased,
		CoinbaseMaturity: optionalInt32(params.CoinbaseMaturity),
	})
	if err != nil {
		return 0, fmt.Errorf("balance: %w", err)
	}

	return btcutil.Amount(balance), nil
}

func utxoInfoFromSqliteRow(hash []byte, outputIndex int64, amount int64,
	pkScript []byte, received time.Time, isCoinbase bool,
	blockHeight sql.NullInt64) (*UtxoInfo, error) {

	index, err := int64ToUint32(outputIndex)
	if err != nil {
		return nil, fmt.Errorf("utxo output index: %w", err)
	}

	var height *uint32
	if blockHeight.Valid {
		heightValue, err := int64ToUint32(blockHeight.Int64)
		if err != nil {
			return nil, fmt.Errorf("utxo block height: %w", err)
		}

		height = &heightValue
	}

	return buildUtxoInfo(
		hash, index, amount, pkScript, received, isCoinbase, height,
	)
}
