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

// GetUtxo retrieves one live wallet-owned UTXO by outpoint. It performs a
// single wallet-scoped read against the current unspent set, so spent outputs,
// outputs from invalid parents, and outputs owned by other wallets are never
// returned.
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

// ListUTXOs lists live wallet-owned UTXOs matching the caller filters. It runs
// as one wallet-scoped read over the current unspent set, preserving the API
// invariant that filters only narrow live outputs rather than resurrect spent
// or invalidated entries.
func (s *SqliteStore) ListUTXOs(ctx context.Context,
	query ListUtxosQuery) ([]UtxoInfo, error) {

	rows, err := s.queries.ListUtxos(ctx, sqlcsqlite.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: optionalUint32Int64(query.Account),
		MinConfirms:   nullableInt32Int64(query.MinConfs),
		MaxConfirms:   nullableInt32Int64(query.MaxConfs),
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

// LeaseOutput atomically acquires or renews a lease for one live UTXO. The
// lookup and lease mutation happen inside one SQL transaction, and the stored
// `expires_at` value is normalized to UTC before it is written.
func (s *SqliteStore) LeaseOutput(ctx context.Context,
	params LeaseOutputParams) (*LeasedOutput, error) {

	expiresAt := time.Now().UTC().Add(params.Duration)

	var lease *LeasedOutput

	err := s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		acquiredLease, err := acquireLeaseCommon(
			ctx, params.OutPoint, params.ID, utxoLeaseHooks{
				AcquireLease: func(ctx context.Context) (time.Time, error) {
					return qtx.AcquireUtxoLease(
						ctx, sqlcsqlite.AcquireUtxoLeaseParams{
							WalletID:    int64(params.WalletID),
							LockID:      params.ID[:],
							ExpiresAt:   expiresAt,
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
	if err != nil {
		return nil, err
	}

	return lease, nil
}

// ReleaseOutput atomically releases a lease when the caller provides the active
// lock ID. The lookup and conditional delete happen inside one SQL
// transaction, so lock validation and state removal cannot be observed
// separately.
func (s *SqliteStore) ReleaseOutput(ctx context.Context,
	params ReleaseOutputParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		err := releaseLeaseCommon(ctx, params.OutPoint, params.ID,
			utxoLeaseHooks{
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
				LookupActiveLeaseLockID: func(ctx context.Context,
					utxoID int64) ([]byte, error) {

					return qtx.GetActiveUtxoLeaseLockID(
						ctx, sqlcsqlite.GetActiveUtxoLeaseLockIDParams{
							WalletID: int64(params.WalletID),
							UtxoID:   utxoID,
						},
					)
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

// ListLeasedOutputs lists all active leases for live wallet-owned UTXOs. It
// executes as one wallet-scoped read and only reports leases whose referenced
// UTXOs still belong to the live wallet view.
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

// Balance returns the sum of wallet-owned live UTXOs after optional filters. It
// computes the total in one SQL statement over the same live-set invariants as
// ListUTXOs, so spent outputs and invalid parents never contribute. Coinbase
// maturity remains enforced even when no explicit MinConfs lower bound is set.
func (s *SqliteStore) Balance(ctx context.Context,
	params BalanceParams) (BalanceResult, error) {

	balance, err := s.queries.Balance(ctx, sqlcsqlite.BalanceParams{
		WalletID:         int64(params.WalletID),
		AccountNumber:    optionalUint32Int64(params.Account),
		MinConfirms:      optionalInt32(params.MinConfs),
		MaxConfirms:      optionalInt32(params.MaxConfs),
		CoinbaseMaturity: optionalInt32(params.CoinbaseMaturity),
	})
	if err != nil {
		return BalanceResult{}, fmt.Errorf("balance: %w", err)
	}

	return BalanceResult{
		Total:  btcutil.Amount(balance.TotalBalance),
		Locked: btcutil.Amount(balance.LockedBalance),
	}, nil
}

// utxoInfoFromSqliteRow converts one normalized sqlite query row into the
// public UtxoInfo shape.
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
