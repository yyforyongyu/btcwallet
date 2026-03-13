package db

import (
	"bytes"
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
//
// Live means the output is still unspent and its creating transaction remains
// visible in the wallet's spendable history.
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
//
// The result set is already constrained to outputs whose creating
// transactions still belong to the wallet's live UTXO set.
func (s *PostgresStore) ListUTXOs(ctx context.Context,
	query ListUtxosQuery) ([]UtxoInfo, error) {

	rows, err := s.queries.ListUtxos(ctx, buildListUtxosParamsPg(query))
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

// LeaseOutput atomically acquires or renews a lease for one live UTXO.
//
// The lease lookup and acquisition run in one transaction so competing calls
// cannot observe a partially-written lease. Expiration timestamps are
// normalized to UTC before insert.
func (s *PostgresStore) LeaseOutput(ctx context.Context,
	params LeaseOutputParams) (*LeasedOutput, error) {

	nowUTC := time.Now().UTC()
	expiresAt := nowUTC.Add(params.Duration)

	outputIndex, err := uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return nil, fmt.Errorf("convert output index: %w", err)
	}

	var lease *LeasedOutput

	acquireLease := func(qtx *sqlcpg.Queries) error {
		expiration, err := qtx.AcquireUtxoLease(
			ctx, sqlcpg.AcquireUtxoLeaseParams{
				WalletID:    int64(params.WalletID),
				LockID:      params.ID[:],
				ExpiresAt:   expiresAt,
				TxHash:      params.OutPoint.Hash[:],
				OutputIndex: outputIndex,
				NowUtc:      nowUTC,
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

		// A no-row acquire means the write path found no leasable row.
		// Distinguish a missing UTXO from an already-active lease before
		// returning a public error.
		_, lookupErr := qtx.GetUtxoIDByOutpoint(
			ctx, sqlcpg.GetUtxoIDByOutpointParams{
				WalletID:    int64(params.WalletID),
				TxHash:      params.OutPoint.Hash[:],
				OutputIndex: outputIndex,
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
			ErrOutputAlreadyLeased)
	}

	err = s.ExecuteTx(ctx, acquireLease)
	if err != nil {
		return nil, err
	}

	return lease, nil
}

// ReleaseOutput atomically releases a lease when the caller provides the
// active lock ID.
//
// The ownership check and lease deletion run in one transaction so callers
// cannot unlock a UTXO using stale state from a separate read.
func (s *PostgresStore) ReleaseOutput(ctx context.Context,
	params ReleaseOutputParams) error {

	nowUTC := time.Now().UTC()

	outputIndex, err := uint32ToInt32(params.OutPoint.Index)
	if err != nil {
		return fmt.Errorf("convert output index: %w", err)
	}

	releaseLease := func(qtx *sqlcpg.Queries) error {
		utxoID, err := qtx.GetUtxoIDByOutpoint(
			ctx, sqlcpg.GetUtxoIDByOutpointParams{
				WalletID:    int64(params.WalletID),
				TxHash:      params.OutPoint.Hash[:],
				OutputIndex: outputIndex,
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

		if rows != 0 {
			return nil
		}

		// No row was deleted, so either the lease already expired/was
		// released or a different active lock still owns this UTXO.
		activeLockID, err := qtx.GetActiveUtxoLeaseLockID(
			ctx, sqlcpg.GetActiveUtxoLeaseLockIDParams{
				WalletID: int64(params.WalletID),
				UtxoID:   utxoID,
				NowUtc:   nowUTC,
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}

			return fmt.Errorf("lookup active utxo lease: %w", err)
		}

		if !bytes.Equal(activeLockID, params.ID[:]) {
			return fmt.Errorf("utxo %s: %w", params.OutPoint,
				ErrOutputUnlockNotAllowed)
		}

		return nil
	}

	return s.ExecuteTx(ctx, releaseLease)
}

// ListLeasedOutputs lists all active leases for live wallet-owned UTXOs.
func (s *PostgresStore) ListLeasedOutputs(ctx context.Context,
	walletID uint32) ([]LeasedOutput, error) {

	nowUTC := time.Now().UTC()

	rows, err := s.queries.ListActiveUtxoLeases(
		ctx, sqlcpg.ListActiveUtxoLeasesParams{
			WalletID: int64(walletID),
			NowUtc:   nowUTC,
		},
	)
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
	params BalanceParams) (BalanceResult, error) {

	balance, err := s.queries.Balance(ctx, sqlcpg.BalanceParams{
		WalletID:         int64(params.WalletID),
		AccountNumber:    nullableUint32Int64(params.Account),
		MinConfirms:      nullableInt32(params.MinConfs),
		MaxConfirms:      nullableInt32(params.MaxConfs),
		CoinbaseMaturity: nullableInt32(params.CoinbaseMaturity),
	})
	if err != nil {
		return BalanceResult{}, fmt.Errorf("balance: %w", err)
	}

	return BalanceResult{
		Total:  btcutil.Amount(balance.TotalBalance),
		Locked: btcutil.Amount(balance.LockedBalance),
	}, nil
}

// buildListUtxosParamsPg prepares the typed nullable filters required by the
// postgres ListUtxos query.
func buildListUtxosParamsPg(query ListUtxosQuery) sqlcpg.ListUtxosParams {
	return sqlcpg.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: nullableUint32Int64(query.Account),
		MinConfirms:   nullableInt32(query.MinConfs),
		MaxConfirms:   nullableInt32(query.MaxConfs),
	}
}

// utxoInfoFromPgRow converts one normalized postgres query row into the public
// UtxoInfo shape.
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
