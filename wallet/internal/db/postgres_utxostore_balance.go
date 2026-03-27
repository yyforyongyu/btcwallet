package db

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Balance returns the sum of wallet-owned current UTXOs after optional filters.
func (s *PostgresStore) Balance(ctx context.Context,
	params BalanceParams) (BalanceResult, error) {

	nowUTC := time.Now().UTC()

	balance, err := s.queries.Balance(ctx, sqlcpg.BalanceParams{
		NowUtc:           nowUTC,
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
