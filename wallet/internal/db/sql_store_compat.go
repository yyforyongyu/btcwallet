package db

import (
	"database/sql"
	"fmt"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// PostgresStore is a transitional compatibility type for root-level SQL store
// helpers that predate the backend package split.
type PostgresStore struct {
	queries *sqlcpg.Queries
}

// SqliteStore is a transitional compatibility type for root-level SQL store
// helpers that predate the backend package split.
type SqliteStore struct {
	queries *sqlcsqlite.Queries
}

// buildPgBlock adapts the old postgres tx-detail helpers to the shared block
// builder used after the backend package split.
func buildPgBlock(height sql.NullInt32, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	height32, err := NullInt32ToUint32(height)
	if err != nil {
		return nil, fmt.Errorf("block height: %w", err)
	}

	return BuildBlock(hash, height32, timestamp.Int64)
}

// buildSqliteBlock adapts the old sqlite tx-detail helpers to the shared block
// builder used after the backend package split.
func buildSqliteBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	height32, err := Int64ToUint32(height.Int64)
	if err != nil {
		return nil, fmt.Errorf("block height: %w", err)
	}

	return BuildBlock(hash, height32, timestamp.Int64)
}

// int64ToUint32 preserves the pre-split helper name used by the transitional
// tx-detail files.
func int64ToUint32(v int64) (uint32, error) {
	return Int64ToUint32(v)
}
