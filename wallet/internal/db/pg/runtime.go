package pg

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

var (
	_ dbruntime.ReadHooks  = (*Store)(nil)
	_ dbruntime.WriteHooks = (*Store)(nil)
)

// Default PostgreSQL read retry settings.
const (
	defaultReadMaxAttempts = 3
	defaultReadBaseDelay   = 10 * time.Millisecond
	defaultReadMaxDelay    = 100 * time.Millisecond
)

// storeRuntimeState holds shared runtime counters and unhealthy state.
type storeRuntimeState struct {
	unhealthy          atomic.Bool
	errStats           dberr.Stats
	retryAttempts      atomic.Uint64
	retrySuccesses     atomic.Uint64
	retryExhausted     atomic.Uint64
	ambiguousTxCommits atomic.Uint64
}

// execRead executes one PostgreSQL read operation through the shared runtime
// helper.
func (s *Store) execRead(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	_, err := dbruntime.Read(
		ctx,
		s,
		s.queries,
		defaultReadConfig(),
		func(_ context.Context, q *sqlc.Queries) (struct{}, error) {
			return struct{}{}, fn(q)
		},
	)

	return err
}

// execWrite executes one PostgreSQL write operation through the shared runtime
// helper.
func (s *Store) execWrite(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	_, err := dbruntime.Write(
		ctx,
		s,
		func(tx *sql.Tx) *sqlc.Queries {
			return s.queries.WithTx(tx)
		},
		func(qtx *sqlc.Queries) (struct{}, error) {
			return struct{}{}, fn(qtx)
		},
	)

	return err
}

// defaultReadConfig returns the PostgreSQL read retry policy.
func defaultReadConfig() dbruntime.ReadConfig {
	return dbruntime.ReadConfig{
		MaxAttempts: defaultReadMaxAttempts,
		BaseDelay:   defaultReadBaseDelay,
		MaxDelay:    defaultReadMaxDelay,
	}
}

// CheckHealthy reports whether a prior fatal SQL backend error poisoned the
// store.
func (s *Store) CheckHealthy() error {
	if s.runtimeState.unhealthy.Load() {
		return dbruntime.ErrStoreUnhealthy
	}

	return nil
}

// ClassifyError normalizes one PostgreSQL backend error into the shared SQL
// error model.
func (s *Store) ClassifyError(err error) error {
	return dberr.Normalize(dberr.BackendPostgres, mapErr, err)
}

// RecordError records one classified PostgreSQL backend error and marks the
// store unhealthy after fatal failures.
func (s *Store) RecordError(err error) {
	s.runtimeState.errStats.Record(err)

	var sqlErr *dberr.SQLError
	if !errors.As(err, &sqlErr) {
		return
	}

	if sqlErr.Class() == dberr.ClassFatal {
		s.runtimeState.unhealthy.Store(true)
	}
}

// RecordRetryAttempt records one PostgreSQL read retry attempt.
func (s *Store) RecordRetryAttempt() {
	s.runtimeState.retryAttempts.Add(1)
}

// RecordRetrySuccess records one successful PostgreSQL read retry outcome.
func (s *Store) RecordRetrySuccess() {
	s.runtimeState.retrySuccesses.Add(1)
}

// RecordRetryExhausted records one exhausted PostgreSQL read retry sequence.
func (s *Store) RecordRetryExhausted() {
	s.runtimeState.retryExhausted.Add(1)
}

// RecordAmbiguousTxCommit records one PostgreSQL commit failure with unknown
// outcome.
func (s *Store) RecordAmbiguousTxCommit() {
	s.runtimeState.ambiguousTxCommits.Add(1)
}

// RawDB returns the PostgreSQL database handle used by shared runtime writes.
func (s *Store) RawDB() *sql.DB {
	return s.db
}
