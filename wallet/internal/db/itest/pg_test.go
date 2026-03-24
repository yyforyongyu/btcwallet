//go:build itest && test_db_postgres

package itest

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	// Limit concurrent database creation to avoid exhausting connections.
	pgDBSemaphore = make(chan struct{}, 4)

	// Shared container instance, reused across tests for performance.
	// This is safe to use concurrently because we only share the container
	// and not the database inside it. Each test gets its own database.
	pgContainer *postgres.PostgresContainer

	// Ensure the container is created only once.
	pgContainerOnce sync.Once

	// Error returned by the container creation operation. We need to store
	// it to return when the error already occurred during test setup.
	pgContainerErr error

	// Timeout for waiting for the postgres container to start. Needs to
	// consider container image download time.
	pgInitTimeout = 2 * time.Minute

	// Timeout for terminating the postgres container after the test suite.
	pgTerminateTimeout = 1 * time.Minute
)

// postgresContainerMaxConnections raises the shared postgres test container's
// server-side connection cap above the image default (`max_connections=100`).
//
// Why this is needed:
//   - The postgres itest package uses many `t.Parallel()` tests.
//   - Each test creates its own isolated database and its own PostgresStore.
//   - A PostgresStore intentionally keeps the production default pool sizing
//     (`DefaultMaxConnections = 25`) so the tests exercise realistic behavior.
//   - Each test also opens a separate admin connection while creating its
//     per-test database.
//
// The resulting aggregate demand across several concurrently active tests can
// exceed Postgres' default server limit even though no single test needs that
// many connections. We prefer increasing the container-side limit here instead
// of shrinking the store pool, because lowering the client pool changed test
// behavior and caused legitimate concurrency tests to time out. A value of 200
// gives the suite enough headroom while still keeping the cap finite so CI can
// catch runaway connection usage.
const postgresContainerMaxConnections = 200

// TestMain ensures the shared postgres container is terminated after the
// integration test suite completes to avoid leaking docker resources.
func TestMain(m *testing.M) {
	code := m.Run()

	// Terminate the container after the test suite completes.
	if pgContainer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), pgTerminateTimeout)
		defer cancel()

		err := pgContainer.Terminate(ctx)
		if err != nil {
			fmt.Printf("failed to terminate postgres container: %v\n", err)
		}
	}

	os.Exit(code)
}

// PostgresConfig holds configuration for the test PostgreSQL database.
type PostgresConfig struct {
	// Image is the Docker image to use.
	Image string

	// Database is the database name.
	Database string

	// Username is the database user.
	Username string

	// Password is the database password.
	Password string
}

// DefaultPostgresConfig returns the default PostgreSQL test configuration.
func DefaultPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Image:    "postgres:18-alpine",
		Database: "postgres",
		Username: "postgres",
		Password: "postgres",
	}
}

// GetPostgresContainer returns the shared PostgreSQL container instance.
// The container is created once and reused across all tests for performance.
//
// Note: the postgres itest suite can keep many independent store pools open at
// once, so we raise max_connections above the image default to avoid exhausting
// clients under the current test volume.
func GetPostgresContainer(ctx context.Context) (*postgres.PostgresContainer, error) {
	pgContainerOnce.Do(func() {
		cfg := DefaultPostgresConfig()

		// PostgreSQL 18 can begin listening on the TCP port before it is
		// ready to handle client queries, so wait for a successful SQL round
		// trip instead of only waiting for the port to open.
		waitForSQL := wait.ForSQL(
			"5432/tcp", "pgx", func(host string, port nat.Port) string {
				return fmt.Sprintf(
					"postgres://%s:%s@%s:%s/%s?sslmode=disable",
					cfg.Username, cfg.Password, host, port.Port(),
					cfg.Database,
				)
			},
		).WithStartupTimeout(pgInitTimeout)

		pgContainer, pgContainerErr = postgres.Run(ctx,
			cfg.Image,
			postgres.WithDatabase(cfg.Database),
			postgres.WithUsername(cfg.Username),
			postgres.WithPassword(cfg.Password),
			testcontainers.WithCmdArgs(
				"-c",
				fmt.Sprintf(
					"max_connections=%d",
					postgresContainerMaxConnections,
				),
			),
			testcontainers.WithWaitStrategyAndDeadline(
				pgInitTimeout, waitForSQL,
			),
		)
	})

	return pgContainer, pgContainerErr
}

// sanitizedPgDBName converts a test name to a valid PostgreSQL database name.
// It converts to lowercase and replaces special characters with underscores.
func sanitizedPgDBName(t *testing.T) string {
	// Convert to lowercase.
	dbName := strings.ToLower(t.Name())

	// Replace slashes and other special chars with underscores.
	reg := regexp.MustCompile(`[^a-z0-9_]`)
	dbName = reg.ReplaceAllString(dbName, "_")

	// PostgreSQL database names are limited to 63 characters.
	if len(dbName) > 63 {
		dbName = dbName[:63]
		t.Logf("database name truncated to %d characters: %s", 63, dbName)
	}

	return dbName
}

// NewTestStore creates a new PostgreSQL database connection with migrations
// applied. Each test gets its own database for isolation.
func NewTestStore(t *testing.T) *db.PostgresStore {
	t.Helper()
	ctx := t.Context()

	// Acquire a semaphore slot to limit concurrent database creation and
	// parallel test execution that depends on it.
	pgDBSemaphore <- struct{}{}
	defer func() {
		<-pgDBSemaphore
	}()

	container, err := GetPostgresContainer(ctx)
	require.NoError(t, err, "failed to get postgres container")

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get connection string")

	// Connect to the default database to create our test database.
	adminDB, err := sql.Open("pgx", connStr)
	require.NoError(t, err, "failed to open admin connection")
	require.NotNil(t, adminDB, "admin connection is nil")

	// Create a database name based on the test name.
	dbName := sanitizedPgDBName(t)

	// Create the test database.
	createDBStmt := fmt.Sprintf("CREATE DATABASE %s", dbName)
	_, err = adminDB.ExecContext(ctx, createDBStmt)
	require.NoError(t, err, "failed to create test database")

	// Close the connection to avoid leaking an idle connection during tests.
	// The container is reused across all tests, so we explicitly clean this up.
	_ = adminDB.Close()

	// Build the connection string for the test database.
	testConnStr := strings.Replace(connStr, "/postgres?", "/"+dbName+"?", 1)

	cfg := db.PostgresConfig{
		Dsn:            testConnStr,
		MaxConnections: 0,
	}

	store, err := db.NewPostgresStore(t.Context(), cfg)
	require.NoError(t, err, "failed to create postgres store")

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

// childSpendingTxIDs returns the direct child transaction IDs recorded for the
// provided parent transaction hash.
func childSpendingTxIDs(t *testing.T, store *db.PostgresStore, walletID uint32,
	txHash chainhash.Hash) []int64 {

	t.Helper()

	meta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	require.NoError(t, err)

	childIDs, err := store.Queries().ListSpendingTxIDsByParentTxID(
		t.Context(), sqlcpg.ListSpendingTxIDsByParentTxIDParams{
			WalletID: int64(walletID),
			TxID:     meta.ID,
		},
	)
	require.NoError(t, err)

	ids := make([]int64, 0, len(childIDs))
	for _, childID := range childIDs {
		require.True(t, childID.Valid)
		ids = append(ids, childID.Int64)
	}

	return ids
}

// insertConflictingRegularTx inserts one live regular transaction row plus any
// credited wallet-owned outputs without claiming wallet spend edges.
func insertConflictingRegularTx(t *testing.T, store *db.PostgresStore,
	walletID uint32, tx *wire.MsgTx, received time.Time, status db.TxStatus,
	credits map[uint32]btcutil.Address) {

	t.Helper()

	var raw bytes.Buffer
	err := tx.Serialize(&raw)
	require.NoError(t, err)

	err = store.ExecuteTx(t.Context(), func(qtx *sqlcpg.Queries) error {
		txHash := tx.TxHash()
		txID, err := qtx.InsertTransaction(
			t.Context(), sqlcpg.InsertTransactionParams{
				WalletID:     int64(walletID),
				TxHash:       txHash[:],
				RawTx:        raw.Bytes(),
				BlockHeight:  sql.NullInt32{},
				TxStatus:     int16(status),
				ReceivedTime: received.UTC(),
				IsCoinbase:   false,
				TxLabel:      "",
			},
		)
		if err != nil {
			return err
		}

		for index := range credits {
			addressID := getAddressID(
				t, qtx, tx.TxOut[index].PkScript, walletID,
			)

			_, err = qtx.InsertUtxo(t.Context(), sqlcpg.InsertUtxoParams{
				WalletID:    int64(walletID),
				TxID:        txID,
				OutputIndex: int32(index),
				Amount:      tx.TxOut[index].Value,
				AddressID:   addressID,
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
	require.NoError(t, err)
}

// insertReplacementEdge inserts one direct victim -> winner audit edge.
func insertReplacementEdge(t *testing.T, store *db.PostgresStore,
	walletID uint32, replacedTxid chainhash.Hash,
	replacementTxid chainhash.Hash) {

	t.Helper()

	replacedMeta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   replacedTxid[:],
		},
	)
	require.NoError(t, err)

	replacementMeta, err := store.Queries().GetTransactionMetaByHash(
		t.Context(), sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   replacementTxid[:],
		},
	)
	require.NoError(t, err)

	_, err = store.Queries().InsertTxReplacementEdge(
		t.Context(), sqlcpg.InsertTxReplacementEdgeParams{
			WalletID:        int64(walletID),
			ReplacedTxID:    replacedMeta.ID,
			ReplacementTxID: replacementMeta.ID,
		},
	)
	require.NoError(t, err)
}

// forceOrphanedCoinbaseTx rewrites one stored coinbase row into the orphaned
// blockless state for reconfirmation/orphan tests.
func forceOrphanedCoinbaseTx(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET block_height = NULL, tx_status = $1 "+
			"WHERE wallet_id = $2 AND tx_hash = $3",
		int16(db.TxStatusOrphaned), int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptTransactionRawTx overwrites one stored raw transaction payload.
func corruptTransactionRawTx(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash, rawTx []byte) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET raw_tx = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		rawTx, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptTransactionStatus overwrites one stored transaction status after
// dropping the validating constraints needed for corruption tests.
func corruptTransactionStatus(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash, status int64) {

	t.Helper()

	for _, stmt := range []string{
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS valid_status",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_orphaned_coinbase_only",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_confirmed_published",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_coinbase_not_pending",
		"ALTER TABLE transactions DROP CONSTRAINT IF EXISTS check_coinbase_confirmation_state",
	} {
		_, err := store.DB().ExecContext(t.Context(), stmt)
		require.NoError(t, err)
	}

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET tx_status = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		status, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptTransactionHash overwrites one stored transaction hash.
func corruptTransactionHash(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash, hash []byte) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET tx_hash = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		hash, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptTransactionBlockHeight overwrites one stored transaction block height.
func corruptTransactionBlockHeight(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash, height int64) {

	t.Helper()

	blockHash := RandomHash()
	_, err := store.DB().ExecContext(
		t.Context(),
		"INSERT INTO blocks (block_height, header_hash, block_timestamp) VALUES ($1, $2, $3) "+
			"ON CONFLICT (block_height) DO UPDATE SET header_hash = EXCLUDED.header_hash, "+
			"block_timestamp = EXCLUDED.block_timestamp",
		height, blockHash[:], time.Now().Unix(),
	)
	require.NoError(t, err)

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE transactions SET block_height = $1 WHERE wallet_id = $2 AND tx_hash = $3",
		height, int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptUtxoOutputIndex overwrites one stored UTXO output index.
func corruptUtxoOutputIndex(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash, oldIndex uint32, newIndex int64) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE utxos SET output_index = $1 WHERE output_index = $2 "+
			"AND tx_id = (SELECT id FROM transactions WHERE wallet_id = $3 AND tx_hash = $4)",
		newIndex, int64(oldIndex), int64(walletID), txHash[:],
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// corruptActiveLeaseLockID overwrites the active lease lock ID for one UTXO.
func corruptActiveLeaseLockID(t *testing.T, store *db.PostgresStore,
	walletID uint32, txHash chainhash.Hash, outputIndex uint32, lockID []byte) {

	t.Helper()

	result, err := store.DB().ExecContext(
		t.Context(),
		"UPDATE utxo_leases SET lock_id = $1 WHERE wallet_id = $2 AND utxo_id = ("+
			"SELECT u.id FROM utxos u JOIN transactions t ON t.id = u.tx_id "+
			"WHERE t.wallet_id = $3 AND t.tx_hash = $4 AND u.output_index = $5)",
		lockID, int64(walletID), int64(walletID), txHash[:], int64(outputIndex),
	)
	require.NoError(t, err)

	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

// requireLargeOutputIndexError asserts the postgres-specific conversion error
// surfaced when an outpoint index exceeds the SQL integer range.
func requireLargeOutputIndexError(t *testing.T, err error) {
	t.Helper()

	require.ErrorContains(t, err, "convert output index")
}
