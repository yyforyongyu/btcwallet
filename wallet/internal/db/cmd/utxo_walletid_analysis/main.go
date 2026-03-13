package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	defaultImage                   = "postgres:18-alpine"
	defaultDatabase                = "postgres"
	defaultUser                    = "postgres"
	defaultPassword                = "postgres"
	defaultWalletNamePrefix        = "wallet"
	defaultBatchSize               = 5000
	defaultBenchmarkRepeats        = 15
	defaultBenchmarkWarmups        = 3
	defaultAcquireLeaseHours       = 24
	largeWalletID            int64 = 1
)

type scaleConfig struct {
	Name               string
	LargeWalletUtxos   int
	OtherWalletCount   int
	OtherWalletUtxos   int
	AccountsPerWallet  int
	AddressesPerAcct   int
	OutputsPerTx       int
	ConfirmedFraction  float64
	SpentFraction      float64
	LeaseFraction      float64
	TxsPerBlock        int
	BenchmarkRepeats   int
	BenchmarkWarmups   int
	BenchmarkAccountNo int64
}

type walletPlan struct {
	WalletID          int64
	WalletName        string
	ScopeID           int64
	AccountBaseID     int64
	AddressBaseID     int64
	TxBaseID          int64
	UtxoBaseID        int64
	UtxoCount         int
	TxCount           int
	ConfirmedTxCount  int
	SpentCount        int
	LeasedCount       int
	AccountsPerWallet int
	AddressesPerAcct  int
	OutputsPerTx      int
	FirstBlockHeight  int32
	LastBlockHeight   int32
}

type datasetPlan struct {
	Scale          scaleConfig
	Wallets        []walletPlan
	MaxBlockHeight int32
	MaxWalletID    int64
	MaxScopeID     int64
	MaxAccountID   int64
	MaxAddressID   int64
	MaxTxID        int64
	MaxUtxoID      int64
	Fixtures       benchmarkFixtures
}

type benchmarkFixtures struct {
	WalletID                  int64
	AccountNumber             int64
	LookupTxHash              []byte
	LookupOutputIndex         int32
	LookupUtxoID              int64
	AcquireTxHash             []byte
	AcquireOutputIndex        int32
	ReleaseWalletID           int64
	ReleaseUtxoID             int64
	ReleaseLockID             []byte
	MarkSpendParentTxHash     []byte
	MarkSpendOutputIndex      int32
	MarkSpendReplacementTxID  int64
	ClearSpentByTxID          int64
	DeleteTxID                int64
	WriteAddressID            int64
	CrossWalletTxID           int64
	CrossWalletSpenderTxID    int64
	CrossWalletAddressIDA     int64
	CrossWalletAddressIDB     int64
	CrossWalletLeaseWalletID  int64
	CrossWalletLeaseUtxoID    int64
	InsertReceivedTime        time.Time
	AcquireExpiresAt          time.Time
	LookupResultFingerprint   string
	BalanceResultFingerprint  string
	ListUtxosFingerprint      string
	ListAcctUtxosFingerprint  string
	IntegrityAddressInvariant string
}

type relationSize struct {
	Name       string
	TableBytes int64
	IndexBytes int64
	TotalBytes int64
}

type planSummary struct {
	PlanningMs       float64
	ExecutionMs      float64
	RootNode         string
	ActualRows       int64
	SharedHitBlocks  int64
	SharedReadBlocks int64
	IndexNames       []string
}

type timingSummary struct {
	Iterations  int
	P50Ms       float64
	P95Ms       float64
	AvgMs       float64
	MinMs       float64
	MaxMs       float64
	Fingerprint string
}

type benchmarkResult struct {
	Name       string
	Plan       planSummary
	Timing     timingSummary
	Notes      string
	Difference string
}

type integrityCheckResult struct {
	Name     string
	Outcome  string
	ErrorMsg string
}

type variantResult struct {
	Variant         string
	Benchmarks      []benchmarkResult
	Relations       []relationSize
	DatabaseBytes   int64
	IntegrityChecks []integrityCheckResult
}

type explainRoot struct {
	Plan          explainNode `json:"Plan"`
	PlanningTime  float64     `json:"Planning Time"`
	ExecutionTime float64     `json:"Execution Time"`
}

type explainNode struct {
	NodeType         string        `json:"Node Type"`
	RelationName     string        `json:"Relation Name"`
	IndexName        string        `json:"Index Name"`
	ActualRows       float64       `json:"Actual Rows"`
	SharedHitBlocks  int64         `json:"Shared Hit Blocks"`
	SharedReadBlocks int64         `json:"Shared Read Blocks"`
	Plans            []explainNode `json:"Plans"`
}

type benchmarkCase struct {
	Name string
	Run  func(context.Context, *pgxpool.Conn, querySet, benchmarkFixtures, int) (string, error)
	Plan func(context.Context, *pgxpool.Conn, querySet, benchmarkFixtures) (planSummary, error)
}

type querySet struct {
	ListUtxos         string
	ListUtxosByAcct   string
	Balance           string
	GetUtxoByOutpoint string
	GetUtxoIDByOutpt  string
	AcquireLease      string
	ReleaseLease      string
	MarkUtxoSpent     string
	ClearSpentByTxID  string
	DeleteUtxosByTxID string
	InsertTransaction string
	InsertUtxo        string
}

var scales = map[string]scaleConfig{
	"two-wallets-100k-5": {
		Name:               "two-wallets-100k-5",
		LargeWalletUtxos:   500000,
		OtherWalletCount:   1,
		OtherWalletUtxos:   500000,
		AccountsPerWallet:  4,
		AddressesPerAcct:   2048,
		OutputsPerTx:       5,
		ConfirmedFraction:  0.8,
		SpentFraction:      0.4,
		LeaseFraction:      0.1,
		TxsPerBlock:        16,
		BenchmarkRepeats:   10,
		BenchmarkWarmups:   2,
		BenchmarkAccountNo: 1,
	},
	"1000-wallets-100tx-10": {
		Name:               "1000-wallets-100tx-10",
		LargeWalletUtxos:   1000,
		OtherWalletCount:   999,
		OtherWalletUtxos:   1000,
		AccountsPerWallet:  4,
		AddressesPerAcct:   256,
		OutputsPerTx:       10,
		ConfirmedFraction:  0.8,
		SpentFraction:      0.4,
		LeaseFraction:      0.1,
		TxsPerBlock:        16,
		BenchmarkRepeats:   10,
		BenchmarkWarmups:   2,
		BenchmarkAccountNo: 1,
	},
	"small": {
		Name:               "small",
		LargeWalletUtxos:   8000,
		OtherWalletCount:   20,
		OtherWalletUtxos:   100,
		AccountsPerWallet:  4,
		AddressesPerAcct:   256,
		OutputsPerTx:       2,
		ConfirmedFraction:  0.8,
		SpentFraction:      0.4,
		LeaseFraction:      0.1,
		TxsPerBlock:        12,
		BenchmarkRepeats:   defaultBenchmarkRepeats,
		BenchmarkWarmups:   defaultBenchmarkWarmups,
		BenchmarkAccountNo: 1,
	},
	"medium": {
		Name:               "medium",
		LargeWalletUtxos:   80000,
		OtherWalletCount:   20,
		OtherWalletUtxos:   1000,
		AccountsPerWallet:  4,
		AddressesPerAcct:   1024,
		OutputsPerTx:       2,
		ConfirmedFraction:  0.8,
		SpentFraction:      0.4,
		LeaseFraction:      0.1,
		TxsPerBlock:        12,
		BenchmarkRepeats:   defaultBenchmarkRepeats,
		BenchmarkWarmups:   defaultBenchmarkWarmups,
		BenchmarkAccountNo: 1,
	},
	"large": {
		Name:               "large",
		LargeWalletUtxos:   900000,
		OtherWalletCount:   10,
		OtherWalletUtxos:   10000,
		AccountsPerWallet:  4,
		AddressesPerAcct:   2048,
		OutputsPerTx:       2,
		ConfirmedFraction:  0.8,
		SpentFraction:      0.4,
		LeaseFraction:      0.1,
		TxsPerBlock:        16,
		BenchmarkRepeats:   10,
		BenchmarkWarmups:   2,
		BenchmarkAccountNo: 1,
	},
}

func main() {
	var (
		scaleName = flag.String("scale", "medium", "dataset scale: small, medium, large, two-wallets-100k-5, 1000-wallets-100tx-10")
		engine    = flag.String("engine", "postgres", "database engine: postgres, sqlite, both")
		repeats   = flag.Int("repeats", 0, "override benchmark repeat count")
		warmups   = flag.Int("warmups", 0, "override benchmark warmup count")
	)
	flag.Parse()

	scale, ok := scales[*scaleName]
	if !ok {
		fatalf("unknown scale %q", *scaleName)
	}
	if *repeats > 0 {
		scale.BenchmarkRepeats = *repeats
	}
	if *warmups > 0 {
		scale.BenchmarkWarmups = *warmups
	}

	ctx := context.Background()
	reports := make([]string, 0, 2)
	appendReport := func(report string, err error) {
		if err != nil {
			fatalf("run %s analysis: %v", *engine, err)
		}
		reports = append(reports, report)
	}

	switch *engine {
	case "postgres":
		appendReport(runPostgresAnalysis(ctx, scale))
	case "sqlite":
		appendReport(runSQLiteAnalysis(ctx, scale))
	case "both":
		appendReport(runPostgresAnalysis(ctx, scale))
		appendReport(runSQLiteAnalysis(ctx, scale))
	default:
		fatalf("unknown engine %q", *engine)
	}

	if _, err := os.Stdout.WriteString(strings.Join(reports, "\n\n")); err != nil {
		fatalf("write report: %v", err)
	}
}

func startPostgresContainer(ctx context.Context) (*postgres.PostgresContainer, error) {
	return postgres.RunContainer(ctx,
		testcontainers.WithImage(defaultImage),
		postgres.WithDatabase(defaultDatabase),
		postgres.WithUsername(defaultUser),
		postgres.WithPassword(defaultPassword),
		testcontainers.WithWaitStrategyAndDeadline(
			2*time.Minute, wait.ForListeningPort("5432/tcp"),
		),
	)
}

func recreateDatabase(ctx context.Context, adminDB *sql.DB, name string) error {
	_, _ = adminDB.ExecContext(ctx,
		fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", name),
	)
	_, err := adminDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s", name))
	return err
}

func openDatabases(ctx context.Context, baseConnStr string, dbName string) (*sql.DB, *pgxpool.Pool, error) {
	dsn := strings.Replace(baseConnStr, "/postgres?", "/"+dbName+"?", 1)
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, nil, err
	}
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, err
	}
	poolCfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, err
	}
	return sqlDB, pool, nil
}

func applyVariantB(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`DROP VIEW spendable_utxos`,
		`ALTER TABLE utxo_leases DROP CONSTRAINT fkey_utxo_leases_utxo`,
		`ALTER TABLE utxo_leases DROP CONSTRAINT pidx_utxo_leases`,
		`ALTER TABLE utxos DROP CONSTRAINT fkey_utxos_tx`,
		`ALTER TABLE utxos DROP CONSTRAINT fkey_utxos_spent_by`,
		`ALTER TABLE utxos DROP CONSTRAINT uidx_utxos_outpoint`,
		`ALTER TABLE utxos DROP CONSTRAINT uidx_utxos_wallet_id_id`,
		`DROP INDEX idx_utxos_unspent`,
		`DROP INDEX idx_utxos_spent_by`,
		`DROP INDEX idx_utxos_by_tx`,
		`ALTER TABLE utxos DROP COLUMN wallet_id`,
		`ALTER TABLE utxos ADD CONSTRAINT fkey_utxos_tx FOREIGN KEY (tx_id) REFERENCES transactions (id) ON DELETE RESTRICT`,
		`ALTER TABLE utxos ADD CONSTRAINT fkey_utxos_spent_by FOREIGN KEY (spent_by_tx_id) REFERENCES transactions (id) ON DELETE RESTRICT`,
		`ALTER TABLE utxos ADD CONSTRAINT uidx_utxos_outpoint UNIQUE (tx_id, output_index)`,
		`CREATE INDEX idx_utxos_unspent ON utxos (tx_id, amount, output_index) WHERE spent_by_tx_id IS NULL`,
		`CREATE INDEX idx_utxos_spent_by ON utxos (spent_by_tx_id)`,
		`CREATE INDEX idx_utxos_by_tx ON utxos (tx_id)`,
		`ALTER TABLE utxo_leases ADD CONSTRAINT pidx_utxo_leases PRIMARY KEY (utxo_id)`,
		`ALTER TABLE utxo_leases ADD CONSTRAINT fkey_utxo_leases_utxo FOREIGN KEY (utxo_id) REFERENCES utxos (id) ON DELETE CASCADE`,
		`CREATE INDEX idx_transactions_live_by_wallet ON transactions (wallet_id, id) WHERE status IN (0, 1)`,
		`CREATE OR REPLACE VIEW spendable_utxos AS SELECT t.wallet_id, u.id, u.tx_id, u.output_index, u.amount, u.address_id, t.block_height, t.is_coinbase, t.status AS tx_status FROM utxos AS u INNER JOIN transactions AS t ON u.tx_id = t.id WHERE u.spent_by_tx_id IS NULL AND t.status IN (0, 1)`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

func buildDatasetPlan(scale scaleConfig) datasetPlan {
	walletCount := 1 + scale.OtherWalletCount
	plan := datasetPlan{Scale: scale}
	plan.Wallets = make([]walletPlan, 0, walletCount)

	var (
		nextAccountID int64 = 1
		nextAddressID int64 = 1
		nextTxID      int64 = 1
		nextUtxoID    int64 = 1
		confirmedSeen int
	)

	for i := 0; i < walletCount; i++ {
		walletID := int64(i + 1)
		utxoCount := scale.OtherWalletUtxos
		if walletID == largeWalletID {
			utxoCount = scale.LargeWalletUtxos
		}
		txCount := int(math.Ceil(float64(utxoCount) / float64(scale.OutputsPerTx)))
		confirmedTxCount := int(float64(txCount) * scale.ConfirmedFraction)
		if confirmedTxCount <= 0 {
			confirmedTxCount = 1
		}
		if confirmedTxCount >= txCount {
			confirmedTxCount = txCount - 1
			if confirmedTxCount < 1 {
				confirmedTxCount = txCount
			}
		}
		spentCount := int(float64(utxoCount) * scale.SpentFraction)
		if spentCount >= utxoCount {
			spentCount = utxoCount - 1
		}
		leasedCount := 0
		if walletID == largeWalletID {
			leasedCount = int(float64(utxoCount-spentCount) * scale.LeaseFraction)
		}
		firstBlock := int32(0)
		lastBlock := int32(0)
		if confirmedTxCount > 0 {
			firstBlock = int32(confirmedSeen/scale.TxsPerBlock + 1)
			lastBlock = int32((confirmedSeen+confirmedTxCount-1)/scale.TxsPerBlock + 1)
			confirmedSeen += confirmedTxCount
		}
		wallet := walletPlan{
			WalletID:          walletID,
			WalletName:        fmt.Sprintf("%s-%02d", defaultWalletNamePrefix, walletID),
			ScopeID:           walletID,
			AccountBaseID:     nextAccountID,
			AddressBaseID:     nextAddressID,
			TxBaseID:          nextTxID,
			UtxoBaseID:        nextUtxoID,
			UtxoCount:         utxoCount,
			TxCount:           txCount,
			ConfirmedTxCount:  confirmedTxCount,
			SpentCount:        spentCount,
			LeasedCount:       leasedCount,
			AccountsPerWallet: scale.AccountsPerWallet,
			AddressesPerAcct:  scale.AddressesPerAcct,
			OutputsPerTx:      scale.OutputsPerTx,
			FirstBlockHeight:  firstBlock,
			LastBlockHeight:   lastBlock,
		}
		plan.Wallets = append(plan.Wallets, wallet)
		nextAccountID += int64(scale.AccountsPerWallet)
		nextAddressID += int64(scale.AccountsPerWallet * scale.AddressesPerAcct)
		nextTxID += int64(txCount)
		nextUtxoID += int64(utxoCount)
	}

	plan.MaxBlockHeight = int32((confirmedSeen-1)/scale.TxsPerBlock + 1)
	plan.MaxWalletID = int64(walletCount)
	plan.MaxScopeID = int64(walletCount)
	plan.MaxAccountID = nextAccountID - 1
	plan.MaxAddressID = nextAddressID - 1
	plan.MaxTxID = nextTxID - 1
	plan.MaxUtxoID = nextUtxoID - 1
	plan.Fixtures = buildFixtures(plan)
	return plan
}

func buildFixtures(plan datasetPlan) benchmarkFixtures {
	large := plan.Wallets[0]
	other := plan.Wallets[1]
	unspentStart := large.SpentCount
	firstLeasedOrdinal := unspentStart
	firstPlainOrdinal := unspentStart + large.LeasedCount
	lookupUtxoID := large.UtxoBaseID + int64(firstPlainOrdinal)
	lookupTxOrdinal := firstPlainOrdinal / large.OutputsPerTx
	lookupOutputIndex := int32(firstPlainOrdinal % large.OutputsPerTx)
	lookupTxID := large.TxBaseID + int64(lookupTxOrdinal)
	releaseUtxoID := large.UtxoBaseID + int64(firstLeasedOrdinal)
	releaseOutputIndex := int32(firstLeasedOrdinal % large.OutputsPerTx)
	_ = releaseOutputIndex
	spenderTxID := large.TxBaseID + int64(large.TxCount/2)
	deleteTxID := large.TxBaseID + 1
	writeAddressID := addressID(large, 0, 0)
	fixtures := benchmarkFixtures{
		WalletID:                 large.WalletID,
		AccountNumber:            plan.Scale.BenchmarkAccountNo,
		LookupTxHash:             txHash(lookupTxID),
		LookupOutputIndex:        lookupOutputIndex,
		LookupUtxoID:             lookupUtxoID,
		AcquireTxHash:            txHash(lookupTxID),
		AcquireOutputIndex:       lookupOutputIndex,
		ReleaseWalletID:          large.WalletID,
		ReleaseUtxoID:            releaseUtxoID,
		ReleaseLockID:            lockID(releaseUtxoID),
		MarkSpendParentTxHash:    txHash(lookupTxID),
		MarkSpendOutputIndex:     lookupOutputIndex,
		MarkSpendReplacementTxID: large.TxBaseID + int64(large.TxCount-1),
		ClearSpentByTxID:         spenderTxID,
		DeleteTxID:               deleteTxID,
		WriteAddressID:           writeAddressID,
		CrossWalletTxID:          large.TxBaseID,
		CrossWalletSpenderTxID:   other.TxBaseID,
		CrossWalletAddressIDA:    writeAddressID,
		CrossWalletAddressIDB:    addressID(other, 0, 0),
		CrossWalletLeaseWalletID: other.WalletID,
		CrossWalletLeaseUtxoID:   lookupUtxoID,
		InsertReceivedTime:       time.Unix(1_700_000_000, 0).UTC(),
		AcquireExpiresAt:         time.Now().UTC().Add(defaultAcquireLeaseHours * time.Hour),
	}
	return fixtures
}

func addressID(wallet walletPlan, accountIndex int, addressOffset int) int64 {
	return wallet.AddressBaseID + int64(accountIndex*wallet.AddressesPerAcct+addressOffset)
}

func seedDataset(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan, withWalletID bool) error {
	if err := seedBlocks(ctx, pool, plan.MaxBlockHeight); err != nil {
		return err
	}
	if err := seedWallets(ctx, pool, plan); err != nil {
		return err
	}
	if err := seedKeyScopes(ctx, pool, plan); err != nil {
		return err
	}
	if err := seedAccounts(ctx, pool, plan); err != nil {
		return err
	}
	if err := seedAddresses(ctx, pool, plan); err != nil {
		return err
	}
	if err := seedWalletSyncStates(ctx, pool, plan); err != nil {
		return err
	}
	if err := seedTransactions(ctx, pool, plan); err != nil {
		return err
	}
	if err := seedUtxos(ctx, pool, plan, withWalletID); err != nil {
		return err
	}
	if err := seedLeases(ctx, pool, plan); err != nil {
		return err
	}
	return resetSequences(ctx, pool, plan)
}

func seedBlocks(ctx context.Context, pool *pgxpool.Pool, maxHeight int32) error {
	rows := make([][]any, 0, defaultBatchSize)
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		return copyRows(ctx, pool, "blocks",
			[]string{"block_height", "header_hash", "block_timestamp"}, rows,
		)
	}
	for height := int32(1); height <= maxHeight; height++ {
		rows = append(rows, []any{height, headerHash(height), int64(1_700_000_000 + height*600)})
		if len(rows) >= defaultBatchSize {
			if err := flush(); err != nil {
				return err
			}
			rows = rows[:0]
		}
	}
	return flush()
}

func seedWallets(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, len(plan.Wallets))
	for _, wallet := range plan.Wallets {
		rows = append(rows, []any{
			wallet.WalletID,
			wallet.WalletName,
			false,
			1,
			false,
			bytesForID("mp", wallet.WalletID),
			bytesForID("cp", wallet.WalletID),
			bytesForID("hp", wallet.WalletID),
		})
	}
	return copyRows(ctx, pool, "wallets", []string{
		"id",
		"wallet_name",
		"is_imported",
		"manager_version",
		"is_watch_only",
		"master_pub_params",
		"encrypted_crypto_pub_key",
		"encrypted_master_hd_pub_key",
	}, rows)
}

func seedKeyScopes(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, len(plan.Wallets))
	for _, wallet := range plan.Wallets {
		rows = append(rows, []any{wallet.ScopeID, wallet.WalletID, int64(84), int64(0), int16(4), int16(4)})
	}
	return copyRows(ctx, pool, "key_scopes", []string{
		"id",
		"wallet_id",
		"purpose",
		"coin_type",
		"internal_type_id",
		"external_type_id",
	}, rows)
}

func seedAccounts(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, len(plan.Wallets)*plan.Scale.AccountsPerWallet)
	for _, wallet := range plan.Wallets {
		for acct := 0; acct < wallet.AccountsPerWallet; acct++ {
			rows = append(rows, []any{
				wallet.AccountBaseID + int64(acct),
				wallet.ScopeID,
				int64(acct),
				fmt.Sprintf("acct-%02d", acct),
				int16(0),
				false,
			})
		}
	}
	return copyRows(ctx, pool, "accounts", []string{
		"id",
		"scope_id",
		"account_number",
		"account_name",
		"origin_id",
		"is_watch_only",
	}, rows)
}

func seedAddresses(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, defaultBatchSize)
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		return copyRows(ctx, pool, "addresses", []string{
			"id",
			"account_id",
			"script_pub_key",
			"type_id",
			"address_branch",
			"address_index",
		}, rows)
	}
	for _, wallet := range plan.Wallets {
		for acct := 0; acct < wallet.AccountsPerWallet; acct++ {
			accountID := wallet.AccountBaseID + int64(acct)
			for offset := 0; offset < wallet.AddressesPerAcct; offset++ {
				id := addressID(wallet, acct, offset)
				rows = append(rows, []any{id, accountID, scriptPubKey(id), int16(4), int16(0), int64(offset)})
				if len(rows) >= defaultBatchSize {
					if err := flush(); err != nil {
						return err
					}
					rows = rows[:0]
				}
			}
		}
	}
	return flush()
}

func seedWalletSyncStates(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, len(plan.Wallets))
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, wallet := range plan.Wallets {
		rows = append(rows, []any{wallet.WalletID, plan.MaxBlockHeight, now})
	}
	return copyRows(ctx, pool, "wallet_sync_states", []string{
		"wallet_id",
		"synced_height",
		"updated_at",
	}, rows)
}

func seedTransactions(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, defaultBatchSize)
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		return copyRows(ctx, pool, "transactions", []string{
			"id",
			"wallet_id",
			"tx_hash",
			"raw_tx",
			"block_height",
			"status",
			"received_time",
			"is_coinbase",
			"label",
		}, rows)
	}
	for _, wallet := range plan.Wallets {
		for txOffset := 0; txOffset < wallet.TxCount; txOffset++ {
			txID := wallet.TxBaseID + int64(txOffset)
			confirmed := txOffset < wallet.ConfirmedTxCount
			var blockHeight any
			status := int16(0)
			isCoinbase := false
			if confirmed {
				blockHeight = wallet.FirstBlockHeight + int32(txOffset/plan.Scale.TxsPerBlock)
				status = 1
				isCoinbase = txOffset%50 == 0
			} else {
				blockHeight = nil
				if txOffset%2 == 0 {
					status = 0
				} else {
					status = 1
				}
			}
			rows = append(rows, []any{
				txID,
				wallet.WalletID,
				txHash(txID),
				rawTx(txID),
				blockHeight,
				status,
				time.Unix(1_700_000_000+int64(txID), 0).UTC(),
				isCoinbase,
				"",
			})
			if len(rows) >= defaultBatchSize {
				if err := flush(); err != nil {
					return err
				}
				rows = rows[:0]
			}
		}
	}
	return flush()
}

func seedUtxos(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan, withWalletID bool) error {
	rows := make([][]any, 0, defaultBatchSize)
	flush := func(columns []string) error {
		if len(rows) == 0 {
			return nil
		}
		return copyRows(ctx, pool, "utxos", columns, rows)
	}
	columns := []string{"id", "tx_id", "output_index", "amount", "address_id", "spent_by_tx_id", "spent_input_index"}
	if withWalletID {
		columns = append([]string{"id", "wallet_id", "tx_id", "output_index", "amount", "address_id", "spent_by_tx_id", "spent_input_index"}, []string{}...)
	}
	for _, wallet := range plan.Wallets {
		for ordinal := 0; ordinal < wallet.UtxoCount; ordinal++ {
			utxoID := wallet.UtxoBaseID + int64(ordinal)
			txOffset := ordinal / wallet.OutputsPerTx
			outputIndex := int32(ordinal % wallet.OutputsPerTx)
			txID := wallet.TxBaseID + int64(txOffset)
			accountIndex := ordinal % wallet.AccountsPerWallet
			addressOffset := (ordinal / wallet.AccountsPerWallet) % wallet.AddressesPerAcct
			addressID := addressID(wallet, accountIndex, addressOffset)
			var spentBy any
			var spentInput any
			if ordinal < wallet.SpentCount {
				spenderStart := wallet.TxCount / 2
				spenderSpan := wallet.TxCount - spenderStart
				spenderOffset := spenderStart + (ordinal % spenderSpan)
				spentBy = wallet.TxBaseID + int64(spenderOffset)
				spentInput = int32(ordinal % wallet.OutputsPerTx)
			} else {
				spentBy = nil
				spentInput = nil
			}
			amount := int64(10_000 + (ordinal % 100_000))
			if withWalletID {
				rows = append(rows, []any{utxoID, wallet.WalletID, txID, outputIndex, amount, addressID, spentBy, spentInput})
			} else {
				rows = append(rows, []any{utxoID, txID, outputIndex, amount, addressID, spentBy, spentInput})
			}
			if len(rows) >= defaultBatchSize {
				if err := flush(columns); err != nil {
					return err
				}
				rows = rows[:0]
			}
		}
	}
	return flush(columns)
}

func seedLeases(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	rows := make([][]any, 0, defaultBatchSize)
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		return copyRows(ctx, pool, "utxo_leases", []string{
			"wallet_id",
			"utxo_id",
			"lock_id",
			"expires_at",
		}, rows)
	}
	expiresAt := time.Now().UTC().Add(defaultAcquireLeaseHours * time.Hour)
	for _, wallet := range plan.Wallets {
		for lease := 0; lease < wallet.LeasedCount; lease++ {
			ordinal := wallet.SpentCount + lease
			utxoID := wallet.UtxoBaseID + int64(ordinal)
			rows = append(rows, []any{wallet.WalletID, utxoID, lockID(utxoID), expiresAt})
			if len(rows) >= defaultBatchSize {
				if err := flush(); err != nil {
					return err
				}
				rows = rows[:0]
			}
		}
	}
	return flush()
}

func resetSequences(ctx context.Context, pool *pgxpool.Pool, plan datasetPlan) error {
	statements := []string{
		fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('wallets', 'id'), %d, true)`, plan.MaxWalletID),
		fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('key_scopes', 'id'), %d, true)`, plan.MaxScopeID),
		fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('accounts', 'id'), %d, true)`, plan.MaxAccountID),
		fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('addresses', 'id'), %d, true)`, plan.MaxAddressID),
		fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('transactions', 'id'), %d, true)`, plan.MaxTxID),
		fmt.Sprintf(`SELECT setval(pg_get_serial_sequence('utxos', 'id'), %d, true)`, plan.MaxUtxoID),
	}
	for _, stmt := range statements {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func analyzeDatabase(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `ANALYZE`)
	return err
}

func configureBenchmarkSession(ctx context.Context, conn *pgxpool.Conn) error {
	statements := []string{
		`SET max_parallel_workers_per_gather = 0`,
		`SET jit = off`,
	}
	for _, stmt := range statements {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func benchmarkCases() []benchmarkCase {
	return []benchmarkCase{
		{
			Name: "ListUtxos(wallet)",
			Run:  runListUtxosWallet,
			Plan: explainListUtxosWallet,
		},
		{
			Name: "ListUtxos(account)",
			Run:  runListUtxosAccount,
			Plan: explainListUtxosAccount,
		},
		{
			Name: "Balance",
			Run:  runBalance,
			Plan: explainBalance,
		},
		{
			Name: "GetUtxoByOutpoint",
			Run:  runGetUtxoByOutpoint,
			Plan: explainGetUtxoByOutpoint,
		},
		{
			Name: "GetUtxoIDByOutpoint",
			Run:  runGetUtxoIDByOutpoint,
			Plan: explainGetUtxoIDByOutpoint,
		},
		{
			Name: "AcquireUtxoLease",
			Run:  runAcquireLease,
			Plan: explainAcquireLease,
		},
		{
			Name: "ReleaseUtxoLease",
			Run:  runReleaseLease,
			Plan: explainReleaseLease,
		},
		{
			Name: "InsertTx+Credits",
			Run:  runInsertTxAndCredits,
			Plan: explainInsertTxAndCredits,
		},
		{
			Name: "MarkUtxoSpent",
			Run:  runMarkUtxoSpent,
			Plan: explainMarkUtxoSpent,
		},
		{
			Name: "ClearUtxosSpentByTxID",
			Run:  runClearSpentByTxID,
			Plan: explainClearSpentByTxID,
		},
		{
			Name: "DeleteUtxosByTxID",
			Run:  runDeleteUtxosByTxID,
			Plan: explainDeleteUtxosByTxID,
		},
	}
}

func runBenchmarks(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, scale scaleConfig, cases []benchmarkCase) ([]benchmarkResult, error) {
	results := make([]benchmarkResult, 0, len(cases))
	for _, bench := range cases {
		plan, err := bench.Plan(ctx, conn, queries, fixtures)
		if err != nil {
			return nil, fmt.Errorf("%s explain: %w", bench.Name, err)
		}
		for warmup := 0; warmup < scale.BenchmarkWarmups; warmup++ {
			if _, err := bench.Run(ctx, conn, queries, fixtures, warmup); err != nil {
				return nil, fmt.Errorf("%s warmup: %w", bench.Name, err)
			}
		}
		durations := make([]float64, 0, scale.BenchmarkRepeats)
		fingerprint := ""
		for iter := 0; iter < scale.BenchmarkRepeats; iter++ {
			start := time.Now()
			fp, err := bench.Run(ctx, conn, queries, fixtures, iter)
			if err != nil {
				return nil, fmt.Errorf("%s iteration %d: %w", bench.Name, iter, err)
			}
			durations = append(durations, time.Since(start).Seconds()*1000)
			if fingerprint == "" {
				fingerprint = fp
			} else if fp != fingerprint {
				return nil, fmt.Errorf("%s produced unstable fingerprints: %q vs %q", bench.Name, fingerprint, fp)
			}
		}
		results = append(results, benchmarkResult{
			Name:   bench.Name,
			Plan:   plan,
			Timing: summarizeDurations(durations, fingerprint),
		})
	}
	return results, nil
}

func summarizeDurations(durations []float64, fingerprint string) timingSummary {
	sorted := append([]float64(nil), durations...)
	sort.Float64s(sorted)
	avg := 0.0
	for _, d := range durations {
		avg += d
	}
	avg /= float64(len(durations))
	return timingSummary{
		Iterations:  len(durations),
		P50Ms:       percentile(sorted, 0.50),
		P95Ms:       percentile(sorted, 0.95),
		AvgMs:       avg,
		MinMs:       sorted[0],
		MaxMs:       sorted[len(sorted)-1],
		Fingerprint: fingerprint,
	}
}

func ensureComparableResults(a []benchmarkResult, b []benchmarkResult) error {
	if len(a) != len(b) {
		return fmt.Errorf("different benchmark counts: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return fmt.Errorf("benchmark order mismatch at %d: %q vs %q", i, a[i].Name, b[i].Name)
		}
		if a[i].Timing.Fingerprint != b[i].Timing.Fingerprint {
			return fmt.Errorf("%s fingerprint mismatch: %q vs %q", a[i].Name, a[i].Timing.Fingerprint, b[i].Timing.Fingerprint)
		}
	}
	return nil
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	idx := int(math.Ceil(float64(len(sorted))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func explainListUtxosWallet(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainJSON(ctx, conn, queries.ListUtxos, fixtures.WalletID, nil, nil, nil)
}

func explainListUtxosAccount(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	minConf := int32(1)
	return explainJSON(ctx, conn, queries.ListUtxosByAcct, fixtures.WalletID, fixtures.AccountNumber, minConf, nil)
}

func explainBalance(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	minConf := int32(1)
	coinbaseMaturity := int32(100)
	return explainJSON(ctx, conn, queries.Balance, fixtures.WalletID, nil, minConf, nil, coinbaseMaturity)
}

func explainGetUtxoByOutpoint(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainJSON(ctx, conn, queries.GetUtxoByOutpoint, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex)
}

func explainGetUtxoIDByOutpoint(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainJSON(ctx, conn, queries.GetUtxoIDByOutpt, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex)
}

func explainAcquireLease(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return planSummary{}, err
	}
	defer tx.Rollback(ctx)
	return explainJSONTx(ctx, tx, queries.AcquireLease,
		fixtures.WalletID, fixtures.AcquireTxHash, fixtures.AcquireOutputIndex,
		lockID(fixtures.LookupUtxoID+999_999), fixtures.AcquireExpiresAt,
	)
}

func explainReleaseLease(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return planSummary{}, err
	}
	defer tx.Rollback(ctx)
	return explainJSONTx(ctx, tx, queries.ReleaseLease, fixtures.ReleaseWalletID, fixtures.ReleaseUtxoID, fixtures.ReleaseLockID)
}

func explainInsertTxAndCredits(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return planSummary{}, err
	}
	defer tx.Rollback(ctx)
	plan, err := explainJSONTx(ctx, tx, queries.InsertUtxo,
		fixtures.WalletID, fixtures.CrossWalletTxID, int32(999003), int64(15_000), fixtures.WriteAddressID,
	)
	if err != nil {
		return planSummary{}, err
	}
	return plan, nil
}

func explainMarkUtxoSpent(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return planSummary{}, err
	}
	defer tx.Rollback(ctx)
	return explainJSONTx(ctx, tx, queries.MarkUtxoSpent,
		fixtures.WalletID,
		fixtures.MarkSpendParentTxHash,
		fixtures.MarkSpendOutputIndex,
		fixtures.MarkSpendReplacementTxID,
		int32(0),
	)
}

func explainClearSpentByTxID(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return planSummary{}, err
	}
	defer tx.Rollback(ctx)
	return explainJSONTx(ctx, tx, queries.ClearSpentByTxID, fixtures.WalletID, fixtures.ClearSpentByTxID)
}

func explainDeleteUtxosByTxID(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return planSummary{}, err
	}
	defer tx.Rollback(ctx)
	return explainJSONTx(ctx, tx, queries.DeleteUtxosByTxID, fixtures.WalletID, fixtures.DeleteTxID)
}

func runListUtxosWallet(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	rows, err := conn.Query(ctx, queries.ListUtxos, fixtures.WalletID, nil, nil, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	count := 0
	var sum int64
	for rows.Next() {
		var txHash []byte
		var outputIndex int32
		var amount int64
		var script []byte
		var received time.Time
		var coinbase bool
		var blockHeight sql.NullInt32
		if err := rows.Scan(&txHash, &outputIndex, &amount, &script, &received, &coinbase, &blockHeight); err != nil {
			return "", err
		}
		count++
		sum += amount
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d,sum=%d", count, sum), nil
}

func runListUtxosAccount(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	minConf := int32(1)
	rows, err := conn.Query(ctx, queries.ListUtxosByAcct, fixtures.WalletID, fixtures.AccountNumber, minConf, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	count := 0
	var sum int64
	for rows.Next() {
		var txHash []byte
		var outputIndex int32
		var amount int64
		var script []byte
		var received time.Time
		var coinbase bool
		var blockHeight sql.NullInt32
		if err := rows.Scan(&txHash, &outputIndex, &amount, &script, &received, &coinbase, &blockHeight); err != nil {
			return "", err
		}
		count++
		sum += amount
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d,sum=%d", count, sum), nil
}

func runBalance(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	minConf := int32(1)
	coinbaseMaturity := int32(100)
	var total int64
	var locked int64
	err := conn.QueryRow(ctx, queries.Balance, fixtures.WalletID, nil, minConf, nil, coinbaseMaturity).Scan(&total, &locked)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("total=%d,locked=%d", total, locked), nil
}

func runGetUtxoByOutpoint(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	var txHash []byte
	var outputIndex int32
	var amount int64
	var script []byte
	var received time.Time
	var coinbase bool
	var blockHeight sql.NullInt32
	err := conn.QueryRow(ctx, queries.GetUtxoByOutpoint, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex).Scan(
		&txHash, &outputIndex, &amount, &script, &received, &coinbase, &blockHeight,
	)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("amount=%d,height=%v", amount, blockHeight.Int32), nil
}

func runGetUtxoIDByOutpoint(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	var utxoID int64
	err := conn.QueryRow(ctx, queries.GetUtxoIDByOutpt, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex).Scan(&utxoID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("utxo_id=%d", utxoID), nil
}

func runAcquireLease(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, iter int) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var expiresAt time.Time
	err = tx.QueryRow(ctx, queries.AcquireLease,
		fixtures.WalletID,
		fixtures.AcquireTxHash,
		fixtures.AcquireOutputIndex,
		lockID(fixtures.LookupUtxoID+int64(iter)+123_000),
		fixtures.AcquireExpiresAt,
	).Scan(&expiresAt)
	if err != nil {
		return "", err
	}
	return expiresAt.UTC().Format(time.RFC3339Nano), nil
}

func runReleaseLease(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	cmd, err := tx.Exec(ctx, queries.ReleaseLease, fixtures.ReleaseWalletID, fixtures.ReleaseUtxoID, fixtures.ReleaseLockID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", cmd.RowsAffected()), nil
}

func runInsertTxAndCredits(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, iter int) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	newHash := fixedHash("newtx", int64(iter+1))
	var txID int64
	err = tx.QueryRow(ctx, queries.InsertTransaction,
		fixtures.WalletID,
		newHash,
		fixedHash("raw", int64(iter+1)),
		nil,
		int16(0),
		fixtures.InsertReceivedTime,
		false,
		"",
	).Scan(&txID)
	if err != nil {
		return "", err
	}
	inserted := 0
	for outputIndex := int32(0); outputIndex < 2; outputIndex++ {
		var utxoID int64
		err = tx.QueryRow(ctx, queries.InsertUtxo,
			fixtures.WalletID,
			txID,
			outputIndex,
			int64(20_000+outputIndex),
			fixtures.WriteAddressID,
		).Scan(&utxoID)
		if err != nil {
			return "", err
		}
		inserted++
	}
	return fmt.Sprintf("credits=%d", inserted), nil
}

func runMarkUtxoSpent(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	cmd, err := tx.Exec(ctx, queries.MarkUtxoSpent,
		fixtures.WalletID,
		fixtures.MarkSpendParentTxHash,
		fixtures.MarkSpendOutputIndex,
		fixtures.MarkSpendReplacementTxID,
		int32(0),
	)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", cmd.RowsAffected()), nil
}

func runClearSpentByTxID(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	cmd, err := tx.Exec(ctx, queries.ClearSpentByTxID, fixtures.WalletID, fixtures.ClearSpentByTxID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", cmd.RowsAffected()), nil
}

func runDeleteUtxosByTxID(ctx context.Context, conn *pgxpool.Conn, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	cmd, err := tx.Exec(ctx, queries.DeleteUtxosByTxID, fixtures.WalletID, fixtures.DeleteTxID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", cmd.RowsAffected()), nil
}

func explainJSON(ctx context.Context, conn *pgxpool.Conn, query string, args ...any) (planSummary, error) {
	return explainJSONConn(ctx, conn, query, args...)
}

func explainJSONTx(ctx context.Context, tx pgx.Tx, query string, args ...any) (planSummary, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, args...).Scan(&raw); err != nil {
		return planSummary{}, err
	}
	return parseExplain(raw)
}

func explainJSONConn(ctx context.Context, conn *pgxpool.Conn, query string, args ...any) (planSummary, error) {
	var raw []byte
	if err := conn.QueryRow(ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, args...).Scan(&raw); err != nil {
		return planSummary{}, err
	}
	return parseExplain(raw)
}

func parseExplain(raw []byte) (planSummary, error) {
	var roots []explainRoot
	if err := json.Unmarshal(raw, &roots); err != nil {
		return planSummary{}, err
	}
	if len(roots) == 0 {
		return planSummary{}, errors.New("empty explain output")
	}
	indexes := make(map[string]struct{})
	collectIndexes(roots[0].Plan, indexes)
	indexNames := make([]string, 0, len(indexes))
	for name := range indexes {
		indexNames = append(indexNames, name)
	}
	sort.Strings(indexNames)
	return planSummary{
		PlanningMs:       roots[0].PlanningTime,
		ExecutionMs:      roots[0].ExecutionTime,
		RootNode:         roots[0].Plan.NodeType,
		ActualRows:       int64(roots[0].Plan.ActualRows),
		SharedHitBlocks:  roots[0].Plan.SharedHitBlocks,
		SharedReadBlocks: roots[0].Plan.SharedReadBlocks,
		IndexNames:       indexNames,
	}, nil
}

func collectIndexes(node explainNode, indexes map[string]struct{}) {
	if node.IndexName != "" {
		indexes[node.IndexName] = struct{}{}
	}
	for _, child := range node.Plans {
		collectIndexes(child, indexes)
	}
}

func measureStorage(ctx context.Context, conn *pgxpool.Conn) ([]relationSize, int64, error) {
	rels := []string{
		"transactions",
		"utxos",
		"utxo_leases",
		"idx_transactions_live_by_wallet",
		"idx_utxos_unspent",
		"idx_utxos_spent_by",
		"idx_utxos_by_tx",
		"idx_utxo_leases_wallet_expires_at",
	}
	rows, err := conn.Query(ctx, `
		SELECT
			c.relname,
			pg_relation_size(c.oid),
			CASE WHEN c.relkind = 'r' THEN pg_indexes_size(c.oid) ELSE 0 END,
			pg_total_relation_size(c.oid)
		FROM pg_class AS c
		JOIN pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = ANY($1)
		ORDER BY c.relname
	`, rels)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	results := make([]relationSize, 0)
	for rows.Next() {
		var item relationSize
		if err := rows.Scan(&item.Name, &item.TableBytes, &item.IndexBytes, &item.TotalBytes); err != nil {
			return nil, 0, err
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var dbBytes int64
	if err := conn.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&dbBytes); err != nil {
		return nil, 0, err
	}
	return results, dbBytes, nil
}

func runIntegrityChecks(ctx context.Context, conn *pgxpool.Conn, withWalletID bool, plan datasetPlan) ([]integrityCheckResult, error) {
	results := make([]integrityCheckResult, 0, 3)
	fixtures := plan.Fixtures

	txEdgeResult, err := attemptIntegrityCheck(ctx, conn, func(tx pgx.Tx) error {
		if withWalletID {
			_, err := tx.Exec(ctx, `
				INSERT INTO utxos (
					wallet_id, tx_id, output_index, amount, address_id,
					spent_by_tx_id, spent_input_index
				) VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, fixtures.WalletID, fixtures.CrossWalletTxID, int32(999001), int64(1), fixtures.CrossWalletAddressIDA, fixtures.CrossWalletSpenderTxID, int32(0))
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO utxos (
				tx_id, output_index, amount, address_id,
				spent_by_tx_id, spent_input_index
			) VALUES ($1, $2, $3, $4, $5, $6)
		`, fixtures.CrossWalletTxID, int32(999001), int64(1), fixtures.CrossWalletAddressIDA, fixtures.CrossWalletSpenderTxID, int32(0))
		return err
	})
	if err != nil {
		return nil, err
	}
	results = append(results, integrityCheckResult{Name: "cross-wallet spent_by tx link", Outcome: txEdgeResult.Outcome, ErrorMsg: txEdgeResult.ErrorMsg})

	leaseResult, err := attemptIntegrityCheck(ctx, conn, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO utxo_leases (wallet_id, utxo_id, lock_id, expires_at)
			VALUES ($1, $2, $3, $4)
		`, fixtures.CrossWalletLeaseWalletID, fixtures.CrossWalletLeaseUtxoID, lockID(fixtures.CrossWalletLeaseUtxoID+77), time.Now().UTC().Add(time.Hour))
		return err
	})
	if err != nil {
		return nil, err
	}
	results = append(results, integrityCheckResult{Name: "cross-wallet lease link", Outcome: leaseResult.Outcome, ErrorMsg: leaseResult.ErrorMsg})

	addressResult, err := attemptIntegrityCheck(ctx, conn, func(tx pgx.Tx) error {
		if withWalletID {
			_, err := tx.Exec(ctx, `
				INSERT INTO utxos (
					wallet_id, tx_id, output_index, amount, address_id
				) VALUES ($1, $2, $3, $4, $5)
			`, fixtures.WalletID, fixtures.CrossWalletTxID, int32(999002), int64(1), fixtures.CrossWalletAddressIDB)
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO utxos (
				tx_id, output_index, amount, address_id
			) VALUES ($1, $2, $3, $4)
		`, fixtures.CrossWalletTxID, int32(999002), int64(1), fixtures.CrossWalletAddressIDB)
		return err
	})
	if err != nil {
		return nil, err
	}
	results = append(results, integrityCheckResult{Name: "cross-wallet address link", Outcome: addressResult.Outcome, ErrorMsg: addressResult.ErrorMsg})

	return results, nil
}

type integrityOutcome struct {
	Outcome  string
	ErrorMsg string
}

func attemptIntegrityCheck(ctx context.Context, conn *pgxpool.Conn, fn func(pgx.Tx) error) (integrityOutcome, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return integrityOutcome{}, err
	}
	defer tx.Rollback(ctx)
	err = fn(tx)
	if err == nil {
		return integrityOutcome{Outcome: "allowed"}, nil
	}
	return integrityOutcome{Outcome: "rejected", ErrorMsg: err.Error()}, nil
}

func buildReport(scale scaleConfig, plan datasetPlan, a variantResult, b variantResult, notes ...string) string {
	var buf bytes.Buffer
	buf.WriteString("# UTXO wallet_id analysis\n\n")
	buf.WriteString(fmt.Sprintf("- scale: `%s`\n", scale.Name))
	buf.WriteString(fmt.Sprintf("- large wallet utxos: `%d`\n", scale.LargeWalletUtxos))
	buf.WriteString(fmt.Sprintf("- other wallets: `%d` wallets x `%d` utxos\n", scale.OtherWalletCount, scale.OtherWalletUtxos))
	if len(plan.Wallets) > 0 {
		buf.WriteString(fmt.Sprintf("- txs per large wallet: `%d`\n", plan.Wallets[0].TxCount))
		buf.WriteString(fmt.Sprintf("- outputs per tx: `%d`\n", plan.Wallets[0].OutputsPerTx))
	}
	buf.WriteString(fmt.Sprintf("- total wallets: `%d`\n", len(plan.Wallets)))
	buf.WriteString(fmt.Sprintf("- total tx rows: `%d`\n", plan.MaxTxID))
	buf.WriteString(fmt.Sprintf("- total utxo rows: `%d`\n", plan.MaxUtxoID))
	buf.WriteString(fmt.Sprintf("- benchmark repeats: `%d`\n\n", scale.BenchmarkRepeats))

	buf.WriteString("## Performance\n\n")
	buf.WriteString("| Query | A exec ms | B exec ms | A p50 ms | B p50 ms | Winner | Indexes |\n")
	buf.WriteString("| --- | ---: | ---: | ---: | ---: | --- | --- |\n")
	for i := range a.Benchmarks {
		left := a.Benchmarks[i]
		right := b.Benchmarks[i]
		winner := decideWinner(left, right)
		buf.WriteString(fmt.Sprintf(
			"| %s | %.2f | %.2f | %.2f | %.2f | %s | `%s` / `%s` |\n",
			left.Name,
			left.Plan.ExecutionMs,
			right.Plan.ExecutionMs,
			left.Timing.P50Ms,
			right.Timing.P50Ms,
			winner,
			strings.Join(left.Plan.IndexNames, ", "),
			strings.Join(right.Plan.IndexNames, ", "),
		))
	}
	buf.WriteString("\n")

	buf.WriteString("## Storage\n\n")
	buf.WriteString(fmt.Sprintf("- A database size: `%s`\n", humanBytes(a.DatabaseBytes)))
	buf.WriteString(fmt.Sprintf("- B database size: `%s`\n\n", humanBytes(b.DatabaseBytes)))
	buf.WriteString("| Relation | A total | B total | Delta |\n")
	buf.WriteString("| --- | ---: | ---: | ---: |\n")
	for _, relName := range mergeRelationNames(a.Relations, b.Relations) {
		left := relationByName(a.Relations, relName)
		right := relationByName(b.Relations, relName)
		delta := right.TotalBytes - left.TotalBytes
		buf.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", relName, humanBytes(left.TotalBytes), humanBytes(right.TotalBytes), signedHumanBytes(delta)))
	}
	buf.WriteString("\n")

	buf.WriteString("## Integrity\n\n")
	buf.WriteString("| Check | A | B |\n")
	buf.WriteString("| --- | --- | --- |\n")
	for _, name := range integrityNames(a.IntegrityChecks, b.IntegrityChecks) {
		left := integrityByName(a.IntegrityChecks, name)
		right := integrityByName(b.IntegrityChecks, name)
		buf.WriteString(fmt.Sprintf("| %s | %s | %s |\n", name, formatIntegrity(left), formatIntegrity(right)))
	}
	buf.WriteString("\n")

	buf.WriteString("## Notes\n\n")
	buf.WriteString("- Variant B keeps `utxo_leases.wallet_id` for a fair performance comparison, but its FK can only anchor `utxo_id`, so wallet/lease consistency is no longer enforced by the DB.\n")
	buf.WriteString("- Both variants still rely on query/application logic for `address_id` wallet ownership because `addresses` does not carry `wallet_id`.\n")
	for _, note := range notes {
		buf.WriteString("- " + note + "\n")
	}
	return buf.String()
}

func decideWinner(a benchmarkResult, b benchmarkResult) string {
	if a.Plan.ExecutionMs == 0 && b.Plan.ExecutionMs == 0 {
		return "tie"
	}
	margin := 0.05
	delta := (b.Plan.ExecutionMs - a.Plan.ExecutionMs) / a.Plan.ExecutionMs
	if math.Abs(delta) <= margin {
		return "tie"
	}
	if delta > 0 {
		return "A"
	}
	return "B"
}

func relationByName(relations []relationSize, name string) relationSize {
	for _, rel := range relations {
		if rel.Name == name {
			return rel
		}
	}
	return relationSize{Name: name}
}

func mergeRelationNames(a []relationSize, b []relationSize) []string {
	set := make(map[string]struct{})
	for _, rel := range a {
		set[rel.Name] = struct{}{}
	}
	for _, rel := range b {
		set[rel.Name] = struct{}{}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func integrityByName(items []integrityCheckResult, name string) integrityCheckResult {
	for _, item := range items {
		if item.Name == name {
			return item
		}
	}
	return integrityCheckResult{Name: name}
}

func integrityNames(a []integrityCheckResult, b []integrityCheckResult) []string {
	set := make(map[string]struct{})
	for _, item := range a {
		set[item.Name] = struct{}{}
	}
	for _, item := range b {
		set[item.Name] = struct{}{}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func formatIntegrity(item integrityCheckResult) string {
	if item.Outcome == "" {
		return "n/a"
	}
	if item.ErrorMsg == "" {
		return item.Outcome
	}
	return fmt.Sprintf("%s (`%s`)", item.Outcome, shortErr(item.ErrorMsg))
}

func shortErr(err string) string {
	if len(err) <= 80 {
		return err
	}
	return err[:77] + "..."
}

func humanBytes(n int64) string {
	if n == 0 {
		return "0 B"
	}
	units := []string{"B", "KiB", "MiB", "GiB"}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return fmt.Sprintf("%.2f %s", value, units[unit])
}

func signedHumanBytes(n int64) string {
	if n >= 0 {
		return "+" + humanBytes(n)
	}
	return "-" + humanBytes(-n)
}

func copyRows(ctx context.Context, pool *pgxpool.Pool, table string, columns []string, rows [][]any) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	_, err = conn.Conn().CopyFrom(ctx, pgx.Identifier{table}, columns, pgx.CopyFromRows(rows))
	return err
}

func txHash(id int64) []byte {
	return fixedHash("tx", id)
}

func rawTx(id int64) []byte {
	return fixedHash("raw", id)
}

func headerHash(height int32) []byte {
	return fixedHash("blk", int64(height))
}

func lockID(id int64) []byte {
	return fixedHash("lock", id)
}

func scriptPubKey(id int64) []byte {
	return append([]byte{0x00, 0x14}, fixedHash("spk", id)[:20]...)
}

func bytesForID(tag string, id int64) []byte {
	buf := make([]byte, 0, len(tag)+8)
	buf = append(buf, []byte(tag)...)
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(id))
	buf = append(buf, num[:]...)
	return buf
}

func fixedHash(tag string, id int64) []byte {
	payload := bytesForID(tag, id)
	sum := sha256.Sum256(payload)
	return sum[:]
}

func currentQueries() querySet {
	return querySet{
		ListUtxos: `
			SELECT
				t.tx_hash,
				u.output_index,
				u.amount,
				a.script_pub_key,
				t.received_time,
				t.is_coinbase,
				t.block_height
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON u.wallet_id = s.wallet_id
			WHERE
				u.wallet_id = $1
				AND ks.wallet_id = $1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND ($2::BIGINT IS NULL OR acc.account_number = $2::BIGINT)
				AND (
					$3::INTEGER IS NULL
					OR $3::INTEGER = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $3::INTEGER
				)
				AND (
					$4::INTEGER IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= $4::INTEGER
				)
			ORDER BY u.amount, t.tx_hash, u.output_index
		`,
		ListUtxosByAcct: `
			SELECT
				t.tx_hash,
				u.output_index,
				u.amount,
				a.script_pub_key,
				t.received_time,
				t.is_coinbase,
				t.block_height
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON u.wallet_id = s.wallet_id
			WHERE
				u.wallet_id = $1
				AND ks.wallet_id = $1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND ($2::BIGINT IS NULL OR acc.account_number = $2::BIGINT)
				AND (
					$3::INTEGER IS NULL
					OR $3::INTEGER = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $3::INTEGER
				)
				AND (
					$4::INTEGER IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= $4::INTEGER
				)
			ORDER BY u.amount, t.tx_hash, u.output_index
		`,
		Balance: `
			SELECT
				(coalesce(sum(u.amount), 0))::BIGINT AS total_balance,
				(coalesce(
					sum(u.amount) FILTER (
						WHERE EXISTS (
							SELECT 1
							FROM utxo_leases AS l
							WHERE
								l.wallet_id = u.wallet_id
								AND l.utxo_id = u.id
								AND l.expires_at > current_timestamp
						)
					),
					0
				))::BIGINT AS locked_balance
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON u.wallet_id = s.wallet_id
			WHERE
				u.wallet_id = $1
				AND ks.wallet_id = $1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND ($2::BIGINT IS NULL OR acc.account_number = $2::BIGINT)
				AND (
					$3::INTEGER IS NULL
					OR $3::INTEGER = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $3::INTEGER
				)
				AND (
					$4::INTEGER IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= $4::INTEGER
				)
				AND (
					$5::INTEGER IS NULL
					OR NOT t.is_coinbase
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $5::INTEGER
				)
		`,
		GetUtxoByOutpoint: `
			SELECT
				t.tx_hash,
				u.output_index,
				u.amount,
				a.script_pub_key,
				t.received_time,
				t.is_coinbase,
				t.block_height
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE
				u.wallet_id = $1
				AND ks.wallet_id = $1
				AND t.tx_hash = $2
				AND u.output_index = $3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
		`,
		GetUtxoIDByOutpt: `
			SELECT u.id
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE
				u.wallet_id = $1
				AND ks.wallet_id = $1
				AND t.tx_hash = $2
				AND u.output_index = $3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
		`,
		AcquireLease: `
			INSERT INTO utxo_leases (
				wallet_id,
				utxo_id,
				lock_id,
				expires_at
			)
			SELECT
				$1,
				u.id,
				$4,
				$5::TIMESTAMPTZ
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			WHERE
				u.wallet_id = $1
				AND t.tx_hash = $2
				AND u.output_index = $3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
			FOR UPDATE OF u
			ON CONFLICT (wallet_id, utxo_id) DO UPDATE
			SET
				lock_id = excluded.lock_id,
				expires_at = excluded.expires_at
			WHERE
				utxo_leases.expires_at <= current_timestamp
				OR utxo_leases.lock_id = excluded.lock_id
			RETURNING expires_at
		`,
		ReleaseLease: `
			DELETE FROM utxo_leases
			WHERE
				wallet_id = $1
				AND utxo_id = $2
				AND lock_id = $3
		`,
		MarkUtxoSpent: `
			UPDATE utxos AS u
			SET
				spent_by_tx_id = $4,
				spent_input_index = $5
			WHERE
				u.wallet_id = $1
				AND u.tx_id = (
					SELECT t.id
					FROM transactions AS t
					WHERE
						t.wallet_id = $1
						AND t.tx_hash = $2
						AND t.status IN (0, 1)
				)
				AND u.output_index = $3
				AND (
					(u.spent_by_tx_id IS NULL AND u.spent_input_index IS NULL)
					OR (u.spent_by_tx_id = $4 AND u.spent_input_index = $5)
				)
		`,
		ClearSpentByTxID: `
			UPDATE utxos
			SET
				spent_by_tx_id = NULL,
				spent_input_index = NULL
			WHERE wallet_id = $1 AND spent_by_tx_id = $2
		`,
		DeleteUtxosByTxID: `
			DELETE FROM utxos
			WHERE wallet_id = $1 AND tx_id = $2
		`,
		InsertTransaction: `
			INSERT INTO transactions (
				wallet_id,
				tx_hash,
				raw_tx,
				block_height,
				status,
				received_time,
				is_coinbase,
				label
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8
			)
			RETURNING id
		`,
		InsertUtxo: `
			INSERT INTO utxos (
				wallet_id,
				tx_id,
				output_index,
				amount,
				address_id
			) SELECT
				$1,
				$2,
				$3,
				$4,
				a.id
			FROM addresses AS a
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE
				a.id = $5
				AND ks.wallet_id = $1
			RETURNING id
		`,
	}
}

func normalizedQueries() querySet {
	return querySet{
		ListUtxos: `
			SELECT
				t.tx_hash,
				u.output_index,
				u.amount,
				a.script_pub_key,
				t.received_time,
				t.is_coinbase,
				t.block_height
			FROM utxos AS u
			INNER JOIN transactions AS t ON u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
			WHERE
				t.wallet_id = $1
				AND ks.wallet_id = $1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND ($2::BIGINT IS NULL OR acc.account_number = $2::BIGINT)
				AND (
					$3::INTEGER IS NULL
					OR $3::INTEGER = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $3::INTEGER
				)
				AND (
					$4::INTEGER IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= $4::INTEGER
				)
			ORDER BY u.amount, t.tx_hash, u.output_index
		`,
		ListUtxosByAcct: `
			SELECT
				t.tx_hash,
				u.output_index,
				u.amount,
				a.script_pub_key,
				t.received_time,
				t.is_coinbase,
				t.block_height
			FROM utxos AS u
			INNER JOIN transactions AS t ON u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
			WHERE
				t.wallet_id = $1
				AND ks.wallet_id = $1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND ($2::BIGINT IS NULL OR acc.account_number = $2::BIGINT)
				AND (
					$3::INTEGER IS NULL
					OR $3::INTEGER = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $3::INTEGER
				)
				AND (
					$4::INTEGER IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= $4::INTEGER
				)
			ORDER BY u.amount, t.tx_hash, u.output_index
		`,
		Balance: `
			SELECT
				(coalesce(sum(u.amount), 0))::BIGINT AS total_balance,
				(coalesce(
					sum(u.amount) FILTER (
						WHERE EXISTS (
							SELECT 1
							FROM utxo_leases AS l
							WHERE
								l.wallet_id = t.wallet_id
								AND l.utxo_id = u.id
								AND l.expires_at > current_timestamp
						)
					),
					0
				))::BIGINT AS locked_balance
			FROM utxos AS u
			INNER JOIN transactions AS t ON u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
			WHERE
				t.wallet_id = $1
				AND ks.wallet_id = $1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND ($2::BIGINT IS NULL OR acc.account_number = $2::BIGINT)
				AND (
					$3::INTEGER IS NULL
					OR $3::INTEGER = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $3::INTEGER
				)
				AND (
					$4::INTEGER IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= $4::INTEGER
				)
				AND (
					$5::INTEGER IS NULL
					OR NOT t.is_coinbase
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= $5::INTEGER
				)
		`,
		GetUtxoByOutpoint: `
			SELECT
				t.tx_hash,
				u.output_index,
				u.amount,
				a.script_pub_key,
				t.received_time,
				t.is_coinbase,
				t.block_height
			FROM transactions AS t
			INNER JOIN utxos AS u ON u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE
				t.wallet_id = $1
				AND ks.wallet_id = $1
				AND t.tx_hash = $2
				AND u.output_index = $3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
		`,
		GetUtxoIDByOutpt: `
			SELECT u.id
			FROM transactions AS t
			INNER JOIN utxos AS u ON u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE
				t.wallet_id = $1
				AND ks.wallet_id = $1
				AND t.tx_hash = $2
				AND u.output_index = $3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
		`,
		AcquireLease: `
			INSERT INTO utxo_leases (
				wallet_id,
				utxo_id,
				lock_id,
				expires_at
			)
			SELECT
				$1,
				u.id,
				$4,
				$5::TIMESTAMPTZ
			FROM transactions AS t
			INNER JOIN utxos AS u ON u.tx_id = t.id
			WHERE
				t.wallet_id = $1
				AND t.tx_hash = $2
				AND u.output_index = $3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
			FOR UPDATE OF u
			ON CONFLICT (utxo_id) DO UPDATE
			SET
				lock_id = excluded.lock_id,
				expires_at = excluded.expires_at
			WHERE
				utxo_leases.wallet_id = excluded.wallet_id
				AND (
					utxo_leases.expires_at <= current_timestamp
					OR utxo_leases.lock_id = excluded.lock_id
				)
			RETURNING expires_at
		`,
		ReleaseLease: `
			DELETE FROM utxo_leases
			WHERE
				wallet_id = $1
				AND utxo_id = $2
				AND lock_id = $3
		`,
		MarkUtxoSpent: `
			UPDATE utxos AS u
			SET
				spent_by_tx_id = $4,
				spent_input_index = $5
			WHERE
				u.tx_id = (
					SELECT t.id
					FROM transactions AS t
					WHERE
						t.wallet_id = $1
						AND t.tx_hash = $2
						AND t.status IN (0, 1)
				)
				AND u.output_index = $3
				AND (
					(u.spent_by_tx_id IS NULL AND u.spent_input_index IS NULL)
					OR (u.spent_by_tx_id = $4 AND u.spent_input_index = $5)
				)
		`,
		ClearSpentByTxID: `
			UPDATE utxos
			SET
				spent_by_tx_id = NULL,
				spent_input_index = NULL
			WHERE $1::BIGINT IS NOT NULL AND spent_by_tx_id = $2
		`,
		DeleteUtxosByTxID: `
			DELETE FROM utxos
			WHERE $1::BIGINT IS NOT NULL AND tx_id = $2
		`,
		InsertTransaction: currentQueries().InsertTransaction,
		InsertUtxo: `
			INSERT INTO utxos (
				tx_id,
				output_index,
				amount,
				address_id
			) SELECT
				$2,
				$3,
				$4,
				a.id
			FROM addresses AS a
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE
				a.id = $5
				AND ks.wallet_id = $1
			RETURNING id
		`,
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func hexString(b []byte) string {
	return hex.EncodeToString(b)
}
