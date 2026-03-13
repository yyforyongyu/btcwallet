package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	dbkit "github.com/btcsuite/btcwallet/wallet/internal/db"
	_ "modernc.org/sqlite"
)

type benchmarkCaseSQLite struct {
	Name string
	Run  func(context.Context, *sql.DB, querySet, benchmarkFixtures, int) (string, error)
	Plan func(context.Context, *sql.DB, querySet, benchmarkFixtures) (planSummary, error)
}

func runSQLiteAnalysis(ctx context.Context, scale scaleConfig) (string, error) {
	baseDir, err := os.MkdirTemp("", "utxo-walletid-sqlite-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(baseDir)

	aPath := filepath.Join(baseDir, "variant_a.db")
	bPath := filepath.Join(baseDir, "variant_b.db")

	aDB, err := openSQLiteDatabase(ctx, aPath)
	if err != nil {
		return "", err
	}
	defer aDB.Close()
	bDB, err := openSQLiteDatabase(ctx, bPath)
	if err != nil {
		return "", err
	}
	defer bDB.Close()

	if err := dbkit.ApplySQLiteMigrations(aDB); err != nil {
		return "", err
	}
	if err := dbkit.ApplySQLiteMigrations(bDB); err != nil {
		return "", err
	}
	if err := applyVariantBSQLite(ctx, bDB); err != nil {
		return "", err
	}

	plan := buildDatasetPlan(scale)
	if err := seedDatasetSQLite(ctx, aDB, plan, true); err != nil {
		return "", err
	}
	if err := seedDatasetSQLite(ctx, bDB, plan, false); err != nil {
		return "", err
	}

	if err := analyzeSQLite(ctx, aDB); err != nil {
		return "", err
	}
	if err := analyzeSQLite(ctx, bDB); err != nil {
		return "", err
	}

	variantAQueries := currentQueriesSQLite()
	variantBQueries := normalizedQueriesSQLite()
	checks := benchmarkCasesSQLite()

	aResults, err := runBenchmarksSQLite(ctx, aDB, variantAQueries, plan.Fixtures, scale, checks)
	if err != nil {
		return "", err
	}
	bResults, err := runBenchmarksSQLite(ctx, bDB, variantBQueries, plan.Fixtures, scale, checks)
	if err != nil {
		return "", err
	}
	if err := ensureComparableResults(aResults, bResults); err != nil {
		return "", err
	}

	aIntegrity, err := runIntegrityChecksSQLite(ctx, aDB, true, plan)
	if err != nil {
		return "", err
	}
	bIntegrity, err := runIntegrityChecksSQLite(ctx, bDB, false, plan)
	if err != nil {
		return "", err
	}

	aRelations, aDBSize, err := measureSQLiteStorage(ctx, aDB, aPath)
	if err != nil {
		return "", err
	}
	bRelations, bDBSize, err := measureSQLiteStorage(ctx, bDB, bPath)
	if err != nil {
		return "", err
	}

	report := buildReport(scale, plan, variantResult{
		Variant:         "A current (keep utxos.wallet_id)",
		Benchmarks:      aResults,
		Relations:       aRelations,
		DatabaseBytes:   aDBSize,
		IntegrityChecks: aIntegrity,
	}, variantResult{
		Variant:         "B normalized (drop utxos.wallet_id)",
		Benchmarks:      bResults,
		Relations:       bRelations,
		DatabaseBytes:   bDBSize,
		IntegrityChecks: bIntegrity,
	}, "Read timings are end-to-end client timings; `A exec ms` and `B exec ms` are single timed runs, and indexes come from `EXPLAIN QUERY PLAN` details.")

	return strings.Replace(report, "# UTXO wallet_id analysis", "# UTXO wallet_id analysis (sqlite)", 1), nil
}

func openSQLiteDatabase(ctx context.Context, path string) (*sql.DB, error) {
	dsn := path + "?_pragma=foreign_keys=on"
	dsn += "&_pragma=journal_mode=WAL"
	dsn += "&_txlock=immediate"
	dsn += "&_pragma=busy_timeout=5000"
	dsn += "&_time_format=sqlite"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	pragmas := []string{
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA temp_store = MEMORY`,
	}
	for _, stmt := range pragmas {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

func applyVariantBSQLite(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`DROP VIEW spendable_utxos`,
		`DROP TABLE utxo_leases`,
		`DROP TABLE utxos`,
		`CREATE TABLE utxos (
			id INTEGER PRIMARY KEY,
			tx_id INTEGER NOT NULL,
			output_index INTEGER NOT NULL CHECK (output_index >= 0),
			amount INTEGER NOT NULL CHECK (amount >= 0),
			address_id INTEGER NOT NULL REFERENCES addresses (id) ON DELETE RESTRICT,
			spent_by_tx_id INTEGER,
			spent_input_index INTEGER CHECK (
				spent_input_index IS NULL OR spent_input_index >= 0
			),
			CONSTRAINT fkey_utxos_tx FOREIGN KEY (tx_id)
			REFERENCES transactions (id) ON DELETE RESTRICT,
			CONSTRAINT fkey_utxos_spent_by FOREIGN KEY (spent_by_tx_id)
			REFERENCES transactions (id) ON DELETE RESTRICT,
			CONSTRAINT check_spent_tx_and_index_pair CHECK (
				(spent_by_tx_id IS NULL AND spent_input_index IS NULL)
				OR (spent_by_tx_id IS NOT NULL AND spent_input_index IS NOT NULL)
			),
			CONSTRAINT uidx_utxos_outpoint UNIQUE (tx_id, output_index)
		)`,
		`CREATE INDEX idx_utxos_unspent
		ON utxos (tx_id, amount, output_index)
		WHERE spent_by_tx_id IS NULL`,
		`CREATE INDEX idx_utxos_by_address ON utxos (address_id)`,
		`CREATE INDEX idx_utxos_spent_by ON utxos (spent_by_tx_id)`,
		`CREATE INDEX idx_utxos_by_tx ON utxos (tx_id)`,
		`CREATE TABLE utxo_leases (
			wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,
			utxo_id INTEGER PRIMARY KEY,
			lock_id BLOB NOT NULL CHECK (length(lock_id) = 32),
			expires_at TIMESTAMP NOT NULL,
			CONSTRAINT fkey_utxo_leases_utxo FOREIGN KEY (utxo_id)
			REFERENCES utxos (id) ON DELETE CASCADE
		)`,
		`CREATE INDEX idx_utxo_leases_wallet_expires_at
		ON utxo_leases (wallet_id, expires_at)`,
		`CREATE INDEX idx_transactions_live_by_wallet
		ON transactions (wallet_id, id)
		WHERE status IN (0, 1)`,
		`CREATE VIEW spendable_utxos AS
		SELECT
			t.wallet_id,
			u.id,
			u.tx_id,
			u.output_index,
			u.amount,
			u.address_id,
			t.block_height,
			t.is_coinbase,
			t.status AS tx_status
		FROM utxos AS u
		INNER JOIN transactions AS t ON u.tx_id = t.id
		WHERE u.spent_by_tx_id IS NULL AND t.status IN (0, 1)`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

func seedDatasetSQLite(ctx context.Context, db *sql.DB, plan datasetPlan, withWalletID bool) error {
	if err := seedBlocksSQLite(ctx, db, plan.MaxBlockHeight); err != nil {
		return err
	}
	if err := seedWalletsSQLite(ctx, db, plan); err != nil {
		return err
	}
	if err := seedKeyScopesSQLite(ctx, db, plan); err != nil {
		return err
	}
	if err := seedAccountsSQLite(ctx, db, plan); err != nil {
		return err
	}
	if err := seedAddressesSQLite(ctx, db, plan); err != nil {
		return err
	}
	if err := seedWalletSyncStatesSQLite(ctx, db, plan); err != nil {
		return err
	}
	if err := seedTransactionsSQLite(ctx, db, plan); err != nil {
		return err
	}
	if err := seedUtxosSQLite(ctx, db, plan, withWalletID); err != nil {
		return err
	}
	if err := seedLeasesSQLite(ctx, db, plan); err != nil {
		return err
	}
	return nil
}

func seedBlocksSQLite(ctx context.Context, db *sql.DB, maxHeight int32) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO blocks (block_height, header_hash, block_timestamp) VALUES (?, ?, ?)`,
		func(exec func(...any) error) error {
			for height := int32(1); height <= maxHeight; height++ {
				if err := exec(height, headerHash(height), int64(1_700_000_000+height*600)); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func seedWalletsSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO wallets (
			id, wallet_name, is_imported, manager_version, is_watch_only,
			master_pub_params, encrypted_crypto_pub_key, encrypted_master_hd_pub_key
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		func(exec func(...any) error) error {
			for _, wallet := range plan.Wallets {
				if err := exec(
					wallet.WalletID,
					wallet.WalletName,
					false,
					1,
					false,
					bytesForID("mp", wallet.WalletID),
					bytesForID("cp", wallet.WalletID),
					bytesForID("hp", wallet.WalletID),
				); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func seedKeyScopesSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO key_scopes (
			id, wallet_id, purpose, coin_type, internal_type_id, external_type_id
		) VALUES (?, ?, ?, ?, ?, ?)`,
		func(exec func(...any) error) error {
			for _, wallet := range plan.Wallets {
				if err := exec(wallet.ScopeID, wallet.WalletID, int64(84), int64(0), int64(4), int64(4)); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func seedAccountsSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO accounts (
			id, scope_id, account_number, account_name, origin_id, is_watch_only
		) VALUES (?, ?, ?, ?, ?, ?)`,
		func(exec func(...any) error) error {
			for _, wallet := range plan.Wallets {
				for acct := 0; acct < wallet.AccountsPerWallet; acct++ {
					if err := exec(
						wallet.AccountBaseID+int64(acct),
						wallet.ScopeID,
						int64(acct),
						fmt.Sprintf("acct-%02d", acct),
						0,
						false,
					); err != nil {
						return err
					}
				}
			}
			return nil
		},
	)
}

func seedAddressesSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO addresses (
			id, account_id, script_pub_key, type_id, address_branch, address_index
		) VALUES (?, ?, ?, ?, ?, ?)`,
		func(exec func(...any) error) error {
			for _, wallet := range plan.Wallets {
				for acct := 0; acct < wallet.AccountsPerWallet; acct++ {
					accountID := wallet.AccountBaseID + int64(acct)
					for offset := 0; offset < wallet.AddressesPerAcct; offset++ {
						id := addressID(wallet, acct, offset)
						if err := exec(id, accountID, scriptPubKey(id), 4, 0, int64(offset)); err != nil {
							return err
						}
					}
				}
			}
			return nil
		},
	)
}

func seedWalletSyncStatesSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO wallet_sync_states (wallet_id, synced_height, updated_at) VALUES (?, ?, ?)`,
		func(exec func(...any) error) error {
			now := time.Unix(1_700_000_000, 0).UTC()
			for _, wallet := range plan.Wallets {
				if err := exec(wallet.WalletID, plan.MaxBlockHeight, now); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func seedTransactionsSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO transactions (
			id, wallet_id, tx_hash, raw_tx, block_height, status,
			received_time, is_coinbase, label
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		func(exec func(...any) error) error {
			for _, wallet := range plan.Wallets {
				for txOffset := 0; txOffset < wallet.TxCount; txOffset++ {
					txID := wallet.TxBaseID + int64(txOffset)
					confirmed := txOffset < wallet.ConfirmedTxCount
					var blockHeight any
					status := 0
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
					if err := exec(
						txID,
						wallet.WalletID,
						txHash(txID),
						rawTx(txID),
						blockHeight,
						status,
						time.Unix(1_700_000_000+int64(txID), 0).UTC(),
						isCoinbase,
						"",
					); err != nil {
						return err
					}
				}
			}
			return nil
		},
	)
}

func seedUtxosSQLite(ctx context.Context, db *sql.DB, plan datasetPlan, withWalletID bool) error {
	stmt := `INSERT INTO utxos (
		id, wallet_id, tx_id, output_index, amount, address_id, spent_by_tx_id, spent_input_index
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if !withWalletID {
		stmt = `INSERT INTO utxos (
			id, tx_id, output_index, amount, address_id, spent_by_tx_id, spent_input_index
		) VALUES (?, ?, ?, ?, ?, ?, ?)`
	}
	return execSQLiteRows(ctx, db, stmt, func(exec func(...any) error) error {
		for _, wallet := range plan.Wallets {
			for ordinal := 0; ordinal < wallet.UtxoCount; ordinal++ {
				utxoID := wallet.UtxoBaseID + int64(ordinal)
				txOffset := ordinal / wallet.OutputsPerTx
				outputIndex := ordinal % wallet.OutputsPerTx
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
					spentInput = ordinal % wallet.OutputsPerTx
				} else {
					spentBy = nil
					spentInput = nil
				}
				amount := int64(10_000 + (ordinal % 100_000))
				var err error
				if withWalletID {
					err = exec(utxoID, wallet.WalletID, txID, outputIndex, amount, addressID, spentBy, spentInput)
				} else {
					err = exec(utxoID, txID, outputIndex, amount, addressID, spentBy, spentInput)
				}
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func seedLeasesSQLite(ctx context.Context, db *sql.DB, plan datasetPlan) error {
	return execSQLiteRows(ctx, db,
		`INSERT INTO utxo_leases (wallet_id, utxo_id, lock_id, expires_at) VALUES (?, ?, ?, ?)`,
		func(exec func(...any) error) error {
			expiresAt := time.Now().UTC().Add(defaultAcquireLeaseHours * time.Hour)
			for _, wallet := range plan.Wallets {
				for lease := 0; lease < wallet.LeasedCount; lease++ {
					ordinal := wallet.SpentCount + lease
					utxoID := wallet.UtxoBaseID + int64(ordinal)
					if err := exec(wallet.WalletID, utxoID, lockID(utxoID), expiresAt); err != nil {
						return err
					}
				}
			}
			return nil
		},
	)
}

func execSQLiteRows(ctx context.Context, db *sql.DB, stmtText string, emit func(func(...any) error) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, stmtText)
	if err != nil {
		return err
	}
	defer stmt.Close()
	execFn := func(args ...any) error {
		_, err := stmt.ExecContext(ctx, args...)
		return err
	}
	if err := emit(execFn); err != nil {
		return err
	}
	return tx.Commit()
}

func analyzeSQLite(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ANALYZE`)
	return err
}

func benchmarkCasesSQLite() []benchmarkCaseSQLite {
	return []benchmarkCaseSQLite{
		{Name: "ListUtxos(wallet)", Run: runListUtxosWalletSQLite, Plan: explainListUtxosWalletSQLite},
		{Name: "ListUtxos(account)", Run: runListUtxosAccountSQLite, Plan: explainListUtxosAccountSQLite},
		{Name: "Balance", Run: runBalanceSQLite, Plan: explainBalanceSQLite},
		{Name: "GetUtxoByOutpoint", Run: runGetUtxoByOutpointSQLite, Plan: explainGetUtxoByOutpointSQLite},
		{Name: "GetUtxoIDByOutpoint", Run: runGetUtxoIDByOutpointSQLite, Plan: explainGetUtxoIDByOutpointSQLite},
		{Name: "AcquireUtxoLease", Run: runAcquireLeaseSQLite, Plan: explainAcquireLeaseSQLite},
		{Name: "ReleaseUtxoLease", Run: runReleaseLeaseSQLite, Plan: explainReleaseLeaseSQLite},
		{Name: "InsertTx+Credits", Run: runInsertTxAndCreditsSQLite, Plan: explainInsertTxAndCreditsSQLite},
		{Name: "MarkUtxoSpent", Run: runMarkUtxoSpentSQLite, Plan: explainMarkUtxoSpentSQLite},
		{Name: "ClearUtxosSpentByTxID", Run: runClearSpentByTxIDSQLite, Plan: explainClearSpentByTxIDSQLite},
		{Name: "DeleteUtxosByTxID", Run: runDeleteUtxosByTxIDSQLite, Plan: explainDeleteUtxosByTxIDSQLite},
	}
}

func runBenchmarksSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, scale scaleConfig, cases []benchmarkCaseSQLite) ([]benchmarkResult, error) {
	results := make([]benchmarkResult, 0, len(cases))
	for _, bench := range cases {
		plan, err := bench.Plan(ctx, db, queries, fixtures)
		if err != nil {
			return nil, fmt.Errorf("%s explain: %w", bench.Name, err)
		}
		for warmup := 0; warmup < scale.BenchmarkWarmups; warmup++ {
			if _, err := bench.Run(ctx, db, queries, fixtures, warmup); err != nil {
				return nil, fmt.Errorf("%s warmup: %w", bench.Name, err)
			}
		}
		durations := make([]float64, 0, scale.BenchmarkRepeats)
		fingerprint := ""
		for iter := 0; iter < scale.BenchmarkRepeats; iter++ {
			start := time.Now()
			fp, err := bench.Run(ctx, db, queries, fixtures, iter)
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

func explainListUtxosWalletSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.ListUtxos, runListUtxosWalletSQLite, queries, fixtures, fixtures.WalletID, nil, nil, nil)
}

func explainListUtxosAccountSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	minConf := int64(1)
	return explainSQLiteQuery(ctx, db, queries.ListUtxosByAcct, runListUtxosAccountSQLite, queries, fixtures, fixtures.WalletID, fixtures.AccountNumber, minConf, nil)
}

func explainBalanceSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	minConf := int64(1)
	coinbaseMaturity := int64(100)
	return explainSQLiteQuery(ctx, db, queries.Balance, runBalanceSQLite, queries, fixtures, fixtures.WalletID, nil, minConf, nil, coinbaseMaturity)
}

func explainGetUtxoByOutpointSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.GetUtxoByOutpoint, runGetUtxoByOutpointSQLite, queries, fixtures, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex)
}

func explainGetUtxoIDByOutpointSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.GetUtxoIDByOutpt, runGetUtxoIDByOutpointSQLite, queries, fixtures, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex)
}

func explainAcquireLeaseSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.AcquireLease, runAcquireLeaseSQLite, queries, fixtures,
		fixtures.WalletID, fixtures.AcquireTxHash, fixtures.AcquireOutputIndex, lockID(fixtures.LookupUtxoID+999_999), fixtures.AcquireExpiresAt)
}

func explainReleaseLeaseSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.ReleaseLease, runReleaseLeaseSQLite, queries, fixtures,
		fixtures.ReleaseWalletID, fixtures.ReleaseUtxoID, fixtures.ReleaseLockID)
}

func explainInsertTxAndCreditsSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.InsertUtxo, runInsertTxAndCreditsSQLite, queries, fixtures,
		fixtures.WalletID, fixtures.CrossWalletTxID, int64(999003), int64(15_000), fixtures.WriteAddressID)
}

func explainMarkUtxoSpentSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.MarkUtxoSpent, runMarkUtxoSpentSQLite, queries, fixtures,
		fixtures.WalletID, fixtures.MarkSpendParentTxHash, fixtures.MarkSpendOutputIndex, fixtures.MarkSpendReplacementTxID, int64(0))
}

func explainClearSpentByTxIDSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.ClearSpentByTxID, runClearSpentByTxIDSQLite, queries, fixtures,
		fixtures.WalletID, fixtures.ClearSpentByTxID)
}

func explainDeleteUtxosByTxIDSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures) (planSummary, error) {
	return explainSQLiteQuery(ctx, db, queries.DeleteUtxosByTxID, runDeleteUtxosByTxIDSQLite, queries, fixtures,
		fixtures.WalletID, fixtures.DeleteTxID)
}

func explainSQLiteQuery(ctx context.Context, db *sql.DB, query string, runFn func(context.Context, *sql.DB, querySet, benchmarkFixtures, int) (string, error), queries querySet, fixtures benchmarkFixtures, args ...any) (planSummary, error) {
	details, indexes, err := explainSQLiteDetails(ctx, db, query, args...)
	if err != nil {
		return planSummary{}, err
	}
	start := time.Now()
	if _, err := runFn(ctx, db, queries, fixtures, 0); err != nil {
		return planSummary{}, err
	}
	return planSummary{
		ExecutionMs: time.Since(start).Seconds() * 1000,
		RootNode:    strings.Join(details, " | "),
		IndexNames:  indexes,
	}, nil
}

func explainSQLiteDetails(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, []string, error) {
	rows, err := db.QueryContext(ctx, `EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	indexSet := make(map[string]struct{})
	details := make([]string, 0)
	indexRegex := regexp.MustCompile(`USING (?:COVERING )?INDEX ([^ ]+)`)
	for rows.Next() {
		var id int
		var parent int
		var notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			return nil, nil, err
		}
		details = append(details, detail)
		match := indexRegex.FindStringSubmatch(detail)
		if len(match) == 2 {
			indexSet[match[1]] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	indexes := make([]string, 0, len(indexSet))
	for name := range indexSet {
		indexes = append(indexes, name)
	}
	sort.Strings(indexes)
	return details, indexes, nil
}

func runListUtxosWalletSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	rows, err := db.QueryContext(ctx, queries.ListUtxos, fixtures.WalletID, nil, nil, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	count := 0
	var sum int64
	for rows.Next() {
		var txHash []byte
		var outputIndex int64
		var amount int64
		var script []byte
		var received any
		var coinbase bool
		var blockHeight sql.NullInt64
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

func runListUtxosAccountSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	minConf := int64(1)
	rows, err := db.QueryContext(ctx, queries.ListUtxosByAcct, fixtures.WalletID, fixtures.AccountNumber, minConf, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	count := 0
	var sum int64
	for rows.Next() {
		var txHash []byte
		var outputIndex int64
		var amount int64
		var script []byte
		var received any
		var coinbase bool
		var blockHeight sql.NullInt64
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

func runBalanceSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	minConf := int64(1)
	coinbaseMaturity := int64(100)
	var total int64
	var locked int64
	err := db.QueryRowContext(ctx, queries.Balance, fixtures.WalletID, nil, minConf, nil, coinbaseMaturity).Scan(&total, &locked)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("total=%d,locked=%d", total, locked), nil
}

func runGetUtxoByOutpointSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	var txHash []byte
	var outputIndex int64
	var amount int64
	var script []byte
	var received any
	var coinbase bool
	var blockHeight sql.NullInt64
	err := db.QueryRowContext(ctx, queries.GetUtxoByOutpoint, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex).Scan(
		&txHash, &outputIndex, &amount, &script, &received, &coinbase, &blockHeight,
	)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("amount=%d,height=%v", amount, blockHeight.Int64), nil
}

func runGetUtxoIDByOutpointSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	var utxoID int64
	err := db.QueryRowContext(ctx, queries.GetUtxoIDByOutpt, fixtures.WalletID, fixtures.LookupTxHash, fixtures.LookupOutputIndex).Scan(&utxoID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("utxo_id=%d", utxoID), nil
}

func runAcquireLeaseSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, iter int) (string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var expiresAt any
	err = tx.QueryRowContext(ctx, queries.AcquireLease,
		fixtures.WalletID,
		fixtures.AcquireTxHash,
		fixtures.AcquireOutputIndex,
		lockID(fixtures.LookupUtxoID+int64(iter)+123_000),
		fixtures.AcquireExpiresAt,
	).Scan(&expiresAt)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", expiresAt), nil
}

func runReleaseLeaseSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, queries.ReleaseLease, fixtures.ReleaseWalletID, fixtures.ReleaseUtxoID, fixtures.ReleaseLockID)
	if err != nil {
		return "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", rows), nil
}

func runInsertTxAndCreditsSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, iter int) (string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	newHash := fixedHash("newtx", int64(iter+1))
	var txID int64
	err = tx.QueryRowContext(ctx, queries.InsertTransaction,
		fixtures.WalletID,
		newHash,
		fixedHash("raw", int64(iter+1)),
		nil,
		0,
		fixtures.InsertReceivedTime,
		false,
		"",
	).Scan(&txID)
	if err != nil {
		return "", err
	}
	inserted := 0
	for outputIndex := int64(0); outputIndex < 2; outputIndex++ {
		var utxoID int64
		err = tx.QueryRowContext(ctx, queries.InsertUtxo,
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

func runMarkUtxoSpentSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, queries.MarkUtxoSpent,
		fixtures.WalletID,
		fixtures.MarkSpendParentTxHash,
		fixtures.MarkSpendOutputIndex,
		fixtures.MarkSpendReplacementTxID,
		0,
	)
	if err != nil {
		return "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", rows), nil
}

func runClearSpentByTxIDSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, queries.ClearSpentByTxID, fixtures.WalletID, fixtures.ClearSpentByTxID)
	if err != nil {
		return "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", rows), nil
}

func runDeleteUtxosByTxIDSQLite(ctx context.Context, db *sql.DB, queries querySet, fixtures benchmarkFixtures, _ int) (string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, queries.DeleteUtxosByTxID, fixtures.WalletID, fixtures.DeleteTxID)
	if err != nil {
		return "", err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("rows=%d", rows), nil
}

func runIntegrityChecksSQLite(ctx context.Context, db *sql.DB, withWalletID bool, plan datasetPlan) ([]integrityCheckResult, error) {
	results := make([]integrityCheckResult, 0, 3)
	fixtures := plan.Fixtures

	txEdgeResult, err := attemptIntegrityCheckSQLite(ctx, db, func(tx *sql.Tx) error {
		if withWalletID {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO utxos (
					wallet_id, tx_id, output_index, amount, address_id,
					spent_by_tx_id, spent_input_index
				) VALUES (?, ?, ?, ?, ?, ?, ?)
			`, fixtures.WalletID, fixtures.CrossWalletTxID, 999001, int64(1), fixtures.CrossWalletAddressIDA, fixtures.CrossWalletSpenderTxID, 0)
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO utxos (
				tx_id, output_index, amount, address_id,
				spent_by_tx_id, spent_input_index
			) VALUES (?, ?, ?, ?, ?, ?)
		`, fixtures.CrossWalletTxID, 999001, int64(1), fixtures.CrossWalletAddressIDA, fixtures.CrossWalletSpenderTxID, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	results = append(results, integrityCheckResult{Name: "cross-wallet spent_by tx link", Outcome: txEdgeResult.Outcome, ErrorMsg: txEdgeResult.ErrorMsg})

	leaseResult, err := attemptIntegrityCheckSQLite(ctx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO utxo_leases (wallet_id, utxo_id, lock_id, expires_at)
			VALUES (?, ?, ?, ?)
		`, fixtures.CrossWalletLeaseWalletID, fixtures.CrossWalletLeaseUtxoID, lockID(fixtures.CrossWalletLeaseUtxoID+77), time.Now().UTC().Add(time.Hour))
		return err
	})
	if err != nil {
		return nil, err
	}
	results = append(results, integrityCheckResult{Name: "cross-wallet lease link", Outcome: leaseResult.Outcome, ErrorMsg: leaseResult.ErrorMsg})

	addressResult, err := attemptIntegrityCheckSQLite(ctx, db, func(tx *sql.Tx) error {
		if withWalletID {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO utxos (
					wallet_id, tx_id, output_index, amount, address_id
				) VALUES (?, ?, ?, ?, ?)
			`, fixtures.WalletID, fixtures.CrossWalletTxID, 999002, int64(1), fixtures.CrossWalletAddressIDB)
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO utxos (
				tx_id, output_index, amount, address_id
			) VALUES (?, ?, ?, ?)
		`, fixtures.CrossWalletTxID, 999002, int64(1), fixtures.CrossWalletAddressIDB)
		return err
	})
	if err != nil {
		return nil, err
	}
	results = append(results, integrityCheckResult{Name: "cross-wallet address link", Outcome: addressResult.Outcome, ErrorMsg: addressResult.ErrorMsg})

	return results, nil
}

func attemptIntegrityCheckSQLite(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) (integrityOutcome, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return integrityOutcome{}, err
	}
	defer tx.Rollback()
	err = fn(tx)
	if err == nil {
		return integrityOutcome{Outcome: "allowed"}, nil
	}
	return integrityOutcome{Outcome: "rejected", ErrorMsg: err.Error()}, nil
}

func measureSQLiteStorage(ctx context.Context, db *sql.DB, path string) ([]relationSize, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	relationNames := []string{
		"transactions",
		"utxos",
		"utxo_leases",
		"idx_transactions_live_by_wallet",
		"idx_utxos_unspent",
		"idx_utxos_spent_by",
		"idx_utxos_by_tx",
		"idx_utxo_leases_wallet_expires_at",
	}
	if _, err := db.ExecContext(ctx, `CREATE VIRTUAL TABLE temp.stat USING dbstat`); err != nil && !strings.Contains(err.Error(), "already exists") {
		return nil, info.Size(), nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(relationNames)), ",")
	query := `SELECT name, SUM(pgsize) FROM temp.stat WHERE name IN (` + placeholders + `) GROUP BY name ORDER BY name`
	args := make([]any, 0, len(relationNames))
	for _, name := range relationNames {
		args = append(args, name)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, info.Size(), nil
	}
	defer rows.Close()
	relations := make([]relationSize, 0)
	for rows.Next() {
		var name string
		var bytes int64
		if err := rows.Scan(&name, &bytes); err != nil {
			return nil, 0, err
		}
		relations = append(relations, relationSize{Name: name, TotalBytes: bytes, TableBytes: bytes})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return relations, info.Size(), nil
}

func currentQueriesSQLite() querySet {
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
				u.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND (?2 IS NULL OR acc.account_number = ?2)
				AND (
					?3 IS NULL
					OR ?3 = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?3
				)
				AND (
					?4 IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= ?4
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
				u.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND (?2 IS NULL OR acc.account_number = ?2)
				AND (
					?3 IS NULL
					OR ?3 = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?3
				)
				AND (
					?4 IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= ?4
				)
			ORDER BY u.amount, t.tx_hash, u.output_index
		`,
		Balance: `
			SELECT
				cast(coalesce(sum(u.amount), 0) AS INTEGER) AS total_balance,
				cast(
					coalesce(
						sum(
							CASE
								WHEN EXISTS (
									SELECT 1
									FROM utxo_leases AS l
									WHERE
										l.wallet_id = u.wallet_id
										AND l.utxo_id = u.id
										AND l.expires_at > current_timestamp
								) THEN u.amount
								ELSE 0
							END
						),
						0
					) AS INTEGER
				) AS locked_balance
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON u.wallet_id = s.wallet_id
			WHERE
				u.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND (?2 IS NULL OR acc.account_number = ?2)
				AND (
					?3 IS NULL
					OR ?3 = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?3
				)
				AND (
					?4 IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= ?4
				)
				AND (
					?5 IS NULL
					OR NOT t.is_coinbase
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?5
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
				u.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND t.tx_hash = ?2
				AND u.output_index = ?3
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
				u.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND t.tx_hash = ?2
				AND u.output_index = ?3
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
				?1,
				u.id,
				?4,
				?5
			FROM utxos AS u
			INNER JOIN transactions AS t
				ON u.wallet_id = t.wallet_id AND u.tx_id = t.id
			WHERE
				u.wallet_id = ?1
				AND t.tx_hash = ?2
				AND u.output_index = ?3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
			ON CONFLICT (wallet_id, utxo_id) DO UPDATE
			SET
				lock_id = excluded.lock_id,
				expires_at = excluded.expires_at
			WHERE
				utxo_leases.expires_at <= current_timestamp
				OR utxo_leases.lock_id = excluded.lock_id
			RETURNING expires_at
		`,
		ReleaseLease: `DELETE FROM utxo_leases WHERE wallet_id = ?1 AND utxo_id = ?2 AND lock_id = ?3`,
		MarkUtxoSpent: `
			UPDATE utxos
			SET
				spent_by_tx_id = ?4,
				spent_input_index = ?5
			WHERE
				wallet_id = ?1
				AND tx_id = (
					SELECT t.id
					FROM transactions AS t
					WHERE t.wallet_id = ?1 AND t.tx_hash = ?2 AND t.status IN (0, 1)
				)
				AND output_index = ?3
				AND (
					(spent_by_tx_id IS NULL AND spent_input_index IS NULL)
					OR (spent_by_tx_id = ?4 AND spent_input_index = ?5)
				)
		`,
		ClearSpentByTxID:  `UPDATE utxos SET spent_by_tx_id = NULL, spent_input_index = NULL WHERE wallet_id = ?1 AND spent_by_tx_id = ?2`,
		DeleteUtxosByTxID: `DELETE FROM utxos WHERE wallet_id = ?1 AND tx_id = ?2`,
		InsertTransaction: `
			INSERT INTO transactions (
				wallet_id, tx_hash, raw_tx, block_height, status, received_time, is_coinbase, label
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			RETURNING id
		`,
		InsertUtxo: `
			INSERT INTO utxos (
				wallet_id, tx_id, output_index, amount, address_id
			) SELECT
				?1, ?2, ?3, ?4, a.id
			FROM addresses AS a
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE a.id = ?5 AND ks.wallet_id = ?1
			RETURNING id
		`,
	}
}

func normalizedQueriesSQLite() querySet {
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
				t.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND (?2 IS NULL OR acc.account_number = ?2)
				AND (
					?3 IS NULL
					OR ?3 = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?3
				)
				AND (
					?4 IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= ?4
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
				t.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND (?2 IS NULL OR acc.account_number = ?2)
				AND (
					?3 IS NULL
					OR ?3 = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?3
				)
				AND (
					?4 IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= ?4
				)
			ORDER BY u.amount, t.tx_hash, u.output_index
		`,
		Balance: `
			SELECT
				cast(coalesce(sum(u.amount), 0) AS INTEGER) AS total_balance,
				cast(
					coalesce(
						sum(
							CASE
								WHEN EXISTS (
									SELECT 1
									FROM utxo_leases AS l
									WHERE
										l.wallet_id = t.wallet_id
										AND l.utxo_id = u.id
										AND l.expires_at > current_timestamp
								) THEN u.amount
								ELSE 0
							END
						),
						0
					) AS INTEGER
				) AS locked_balance
			FROM utxos AS u
			INNER JOIN transactions AS t ON u.tx_id = t.id
			INNER JOIN addresses AS a ON u.address_id = a.id
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
			WHERE
				t.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
				AND (?2 IS NULL OR acc.account_number = ?2)
				AND (
					?3 IS NULL
					OR ?3 = 0
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?3
				)
				AND (
					?4 IS NULL
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) <= ?4
				)
				AND (
					?5 IS NULL
					OR NOT t.is_coinbase
					OR (
						CASE
							WHEN t.block_height IS NULL THEN 0
							WHEN s.synced_height IS NULL THEN NULL
							WHEN t.block_height > s.synced_height THEN NULL
							ELSE s.synced_height - t.block_height + 1
						END
					) >= ?5
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
				t.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND t.tx_hash = ?2
				AND u.output_index = ?3
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
				t.wallet_id = ?1
				AND ks.wallet_id = ?1
				AND t.tx_hash = ?2
				AND u.output_index = ?3
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
				?1,
				u.id,
				?4,
				?5
			FROM transactions AS t
			INNER JOIN utxos AS u ON u.tx_id = t.id
			WHERE
				t.wallet_id = ?1
				AND t.tx_hash = ?2
				AND u.output_index = ?3
				AND u.spent_by_tx_id IS NULL
				AND t.status IN (0, 1)
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
		ReleaseLease: `DELETE FROM utxo_leases WHERE wallet_id = ?1 AND utxo_id = ?2 AND lock_id = ?3`,
		MarkUtxoSpent: `
			UPDATE utxos
			SET
				spent_by_tx_id = ?4,
				spent_input_index = ?5
			WHERE
				tx_id = (
					SELECT t.id
					FROM transactions AS t
					WHERE t.wallet_id = ?1 AND t.tx_hash = ?2 AND t.status IN (0, 1)
				)
				AND output_index = ?3
				AND (
					(spent_by_tx_id IS NULL AND spent_input_index IS NULL)
					OR (spent_by_tx_id = ?4 AND spent_input_index = ?5)
				)
		`,
		ClearSpentByTxID:  `UPDATE utxos SET spent_by_tx_id = NULL, spent_input_index = NULL WHERE ?1 IS NOT NULL AND spent_by_tx_id = ?2`,
		DeleteUtxosByTxID: `DELETE FROM utxos WHERE ?1 IS NOT NULL AND tx_id = ?2`,
		InsertTransaction: currentQueriesSQLite().InsertTransaction,
		InsertUtxo: `
			INSERT INTO utxos (
				tx_id, output_index, amount, address_id
			) SELECT
				?2, ?3, ?4, a.id
			FROM addresses AS a
			INNER JOIN accounts AS acc ON a.account_id = acc.id
			INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
			WHERE a.id = ?5 AND ks.wallet_id = ?1
			RETURNING id
		`,
	}
}
