package main

import (
	"context"
	"database/sql"
	"strings"
	"time"

	dbkit "github.com/btcsuite/btcwallet/wallet/internal/db"
)

func runPostgresAnalysis(ctx context.Context, scale scaleConfig) (string, error) {
	container, err := startPostgresContainer(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		termCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = container.Terminate(termCtx)
	}()

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", err
	}

	adminDB, err := sql.Open("pgx", connStr)
	if err != nil {
		return "", err
	}
	defer adminDB.Close()

	variantADatabase := "utxo_walletid_a"
	variantBDatabase := "utxo_walletid_b"

	if err := recreateDatabase(ctx, adminDB, variantADatabase); err != nil {
		return "", err
	}
	if err := recreateDatabase(ctx, adminDB, variantBDatabase); err != nil {
		return "", err
	}

	aSQL, aPool, err := openDatabases(ctx, connStr, variantADatabase)
	if err != nil {
		return "", err
	}
	defer aSQL.Close()
	defer aPool.Close()

	bSQL, bPool, err := openDatabases(ctx, connStr, variantBDatabase)
	if err != nil {
		return "", err
	}
	defer bSQL.Close()
	defer bPool.Close()

	if err := dbkit.ApplyPostgresMigrations(aSQL); err != nil {
		return "", err
	}
	if err := dbkit.ApplyPostgresMigrations(bSQL); err != nil {
		return "", err
	}
	if err := applyVariantB(ctx, bSQL); err != nil {
		return "", err
	}

	plan := buildDatasetPlan(scale)
	if err := seedDataset(ctx, aPool, plan, true); err != nil {
		return "", err
	}
	if err := seedDataset(ctx, bPool, plan, false); err != nil {
		return "", err
	}

	if err := analyzeDatabase(ctx, aPool); err != nil {
		return "", err
	}
	if err := analyzeDatabase(ctx, bPool); err != nil {
		return "", err
	}

	variantAQueries := currentQueries()
	variantBQueries := normalizedQueries()

	aConn, err := aPool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer aConn.Release()
	bConn, err := bPool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer bConn.Release()

	if err := configureBenchmarkSession(ctx, aConn); err != nil {
		return "", err
	}
	if err := configureBenchmarkSession(ctx, bConn); err != nil {
		return "", err
	}

	checks := benchmarkCases()
	aResults, err := runBenchmarks(ctx, aConn, variantAQueries, plan.Fixtures, scale, checks)
	if err != nil {
		return "", err
	}
	bResults, err := runBenchmarks(ctx, bConn, variantBQueries, plan.Fixtures, scale, checks)
	if err != nil {
		return "", err
	}
	if err := ensureComparableResults(aResults, bResults); err != nil {
		return "", err
	}

	aIntegrity, err := runIntegrityChecks(ctx, aConn, true, plan)
	if err != nil {
		return "", err
	}
	bIntegrity, err := runIntegrityChecks(ctx, bConn, false, plan)
	if err != nil {
		return "", err
	}

	aRelations, aDBSize, err := measureStorage(ctx, aConn)
	if err != nil {
		return "", err
	}
	bRelations, bDBSize, err := measureStorage(ctx, bConn)
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
	}, "Read timings are end-to-end client timings; exec times come from `EXPLAIN (ANALYZE, BUFFERS)` and reflect server-side work.")

	return strings.Replace(report, "# UTXO wallet_id analysis", "# UTXO wallet_id analysis (postgres)", 1), nil
}
